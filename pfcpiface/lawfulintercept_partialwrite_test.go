// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"crypto/tls"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
)

// halfOpenMDF3 accepts connections, reads a bounded number of bytes on the first and
// then stops reading while holding it open, so a write large enough to fill the socket
// buffer trips the client's write deadline part-way through. The second connection reads
// everything, which is what the client's single reconnect lands on.
//
// That is the whole of the condition, and both halves of it matter: **the destination is
// reachable** — it completed a mutually authenticated handshake and it accepts the retry
// — and one content copy of what was offered is lost, because a partially written unit
// cannot be resumed on a fresh stream without the peer taking its tail for the head of
// the next one.
func halfOpenMDF3(t *testing.T, server *tls.Config, stallAfter int) string {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	held := make(chan struct{})
	t.Cleanup(func() { close(held) })

	var mu sync.Mutex
	accepted := 0

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			mu.Lock()
			accepted++
			stall := accepted == 1
			mu.Unlock()

			go func() {
				defer conn.Close() //nolint:errcheck // test

				buf := make([]byte, 4096)
				read := 0
				for {
					if stall && read >= stallAfter {
						<-held

						return
					}
					if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
						return
					}
					n, err := conn.Read(buf)
					read += n
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	return ln.Addr().String()
}

// TestAPartialWriteToAReachableMDF3IsReportedAsALoss is the CC-POI's half of the
// unreported drop. The two IRI-POIs had the same gap; this element also keeps its own
// senders rather than using x2x3.Pool, so it needed the fix in its own senderFor.
//
// A partial write costs one content copy. The library correctly refuses to call that
// unreachability — a healthy mediation function must not be reported unreachable over one
// truncated write, and doing so would have the watcher raise a fault about a working
// destination and retract it on the next send — so it returns ErrUnitDropped instead.
// This element's two hooks, the delivery one and the keepalive's, both discarded the
// error and nudged the watcher, which sampled a destination it correctly considered
// reachable. The loss was reported by nothing: content missing from an agency's record
// with every channel that could have said so agreeing that nothing was wrong.
//
// It is reported as x3DeliveryLost, the same condition a full delivery queue raises:
// from the agency's side the two are one fact — a copy this element made and did not
// deliver.
func TestAPartialWriteToAReachableMDF3IsReportedAsALoss(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := liCA(t, dir)
	mdfCert, mdfKey := liLeaf(t, dir, caCert, caKey, "MDF", "mdf3-1")
	upfCert, upfKey := liLeaf(t, dir, caCert, caKey, "NE", "upf-1")

	mdfMat, err := mtls.Load(mdfCert, mdfKey, caPath)
	if err != nil {
		t.Fatalf("load mdf material: %v", err)
	}
	upfMat, err := mtls.Load(upfCert, upfKey, caPath)
	if err != nil {
		t.Fatalf("load upf material: %v", err)
	}

	// 64 KiB read and then no more: the client's own 5s write deadline is what ends the
	// stalled write, so this test costs that once.
	addr := halfOpenMDF3(t, mdfMat.ServerTLS(), 64*1024)

	rec := &recordingReporter{}
	s := &liShipper{
		reporter:  rec,
		tlsConfig: upfMat.ClientTLS(),
		senders:   make(map[string]x2x3.Sender),
		ids:       x2x3.NewIdentity("upf-1", upfInterceptionPoint),
		keepalive: x2x3.KeepaliveConfig{Disabled: true},
	}

	sender, err := s.senderFor(addr)
	if err != nil {
		t.Fatalf("senderFor: %v", err)
	}

	// One unit, far larger than any socket buffer, so the write cannot complete and the
	// unit cannot be resumed. A single PDU is the sharpest form: there are no boundaries
	// to resume at, so exactly one copy is lost and nothing else is in question.
	//nolint:errcheck // the loss is the contract; what is asserted is that it is reported
	_ = sender.Send(&x2x3.PDU{
		Type:          x2x3.PDUTypeX3,
		PayloadFormat: x2x3.PayloadFormatIPv4,
		Payload:       make([]byte, 2*1024*1024),
	})

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if slices.Contains(rec.reported(), x1.NEIssueX3DeliveryLost) {
			// The other half, and the reason this was invisible: the destination is
			// reachable, by every measure including its own.
			if r, ok := sender.(x2x3.Reachability); ok && r.Unreachable() {
				t.Error("the destination reports unreachable after a dropped copy; this test no " +
					"longer reproduces the reachable-MDF case it exists for, and the watcher " +
					"would now raise a fault about a working mediation function")
			}

			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("a content copy was partially written to a reachable mediation function, dropped, "+
		"and reported by nothing:\n%s", strings.Join(rec.reported(), "\n"))
}
