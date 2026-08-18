// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
)

// unansweringADMF is an ADMF that accepts the connection and never answers, which is
// the condition a fault report is most likely to be issued under: the conditions worth
// reporting are the conditions under which the peer is most likely to be unreachable.
func unansweringADMF(t *testing.T) string {
	t.Helper()

	held := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-held:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(held)
		srv.Close()
	})

	return srv.URL
}

// TestTheReadLoopKeepsDrainingWhileAReportIsOutstanding is the data-plane half of
// "reporting a fault does not stall the path that observed it", and it is a timing
// claim, so it is driven rather than reasoned about.
//
// The read loop sits in front of an AF_UNIX SEQPACKET queue whose invariant its own
// comment states: everything done before returning to Read is time that queue spends
// filling, and what it overflows with is intercept product nobody can recover. A
// synchronous report on that path made the remedy amplify the fault — the report that
// says copies were dropped before framing was what dropped the next several hundred —
// and it did so for as long as the ADMF took to answer, which is up to the client's
// full 10s timeout when it never answers at all.
//
// The framing side is deliberately absent, so the punt queue fills immediately and
// every subsequent datagram takes the x3FramingLost branch. With the report issued on
// the loop, the writes below block behind a stalled reader and this test times out.
func TestTheReadLoopKeepsDrainingWhileAReportIsOutstanding(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "li-x3.sock")

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unixpacket", addr)
	if err != nil {
		t.Skipf("unixpacket sockets unavailable here: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup

	s := &liShipper{
		sockAddr: addr,
		senders:  make(map[string]x2x3.Sender),
		// One slot and nothing draining it: the second datagram onwards is a drop, so
		// the report fires on all but the first.
		punted:   make(chan []byte, 1),
		free:     make(chan []byte, 1),
		reporter: x1.NewReporter(unansweringADMF(t), "admfID", "neID", nil),
	}
	s.egressDown.Store(true)

	go s.shipLoop()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("the shipper never dialled the egress: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup

	// Enough datagrams that a single 10s stall cannot be mistaken for slowness, and
	// small enough that a draining loop finishes them in milliseconds.
	const copies = 500

	payload := make([]byte, liTagLen+64)

	done := make(chan error, 1)
	go func() {
		for range copies {
			if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				done <- err

				return
			}
			if _, err := conn.Write(payload); err != nil {
				done <- err

				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the datapath could not hand the shipper its copies: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the read loop stopped draining the datapath socket while a report was outstanding")
	}
}
