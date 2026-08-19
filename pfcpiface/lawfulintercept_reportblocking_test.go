// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/types"
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

// slowFormReporter stands in for a reporter whose blocking form blocks — which is what
// x1.Reporter is, an mTLS round trip bounded only by its own 10s timeout. Notify sleeps;
// NotifyAsync returns at once. It also counts the calls, so a test can prove the callback
// under examination actually ran.
//
// A double rather than a real reporter and a hanging ADMF, because what is being asserted
// is which *form* this element's callback uses. Whether the blocking form really blocks is
// x1.Reporter's own property, and li asserts it there.
type slowFormReporter struct {
	block time.Duration

	mu    sync.Mutex
	sync  int
	async int
}

func (r *slowFormReporter) Notify(string, string) {
	r.mu.Lock()
	r.sync++
	r.mu.Unlock()
	time.Sleep(r.block)
}

func (r *slowFormReporter) NotifyAsync(issueType, description string) {
	r.mu.Lock()
	r.async++
	r.mu.Unlock()
}

func (r *slowFormReporter) counts() (syncCalls, asyncCalls int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.sync, r.async
}

// TestARefusedX1RequestIsAnsweredWithoutWaitingOnTheReporter is the
// provisioning-direction half of the rule the read-loop test covers for the data plane.
//
// OnAuthFailure runs synchronously on the X1 request goroutine and its own contract says
// it must not block. This element reported from it with the blocking form, so a refusal
// held the triggering interface open for as long as the ADMF took to answer — up to the
// reporter's full 10s timeout when it never answers at all. That makes this element's
// response time a function of whether its ADMF is up, measurable by whoever is probing the
// interface, and it does it on the path that refuses unauthorised tasking: precisely where
// an element should be quickest. The AMF and SMF had honoured that contract since it was
// written; this element had not.
//
// **The callback is asserted to have run.** The first version of this test refused a
// request that never reached OnAuthFailure at all, so its timing assertion passed against
// the blocking form — measuring a path that does not report. OnPurge uses the same form
// for the same reason (a bulk deactivation reaches it on this goroutine) and is not driven
// separately, because producing a keepalive lapse means waiting one out.
func TestARefusedX1RequestIsAnsweredWithoutWaitingOnTheReporter(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := liCA(t, dir)
	upfCert, upfKey := liLeaf(t, dir, caCert, caKey, "NE", "upf-1")

	// A peer holding a certificate from the LI CA that binds it as a *network element*,
	// not as the ADMF. It authenticates at TLS and fails clause 8.2.4, which is the
	// condition OnAuthFailure exists for.
	wrongRoleCert, wrongRoleKey := liLeaf(t, dir, caCert, caKey, "NE", "smf-1")

	upfMat, err := mtls.Load(upfCert, upfKey, caPath)
	if err != nil {
		t.Fatalf("load upf material: %v", err)
	}
	peerMat, err := mtls.Load(wrongRoleCert, wrongRoleKey, caPath)
	if err != nil {
		t.Fatalf("load peer material: %v", err)
	}

	cfg := &LiConfig{NEID: "upf-1", TFID: "smf-1", X1Listen: freePort(t)}

	reporter := &slowFormReporter{block: 10 * time.Second}
	if _, err := startTriggerListener(cfg, upfMat.ServerTLS(), reporter, nil,
		x2x3.NewIdentity("upf-1", upfInterceptionPoint), nil, nil); err != nil {
		t.Fatalf("startTriggerListener: %v", err)
	}

	req := x1.NewRequester("https://"+cfg.X1Listen, "smf-1", "upf-1", peerMat.ClientTLS())

	start := time.Now()
	err = req.ActivateTask(x1.Trigger{
		XID:           types.XID("11111111-1111-4111-8111-111111111111"),
		ProductID:     types.XID("22222222-2222-4222-8222-222222222222"),
		CorrelationID: 7,
		SEID:          0x2632898145f4d191,
		// A destination, or the requester refuses this client-side and the request never
		// reaches the element at all — which is how the first version of this test came
		// to measure a validation error instead of a refusal.
		DIDs: []string{"33333333-3333-4333-8333-333333333333"},
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a peer whose certificate binds it as a network element rather than the ADMF " +
			"was allowed to task this element")
	}

	syncCalls, asyncCalls := reporter.counts()
	if syncCalls+asyncCalls == 0 {
		t.Fatalf("the authentication failure was not reported at all (err=%v), so this asserts "+
			"nothing about which form reports it", err)
	}
	if syncCalls > 0 {
		t.Errorf("the refusal was reported with the blocking form (%d calls): this element's answer "+
			"waits on its own reporting peer, which is observable to whoever is probing the interface",
			syncCalls)
	}
	if elapsed > 3*time.Second {
		t.Errorf("refusing an unauthorised request took %s while the reporter was unresponsive", elapsed)
	}
}
