// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"net"
	"sync"
	"testing"

	"github.com/omec-project/li/store"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// storedSession builds a session allocated the way the store allocates one.
//
// **The allocation shape is the whole point.** NewPFCPSession makes each rule slice at
// cap(MaxItems) and nothing ever grows past it, so append never reallocates and a
// stored session's array is the same array every reader holds. A session built from
// slice literals — which is how every other test here builds one — has cap == len, so
// the first append reallocates and the sharing quietly stops being total. That is
// exactly why -race never saw this: the tests were not reproducing the memory layout
// the store produces.
func storedSession(seid uint64, ue string) PFCPSession {
	addr := ip2int(net.ParseIP(ue))
	s := PFCPSession{
		localSEID:  seid,
		remoteSEID: seid + 1,
		PacketForwardingRules: PacketForwardingRules{
			pdrs: make([]pdr, 0, MaxItems),
			fars: make([]far, 0, MaxItems),
			qers: make([]qer, 0, MaxItems),
		},
	}
	s.CreatePDR(uplinkPDR(seid, 1, uint32(seid)+0x1000, ip2int(net.ParseIP("10.76.0.2")), addr))
	s.CreatePDR(downlinkPDR(seid, 2, addr))
	for id := uint32(1); id <= 4; id++ {
		s.CreateFAR(far{farID: id, fseID: seid, applyAction: ActionForward})
	}

	return s
}

// modifyFARRequest is one round of the modification the SMF sends, and it alternates
// so that every round writes.
//
// Both writes matter and they are different writes: UpdateFAR replaces a whole far
// inside the array, and RemoveFAR shifts the remainder down inside it — the second is
// what lets a reader observe a rule at an index that now belongs to a different one.
// A round that only removed would fail on the next round with the FAR already gone,
// and the handler answers a failed removal by returning before it writes anything, so
// the writer would go quiet after one round and the test would assert nothing.
func modifyFARRequest(seid uint64, round int) message.Message {
	seq := uint32(round)
	if round%2 == 0 {
		return message.NewSessionModificationRequest(0, 0, seid, seq, 0,
			ie.NewUpdateFAR(
				ie.NewFARID(uint32(1+round%3)),
				ie.NewApplyAction(ActionForward),
				ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
			),
			ie.NewRemoveFAR(ie.NewFARID(4)),
		)
	}

	// Put it back, so the next even round has something to remove.
	return message.NewSessionModificationRequest(0, 0, seid, seq, 0,
		ie.NewCreateFAR(
			ie.NewFARID(4),
			ie.NewApplyAction(ActionForward),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
		),
	)
}

// modifyRepeatedly drives the writer and answers how many modifications the handler
// actually applied. The count is asserted, because a handler that returns early — as
// it does on a removal it cannot perform — writes nothing, and a writer that stops
// writing turns this into a test of nothing at all.
func modifyRepeatedly(pConn *PFCPConn, seid uint64, rounds int) int {
	applied := 0
	for i := range rounds {
		rsp, err := pConn.handleSessionModificationRequest(modifyFARRequest(seid, i))
		if err != nil {
			continue
		}
		if smres, ok := rsp.(*message.SessionModificationResponse); ok && smres.Cause != nil {
			if cause, err := smres.Cause.Cause(); err == nil && cause == ie.CauseRequestAccepted {
				applied++
			}
		}
	}

	return applied
}

// raceConn is the minimum PFCPConn the modification handler needs: a store to read the
// session from, and a datapath to answer the push.
func raceConn(t *testing.T, sessions SessionsStore) *PFCPConn {
	t.Helper()

	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() }) //nolint:errcheck // test cleanup

	return &PFCPConn{Conn: l, store: sessions, upf: &upf{datapath: &fakeDP{}}}
}

// TestAStoredSessionsRulesAreStableForAConcurrentReader drives the two paths that
// reach one session's rules with no ordering between them, against the real store,
// under -race.
//
// The interception plane re-derives duplication on its own worker, reading sess.fars
// for every session the store holds. The session's own signalling modifies those same
// FARs in place. Both are correct in isolation and the ordering arguments above them
// are sound — they operate on whole sessions, and this operates on the bytes of one
// rule. What a reader can observe is a far half-replaced, or a far at an index that
// now belongs to a different rule, and what it does with it is program BESS: the wrong
// forwarding action, or the wrong duplication decision, for a rule belonging to
// someone else's traffic.
//
// It must fail before the copy-on-write. A test that builds two sessions and asserts
// they do not alias would pass against the broken build, because the aliasing is
// between a stored session and the copy every getter hands out.
func TestAStoredSessionsRulesAreStableForAConcurrentReader(t *testing.T) {
	sessions := NewInMemoryStore()

	sess := storedSession(100, "10.250.0.9")
	if cap(sess.fars) != MaxItems {
		t.Fatalf("the fixture allocates fars at cap %d, not the store's %d; "+
			"it no longer reproduces the sharing this test exists for", cap(sess.fars), MaxItems)
	}
	if err := sessions.PutSession(sess); err != nil {
		t.Fatal(err)
	}

	e := newCCEnabler(store.New(), func(_, _ PacketForwardingRules) uint8 {
		return ie.CauseRequestAccepted
	}, nil)
	t.Cleanup(e.stop)
	e.addSource(sessions)

	pConn := raceConn(t, sessions)

	var wg sync.WaitGroup

	const rounds = 60

	applied := 0

	wg.Add(2)
	go func() {
		defer wg.Done()
		applied = modifyRepeatedly(pConn, 100, rounds)
	}()
	go func() {
		defer wg.Done()
		for range rounds {
			e.retaskAndWait()
		}
	}()
	wg.Wait()

	if applied < rounds/2 {
		t.Fatalf("the handler applied %d of %d modifications; it stopped writing, "+
			"so nothing was racing the re-derivation", applied, rounds)
	}
}

// TestTheFramingPathReadsAStableSession is the same hazard reached from the other
// reader, and the one that runs per packet.
//
// resolveCovering resolves a duplicated copy's F-SEID to the task covering it, and gets
// there through sessionFor — a plain GetSession, on a framing worker. It then resolves
// detection criteria against that session's rules. So the second reader of the arrays
// the modification handler writes is on the content path, where a torn read decides
// which warrant a packet is delivered under.
func TestTheFramingPathReadsAStableSession(t *testing.T) {
	sessions := NewInMemoryStore()

	sess := storedSession(200, "10.250.0.10")
	if err := sessions.PutSession(sess); err != nil {
		t.Fatal(err)
	}

	tasks := store.New()
	e := newCCEnabler(tasks, func(_, _ PacketForwardingRules) uint8 {
		return ie.CauseRequestAccepted
	}, nil)
	t.Cleanup(e.stop)
	e.addSource(sessions)

	task := ccTask("W1", ueAddr("10.250.0.10"))
	if !tasks.Activate(task) {
		t.Fatal("Activate failed")
	}
	e.retaskAndWait()

	pConn := raceConn(t, sessions)

	var wg sync.WaitGroup

	const rounds = 60

	applied := 0

	wg.Add(2)
	go func() {
		defer wg.Done()
		applied = modifyRepeatedly(pConn, 200, rounds)
	}()
	go func() {
		defer wg.Done()
		for range rounds {
			// The epoch is bumped so the memo does not answer from cache: what has to
			// run concurrently with the writer is the resolution itself.
			e.epoch.Add(1)
			e.resolveCovering(200)
		}
	}()
	wg.Wait()

	if applied < rounds/2 {
		t.Fatalf("the handler applied %d of %d modifications; it stopped writing, "+
			"so nothing was racing the framing path", applied, rounds)
	}
}
