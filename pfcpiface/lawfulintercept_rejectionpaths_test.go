// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"math/rand"
	"net"
	"sync"
	"testing"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/upf-epc/pfcpiface/metrics"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// refusingDP is a datapath that refuses what it is asked to do *after* applying it, which is what
// the real one does: SendMsgToUPF issues one gRPC call per rule and GRPCJoin returns on the first
// failure with the rest of the batch still in flight, so a "rejected" answer means an unknown
// subset was applied — not that nothing was.
//
// Every other datapath fake in this package models all-or-nothing, which is why none of them can
// reach the state the live incident produced.
type refusingDP struct {
	fakeDP

	mu      sync.Mutex
	refuse  bool
	methods []upfMsgType
	// duplicating is what this datapath believes it is duplicating, keyed by FAR ID. It is
	// written whatever the answer, because that is the point.
	duplicating map[uint32]bool
}

// sharedMetrics builds the collector once for the whole package.
//
// The session handlers record per-session metrics, so the embedded collector must be real: it is
// an interface field and a nil one panics inside NewPFCPSession, before the handler reaches
// anything these tests are about. It cannot be per-test, because the constructor registers global
// Prometheus collectors and the second call fails.
var sharedMetrics = sync.OnceValues(func() (*metrics.Service, error) {
	return metrics.NewPrometheusService()
})

func newRefusingDP() *refusingDP {
	return &refusingDP{duplicating: make(map[uint32]bool)}
}

func (d *refusingDP) SendMsgToUPF(method upfMsgType, all, updated PacketForwardingRules) uint8 {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.methods = append(d.methods, method)

	rules := updated
	if method == upfMsgTypeDel || len(updated.fars) == 0 {
		rules = all
	}

	for _, f := range rules.fars {
		if method == upfMsgTypeDel {
			delete(d.duplicating, f.farID)
			continue
		}

		d.duplicating[f.farID] = f.liDuplicate
	}

	if d.refuse {
		return ie.CauseRequestRejected
	}

	return ie.CauseRequestAccepted
}

func (d *refusingDP) sawMethod(m upfMsgType) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, seen := range d.methods {
		if seen == m {
			return true
		}
	}

	return false
}

// rejectionConn builds a connection whose datapath refuses, wired to a real enabler as production
// wires it — without the enabler, applyTasking and every recorder are nil-receiver no-ops and the
// paths under test record nothing for reasons unrelated to the defect.
func rejectionConn(t *testing.T) (*PFCPConn, *refusingDP, *ccEnabler, *[]string) {
	t.Helper()

	dp := newRefusingDP()
	sessions := NewInMemoryStore()
	tasks := store.New()

	svc, err := sharedMetrics()
	if err != nil {
		t.Fatalf("metrics service: %v", err)
	}

	var (
		mu       sync.Mutex
		reported []string
	)

	e := newCCEnabler(tasks, func(all, updated PacketForwardingRules) uint8 {
		return dp.SendMsgToUPF(upfMsgTypeMod, all, updated)
	}, func(issueType, _ string) {
		mu.Lock()
		defer mu.Unlock()

		reported = append(reported, issueType)
	})

	t.Cleanup(e.stop)
	e.addSource(sessions)

	pConn := &PFCPConn{
		Conn:  nil,
		store: sessions,
		// localIE is what the handlers put in every response they build; a nil one panics
		// while the response is assembled, before the assertion is reached.
		nodeID: nodeID{remote: "1.1.1.1", local: "2.2.2.2", localIE: ie.NewNodeID("2.2.2.2", "", "")},
		upf:    &upf{datapath: dp, ccEnabler: e},
		// The establishment handler allocates a local SEID from these, as production does.
		// Fixed seed: the SEID is not asserted on, and a deterministic test is worth more than
		// an arbitrary one.
		rng:            rand.New(rand.NewSource(1)), // #nosec G404
		maxRetries:     100,
		InstrumentPFCP: svc,
	}

	return pConn, dp, e, &reported
}

// programmedFor reports what the element's record says about a FAR, and whether it holds one.
func programmedFor(e *ccEnabler, seid uint64, farID uint32) (bool, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	entry, held := e.programmed[farRef{seid: seid, farID: farID}]

	return entry.duplicating, held
}

// TestARefusedModificationRecordsWhatItPushed drives the real handler rather than calling
// farsPushed directly.
//
// That distinction is the finding. The existing coverage calls farsPushed by hand, so it passes
// with three of the four call sites missing — which is exactly what happened: the remedy was added
// to the deletion stage, with a comment explaining why, and the branch that reaches the datapath
// first was never given it.
//
// Without the record, a later re-derivation computes "nothing should duplicate", finds no entry,
// reads that as "not duplicating", and concludes there is nothing to turn off. The copies continue
// under no authority, and the element's own account is what conceals it.
func TestARefusedModificationRecordsWhatItPushed(t *testing.T) {
	pConn, dp, e, _ := rejectionConn(t)

	const seid = 400

	sess := storedSession(seid, "10.250.0.12")
	if err := pConn.store.PutSession(sess); err != nil {
		t.Fatal(err)
	}

	dp.mu.Lock()
	dp.refuse = true
	dp.mu.Unlock()

	// The SMF restates FAR 1. The datapath applies it and then refuses the batch.
	_, err := pConn.handleSessionModificationRequest(
		message.NewSessionModificationRequest(0, 0, seid, 1, 0,
			ie.NewUpdateFAR(
				ie.NewFARID(1),
				ie.NewApplyAction(ActionForward),
				ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
			),
		))
	if err == nil {
		t.Fatal("the refused modification was reported as succeeding")
	}

	if _, held := programmedFor(e, seid, 1); !held {
		t.Error("a refused modification left no record of the FAR it had already pushed. The " +
			"datapath may be duplicating it, and no re-derivation can turn that off, because " +
			"the element's record says there is nothing to turn off")
	}
}

// TestARefusedEstablishmentDoesNotStrandDuplication drives the establishment handler.
//
// This branch cannot be fixed by recording: NewPFCPSession does not store the session and the
// branch abandons it before PutSession, so no re-derivation will ever walk it and no record
// written here could be read again. Removing the rules from the datapath is the only remedy, and
// the absence of that push is what leaves a PDR matching the UE address and a FAR duplicating for
// the life of the process.
func TestARefusedEstablishmentDoesNotStrandDuplication(t *testing.T) {
	pConn, dp, _, _ := rejectionConn(t)

	dp.mu.Lock()
	dp.refuse = true
	dp.mu.Unlock()

	ueIP := net.ParseIP("10.250.0.12")

	_, err := pConn.handleSessionEstablishmentRequest(
		message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
			ie.NewNodeID("1.1.1.1", "", ""),
			ie.NewFSEID(200, net.ParseIP("1.1.1.1"), nil),
			ie.NewCreatePDR(
				ie.NewPDRID(1),
				ie.NewPrecedence(0),
				ie.NewPDI(
					ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x2, ueIP.String(), "", 0, 0),
				),
				ie.NewFARID(1),
			),
			ie.NewCreateFAR(
				ie.NewFARID(1),
				ie.NewApplyAction(ActionForward),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess)),
			),
		))
	if err == nil {
		t.Fatal("the refused establishment was reported as succeeding")
	}

	if !dp.sawMethod(upfMsgTypeDel) {
		t.Error("a refused establishment abandoned the session without asking the datapath to " +
			"remove the rules it had already applied. The session is never stored, so nothing " +
			"in this element will ever walk it again: whatever was programmed — including " +
			"duplication — stays for the life of the process, with no record of it anywhere")
	}
}

// TestARefusedLocalDeleteKeepsItsRecord covers the session-report-response path, which deleted the
// record before it knew whether the datapath had accepted the removal.
//
// The record's entries go with the session, so dropping them first means a refused delete strands
// rules that no later re-derivation can find — it walks the sessions this element holds, and this
// one is gone.
func TestARefusedLocalDeleteKeepsItsRecord(t *testing.T) {
	pConn, dp, e, _ := rejectionConn(t)

	const seid = 401

	sess := storedSession(seid, "10.250.0.13")
	if err := pConn.store.PutSession(sess); err != nil {
		t.Fatal(err)
	}

	// The element believes FAR 1 is duplicating.
	e.farsPushed(seid, []far{{farID: 1, fseID: seid, liDuplicate: true}})

	if dup, held := programmedFor(e, seid, 1); !held || !dup {
		t.Fatalf("fixture did not establish the record: duplicating=%v held=%v", dup, held)
	}

	dp.mu.Lock()
	dp.refuse = true
	dp.mu.Unlock()

	err := pConn.handleSessionReportResponse(
		message.NewSessionReportResponse(0, 0, seid, 1, 0,
			ie.NewCause(ie.CauseSessionContextNotFound),
		))
	if err == nil {
		t.Fatal("the refused local delete was reported as succeeding")
	}

	if _, held := programmedFor(e, seid, 1); !held {
		t.Error("the record was dropped before the datapath confirmed the removal, so a rule " +
			"the datapath still holds is now invisible to every re-derivation")
	}
}

// TestAbandonedDuplicationIsReportedOnlyWhenSomethingWasDuplicating covers the report the two
// abandoning paths raise — a refused establishment, and an association teardown.
//
// Those are the paths where recording is not a remedy: the session is gone or was never stored, so
// no re-derivation can ever walk it. Saying so is all that is left, and it must be said only when
// it means something. An ordinary failed delete of a session no warrant covered is the datapath's
// business; reporting that to the ADMF would manufacture LI faults out of routine PFCP churn, and
// an element that always reports is ignored exactly as fast as one that never does.
func TestAbandonedDuplicationIsReportedOnlyWhenSomethingWasDuplicating(t *testing.T) {
	for _, tt := range []struct {
		name string
		fars []far
		want bool
	}{
		{"a rule that was duplicating", []far{{farID: 1, liDuplicate: true}}, true},
		{"one of several duplicating", []far{{farID: 1}, {farID: 2, liDuplicate: true}}, true},
		{"nothing was duplicating", []far{{farID: 1}, {farID: 2}}, false},
		{"no rules at all", nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, e, reported := rejectionConn(t)

			e.abandonedDuplication(tt.fars, "a test")

			got := len(*reported) > 0
			if got != tt.want {
				t.Errorf("reported=%v want=%v (%v)", got, tt.want, *reported)
			}

			if tt.want && (*reported)[0] != x1.NEIssueDuplicationRefused {
				t.Errorf("reported %q, want %q", (*reported)[0], x1.NEIssueDuplicationRefused)
			}
		})
	}
}

// TestAPartiallyProgrammedRefusalIsStillWithdrawn is the whole shape in one test, against a
// datapath that behaves like the real one.
//
// A warrant is active and the element programs duplication. The datapath then refuses a pass
// *after* applying it — which is what SendMsgToUPF does, because GRPCJoin returns on the first
// failure with the rest of the batch still in flight. The warrant is withdrawn. Duplication must
// stop.
//
// Before this change the element could reach a state where it never stopped: the refusal left the
// record saying "not duplicating" while the datapath duplicated, and `transact` skips any FAR
// whose record already equals what the tasking implies. The element computed "nothing should
// duplicate", saw its record agreeing, and did nothing — for ever. `everDuplicated` bounds that,
// but only for a FAR the element successfully recorded as duplicating in the first place, which is
// exactly what a refusal used to prevent.
//
// The fixture's all-or-nothing mode cannot reach this state at all, which is why it went unnoticed:
// with `partial` off, a refused push programs nothing and the record and the datapath never
// disagree. See enablerFixture.partial.
func TestAPartiallyProgrammedRefusalIsStillWithdrawn(t *testing.T) {
	f := newEnablerFixture(t)

	const seid = 500

	f.putSession(t, unmarkedSession(seid, "10.250.0.21"))

	// The datapath applies what it is told and then refuses the batch.
	f.mu.Lock()
	f.partial = true
	f.cause = ie.CauseRequestRejected
	f.mu.Unlock()

	f.activate(t, "W1", ueAddr("10.250.0.21"))

	if !f.duplicates(t, seid, 1) {
		t.Fatal("the datapath did not start duplicating, so this test is not exercising the " +
			"state it exists for")
	}

	// The datapath recovers, and the warrant ends.
	f.mu.Lock()
	f.cause = ie.CauseRequestAccepted
	f.mu.Unlock()

	f.deactivate(t, "W1")

	if f.duplicates(t, seid, 1) {
		t.Error("duplication continued after the warrant was withdrawn. The refusal left the " +
			"element's record disagreeing with the datapath, and a re-derivation that trusts " +
			"that record concludes there is nothing to turn off — so a subscriber's traffic is " +
			"copied under no authority, invisibly from both ends")
	}
}

// TestEverDuplicatedIsReclaimedWithItsSessions pins the second record against the same requirement
// as the first.
//
// `A point of interception's record of what it programmed stays bounded` binds every record of
// what was programmed, and this set is one. It was written as monotone-for-ever, justified by a
// SEID-reuse hazard that does not exist in this element — NewPFCPSession allocates from a 64-bit
// random source — so every entry whose session had ended was unreachable garbage: transact
// consults the set only inside its walk of live sessions' FARs.
//
// "A handful" was the other half of that justification, and it holds only for narrow criteria. A
// task keyed by network instance or tunnel direction selects every session on the element, so
// under ordinary subscriber churn the set grows with every session that has ever existed while the
// task was held. Interception stays correct the whole time, which is what makes it invisible —
// until the process dies and takes every warrant with it.
//
// sessionForgotten is called directly here because the churn is what is under test; its production
// call site is RemoveSession, which the rejection-path tests in this file drive.
func TestEverDuplicatedIsReclaimedWithItsSessions(t *testing.T) {
	f := newEnablerFixture(t)
	f.activate(t, "W1", ueAddr("10.250.0.9"))

	const rounds = 200

	for seid := uint64(1); seid <= rounds; seid++ {
		s := unmarkedSession(seid, "10.250.0.9")
		f.putSession(t, s)

		// ...and the subscriber goes away again, as RemoveSession does in production.
		if err := f.store.DeleteSession(seid); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}

		f.e.sessionForgotten(&s)
	}

	f.e.retaskAndWait()
	f.settle(t)

	programmed, everDuplicated := f.recordSizes()

	if programmed != 0 {
		t.Errorf("the primary record holds %d entries with no sessions left", programmed)
	}

	if everDuplicated != 0 {
		t.Errorf("the ever-duplicated set holds %d entries with no sessions left. It is a record "+
			"of what was programmed and is bounded by the same requirement; every one of those "+
			"entries is unreachable, because transact consults the set only while walking the "+
			"FARs of a live session", everDuplicated)
	}
}
