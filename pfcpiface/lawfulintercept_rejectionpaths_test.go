// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"math/rand"
	"net"
	"sync"
	"testing"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
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

// TestAFARRecreatedUnderTheSameIDKeepsItsRecord pins the deletion sweep against the entry's own
// stamp rather than the pass's mark.
//
// Comparing to the mark answers "was this forgotten after the pass began", which also discards an
// entry written *after* the forgetting — and a FAR re-created under the same identifier is exactly
// that. A path switch does it routinely: the modification removes FAR n, stamping it forgotten,
// then re-creates FAR n and records it duplicating. Both stamps are past the mark, so the sweep
// dropped a record describing a live, duplicating rule.
//
// A missing entry reads as "not duplicating", so until the next pass this element answers
// TaskIssueDuplicationNotProgrammed for a warrant it is in fact serving — a wrong answer rather
// than lost interception, and the answer the triggering function acts on.
func TestAFARRecreatedUnderTheSameIDKeepsItsRecord(t *testing.T) {
	f := newEnablerFixture(t)

	const seid = 600

	sess := unmarkedSession(seid, "10.250.0.9")
	f.putSession(t, sess)
	w := f.windowed(t)

	task := ccTask("W1", ueAddr("10.250.0.9"))
	if err := f.e.canApply(task); err != nil {
		t.Fatalf("canApply: %v", err)
	}

	if !f.tasks.Activate(task) {
		t.Fatal("Activate failed")
	}

	// A pass begins and reads the sessions.
	w.hold <- struct{}{}
	gen := f.e.request()
	<-w.read

	// Inside the interval the SMF removes FAR 1 and immediately re-creates it — one path
	// switch, as far as this element is concerned.
	f.e.farsRemoved(seid, []far{{farID: 1, fseID: seid}})
	f.e.farsPushed(seid, []far{{farID: 1, fseID: seid, liDuplicate: true}})

	// The pass concludes on its older view.
	w.release <- struct{}{}
	f.e.await(gen)
	f.settle(t)

	value, held := f.recorded(seid, 1)
	if !held {
		t.Fatal("the record for a FAR re-created after it was forgotten was swept away. It is " +
			"live and duplicating; a missing entry reads as 'not duplicating', so this element " +
			"now reports the interception as not programmed for a warrant it is serving")
	}

	if !value {
		t.Error("the record says the re-created FAR is not duplicating, while the element pushed " +
			"it duplicating")
	}
}

// TestConcurrentMissesShareOneFragmentMemo pins the memoisation against the one thing that makes
// two equivalent answers *not* interchangeable.
//
// Resolution runs unlocked — it walks every session, so it must — and the framing workers are four.
// Two of them missing on the same session at the same time both compute an answer, and the answers
// agree about which tasks cover the session. What they do not share is the fragment memo, which
// resolveCovering allocates: it remembers what the initial fragment of a datagram was classified
// as, so the later fragments, which carry no transport header, are delivered or dropped with it.
//
// Last-writer-wins left the losing worker holding a filter whose memo nothing else shares. A
// datagram whose initial fragment was classified into one memo and whose later fragments were
// looked up in the other loses its tail — dropped, and reported as X3 delivery loss, for content
// the criterion did select. A manufactured loss report is worse than a silent one: it tells the
// agency product went missing that never did.
func TestConcurrentMissesShareOneFragmentMemo(t *testing.T) {
	f := newEnablerFixture(t)

	const seid = 700

	// A transport-port criterion on rules that constrain no port: the only shape whose filter
	// has to read the packet, and therefore the only one that carries a fragment memo at all.
	// A UE-address criterion yields a match-all filter with no memo, so it cannot exercise this.
	f.putSession(t, unmarkedSession(seid, "10.250.0.9"))
	f.activate(t, "W1", types.TargetIdentifier{Type: types.TargetTCPPort, Value: "443"})

	// Force every worker to miss: a tasking change invalidates the memo by epoch.
	f.e.epoch.Add(1)

	const workers = 8

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		answers [][]coveredTask
	)

	start := make(chan struct{})

	for range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			got := f.e.tasksCovering(seid)

			mu.Lock()
			answers = append(answers, got)
			mu.Unlock()
		}()
	}

	close(start)
	wg.Wait()

	var memo *fragmentMemo

	for i, got := range answers {
		if len(got) == 0 {
			t.Fatalf("worker %d resolved no covering task; the fixture is not exercising a miss", i)
		}

		if got[0].filter.frags == nil {
			t.Fatalf("worker %d resolved a filter with no fragment memo, so this test compares "+
				"nil against nil and would pass against the defect", i)
		}

		if memo == nil {
			memo = got[0].filter.frags

			continue
		}

		if got[0].filter.frags != memo {
			t.Fatalf("worker %d holds a different fragment memo from the others. A datagram whose "+
				"initial fragment is classified into one memo and whose later fragments are looked "+
				"up in another loses its tail — dropped, and reported as delivery loss, for "+
				"content the criterion selected", i)
		}
	}
}

// countingStore reports how many times the sessions were walked, which is the cost taskFaults used
// to pay on the X1 request goroutine.
type countingStore struct {
	SessionsStore

	mu    sync.Mutex
	walks int
}

func (c *countingStore) GetAllSessions() []PFCPSession {
	c.mu.Lock()
	c.walks++
	c.mu.Unlock()

	return c.SessionsStore.GetAllSessions()
}

func (c *countingStore) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.walks
}

// TestTaskFaultsDoesNotWalkEverySessionPerRequest pins the cost off the X1 request goroutine.
//
// li/x1 asks this once per task on *every* response that carries tasks — an activation, a
// modification, a deactivation, a status query alike. Answering it resolved every criterion
// against every session this element holds, so an element with twenty thousand sessions and ten
// tasks resolved two hundred thousand criterion sets to answer one provisioning message, on the
// goroutine answering it.
//
// That is exactly the cost the enabler's worker exists to keep off the request path — its own
// doc-comment says "an X1 request's latency would become a function of session count on the
// element holding the most sessions". The remedy for one path had reintroduced it on another.
//
// The answer is still determined when asked rather than pushed: the memo is stamped with the
// tasking epoch and the record's write counter, and every event that could change the answer moves
// one of them. What is avoided is recomputing an answer nothing has invalidated.
func TestTaskFaultsDoesNotWalkEverySessionPerRequest(t *testing.T) {
	f := newEnablerFixture(t)

	counting := &countingStore{SessionsStore: f.store}
	f.e.mu.Lock()
	f.e.sources = []SessionsStore{counting}
	f.e.mu.Unlock()

	for seid := uint64(800); seid < 810; seid++ {
		f.putSession(t, unmarkedSession(seid, "10.250.0.9"))
	}

	f.activate(t, "W1", ueAddr("10.250.0.9"))
	f.settle(t)

	// The first ask resolves.
	_ = f.e.taskFaults("W1")

	after := counting.count()

	// Nine more, with nothing changed in between: an ADMF interrogating, or simply several
	// X1 responses each carrying the task.
	for range 9 {
		_ = f.e.taskFaults("W1")
	}

	if grew := counting.count() - after; grew != 0 {
		t.Errorf("nine further X1 answers walked the sessions %d more times with nothing changed "+
			"between them. An X1 request's latency is then a function of session count, which is "+
			"the cost the enabler's worker exists to keep off this goroutine", grew)
	}

	// And a tasking change invalidates it, so the answer is still the current one rather than
	// a cached history.
	before := counting.count()

	f.deactivate(t, "W1")
	_ = f.e.taskFaults("W1")

	if counting.count() == before {
		t.Error("a tasking change did not invalidate the answer; a status reply that survives the " +
			"tasking it describes is a history, not a state")
	}
}
