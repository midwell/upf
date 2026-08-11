// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"net"
	"testing"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
)

// enablerFixture is a CC-POI duplication control wired to an in-memory session
// store, with the rules it would program to the datapath recorded instead.
type enablerFixture struct {
	e     *ccEnabler
	tasks *store.Store
	store SessionsStore
	// pushed is every set of rules programmed to the datapath, and datapath is what
	// those pushes add up to: whether each FAR is currently duplicating.
	//
	// Assertions read datapath rather than the session store, because that is where
	// interception either happens or does not. Duplication enabled while the tasking
	// changes is deliberately not written back to the session store — see retask —
	// so a test reading the store would report an interception as absent while it was
	// running.
	pushed   []PacketForwardingRules
	datapath map[farRef]bool
}

func newEnablerFixture(t *testing.T) *enablerFixture {
	t.Helper()
	f := &enablerFixture{
		tasks: store.New(), store: NewInMemoryStore(),
		datapath: make(map[farRef]bool),
	}
	f.e = newCCEnabler(f.tasks, func(_, updated PacketForwardingRules) {
		f.pushed = append(f.pushed, updated)
		f.record(updated)
	})
	f.e.addSource(f.store)

	return f
}

// record applies to the fake datapath what a push would program.
func (f *enablerFixture) record(rules PacketForwardingRules) {
	for i := range rules.fars {
		ref := farRef{seid: rules.fars[i].fseID, farID: rules.fars[i].farID}
		f.datapath[ref] = rules.fars[i].Duplicates()
	}
}

// putSession installs a session, running the same tasking step the PFCP
// establishment handler runs, so what the test sees is what a real establishment
// would produce.
func (f *enablerFixture) putSession(t *testing.T, s PFCPSession) {
	t.Helper()
	updated := PacketForwardingRules{
		pdrs: append([]pdr(nil), s.pdrs...),
		fars: append([]far(nil), s.fars...),
	}
	f.e.applyTasking(&s, &updated)
	if err := f.store.PutSession(s); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	// An establishment programs the datapath from the session's own rules — the
	// datapath's add path takes those, and only its modify path takes the update
	// subset. Recording the wrong one here would leave the session-side marking
	// untested.
	f.record(s.PacketForwardingRules)
}

// duplicates reports whether the datapath is currently duplicating the traffic of
// a FAR — that is, whether interception is actually happening for it.
func (f *enablerFixture) duplicates(t *testing.T, seid uint64, farID uint32) bool {
	t.Helper()
	ref := farRef{seid: seid, farID: farID}
	if _, ok := f.datapath[ref]; !ok {
		t.Fatalf("FAR %d of session %d was never programmed", farID, seid)
	}

	return f.datapath[ref]
}

// activate installs a task the way the X1 listener does: the criteria checked
// first, then stored, then duplication re-derived.
func (f *enablerFixture) activate(t *testing.T, xid types.XID, ids ...types.TargetIdentifier) {
	t.Helper()
	task := types.InterceptTask{XID: xid, Targets: ids, Products: []types.ProductType{types.ProductCC}}
	if err := f.e.canApply(task); err != nil {
		t.Fatalf("canApply(%v): %v", ids, err)
	}
	if !f.tasks.Activate(task) {
		t.Fatal("Activate failed")
	}
	f.e.retask()
}

func (f *enablerFixture) deactivate(t *testing.T, xid types.XID) {
	t.Helper()
	if !f.tasks.Deactivate(xid) {
		t.Fatalf("Deactivate(%q) found no task", xid)
	}
	f.e.retask()
}

func ueAddr(v string) types.TargetIdentifier {
	return types.TargetIdentifier{Type: types.TargetUEIPv4, Value: v}
}

// unmarkedSession is a session the SMF asked no duplication for — the normal case,
// and the one a criterion other than a PFCP Session ID has to cope with.
func unmarkedSession(seid uint64, ue string) PFCPSession {
	addr := ip2int(net.ParseIP(ue))

	return PFCPSession{
		localSEID: seid,
		PacketForwardingRules: PacketForwardingRules{
			pdrs: []pdr{
				uplinkPDR(seid, 1, uint32(seid)+0x1000, ip2int(net.ParseIP("10.76.0.2")), addr),
				downlinkPDR(seid, 2, 2, addr),
			},
			fars: []far{
				{farID: 1, fseID: seid, applyAction: ActionForward},
				{farID: 2, fseID: seid, applyAction: ActionForward},
			},
		},
	}
}

// TestEnableDuplicationForUnmarkedSession is the case the CC-POI could not serve
// before: a criterion identifying traffic the SMF never marked for duplication.
// Acknowledging such a task and producing nothing is mandated interception failing
// silently, so the CC-POI has to enable duplication itself.
func TestEnableDuplicationForUnmarkedSession(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))

	if f.duplicates(t, 100, 1) || f.duplicates(t, 100, 2) {
		t.Fatal("duplication on before any tasking")
	}

	f.activate(t, "W1", ueAddr("10.250.0.9"))

	if !f.duplicates(t, 100, 1) || !f.duplicates(t, 100, 2) {
		t.Error("a task keyed by UE address did not enable duplication for that session")
	}
	if len(f.pushed) == 0 {
		t.Error("the change was not pushed to the datapath, so nothing is intercepted")
	}
}

// TestEnablementDoesNotTouchOtherSubscribers checks the other side of the same
// step: enabling duplication for one criterion must not enable it for traffic the
// criterion does not identify. Over-collection is a warrant breach, not a
// performance problem.
func TestEnablementDoesNotTouchOtherSubscribers(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.putSession(t, unmarkedSession(200, "10.250.0.10"))

	f.activate(t, "W1", ueAddr("10.250.0.9"))

	if !f.duplicates(t, 100, 1) {
		t.Error("the tasked session is not duplicated")
	}
	if f.duplicates(t, 200, 1) || f.duplicates(t, 200, 2) {
		t.Error("an untasked subscriber's traffic is being duplicated")
	}
}

// TestDuplicationSurvivesSessionModification is the R22 failure mode. The SMF owns
// PFCP session state and its modifications carry its own view of each FAR, which
// does not include duplication it never asked for. Losing the flip there ends the
// interception mid-session, with nothing logged and the triggering function never
// told.
func TestDuplicationSurvivesSessionModification(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.activate(t, "W1", ueAddr("10.250.0.9"))

	// What a Session Modification does: the SMF sends its FAR again, with its own
	// apply action and no notion of duplication.
	sess, _ := f.store.GetSession(100)
	sess.fars = []far{
		{farID: 1, fseID: 100, applyAction: ActionForward},
		{farID: 2, fseID: 100, applyAction: ActionForward},
	}
	// A separate slice, as the handler has: it accumulates the FARs it parsed from
	// the request and pushes those, while the session holds its own copies. Sharing
	// one slice here would let a test pass while the rules reaching the datapath went
	// unmarked.
	updated := PacketForwardingRules{fars: append([]far(nil), sess.fars...)}

	f.e.applyTasking(&sess, &updated)
	if err := f.store.PutSession(sess); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	f.record(updated)

	if !f.duplicates(t, 100, 1) || !f.duplicates(t, 100, 2) {
		t.Error("a session modification ended the interception")
	}
	// Specifically in the rules pushed: the datapath acts on those, not on the store.
	for i := range updated.fars {
		if !updated.fars[i].Duplicates() {
			t.Errorf("FAR %d pushed to the datapath without duplication", updated.fars[i].farID)
		}
	}
}

// TestCriteriaApplyToLaterSessions checks that a task armed before its traffic
// exists starts intercepting when the traffic appears. A criterion may name a
// subscriber who has not attached; requiring the triggering function to re-task on
// each new session would make coverage depend on it noticing.
func TestCriteriaApplyToLaterSessions(t *testing.T) {
	f := newEnablerFixture(t)

	// Tasked with no session at all: accepted, selecting nothing yet.
	f.activate(t, "W1", ueAddr("10.250.0.9"))

	f.putSession(t, unmarkedSession(100, "10.250.0.9"))

	if !f.duplicates(t, 100, 1) || !f.duplicates(t, 100, 2) {
		t.Error("a session established after tasking is not intercepted")
	}
}

// TestDeactivationRemovesOnlyItsOwnEnablement covers the two ways withdrawal can
// go wrong: stopping content another warrant still requires, and stopping
// duplication the SMF asked for on its own account.
func TestDeactivationRemovesOnlyItsOwnEnablement(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))

	// Two warrants over the same traffic, described two different ways.
	f.activate(t, "W1", ueAddr("10.250.0.9"))
	f.activate(t, "W2", types.TargetIdentifier{Type: types.TargetFSEID, Value: "100"})

	f.deactivate(t, "W1")
	if !f.duplicates(t, 100, 1) {
		t.Error("withdrawing one warrant stopped content the other still requires")
	}

	f.deactivate(t, "W2")
	if f.duplicates(t, 100, 1) || f.duplicates(t, 100, 2) {
		t.Error("duplication continued after the last warrant was withdrawn")
	}
}

// TestDeactivationLeavesTheSMFsOwnDuplication checks that withdrawing CC-POI
// tasking does not clear duplication the SMF instructed with the DUPL apply
// action. The SMF's instruction belongs to its own triggering, which this element
// is not party to.
func TestDeactivationLeavesTheSMFsOwnDuplication(t *testing.T) {
	f := newEnablerFixture(t)
	s := unmarkedSession(100, "10.250.0.9")
	s.fars[0].applyAction = ActionForward | ActionDuplicate // the SMF marked the uplink FAR
	f.putSession(t, s)

	f.activate(t, "W1", ueAddr("10.250.0.9"))
	f.deactivate(t, "W1")

	if !f.duplicates(t, 100, 1) {
		t.Error("withdrawing CC-POI tasking cleared duplication the SMF asked for")
	}
	if f.duplicates(t, 100, 2) {
		t.Error("duplication this element enabled was not withdrawn")
	}
}

// TestEnablementIsIdempotent checks that traffic covered by several criteria, or by
// both the SMF's instruction and this element's, is duplicated once. Duplication is
// a property of the FAR rather than a count of the parties wanting it, which is
// what makes a second copy impossible — this pins that, since a counter would be
// the obvious way to get withdrawal wrong.
func TestEnablementIsIdempotent(t *testing.T) {
	f := newEnablerFixture(t)
	s := unmarkedSession(100, "10.250.0.9")
	s.fars[0].applyAction = ActionForward | ActionDuplicate
	f.putSession(t, s)

	// One task, two criteria selecting the same traffic, plus the SMF's own DUPL.
	f.activate(t, "W1",
		ueAddr("10.250.0.9"),
		types.TargetIdentifier{Type: types.TargetFSEID, Value: "100"})

	if !f.duplicates(t, 100, 1) || !f.duplicates(t, 100, 2) {
		t.Error("traffic covered by several criteria is not duplicated")
	}
	// The SMF's own bit is never written by this element, so withdrawal cannot clear
	// it and enabling cannot double it: duplication is a property of the FAR, not a
	// count of the parties wanting it.
	sess, _ := f.store.GetSession(100)
	for i := range sess.fars {
		if sess.fars[i].farID == 1 && sess.fars[i].applyAction&ActionDuplicate == 0 {
			t.Error("the SMF's DUPL apply-action was overwritten")
		}
		if sess.fars[i].farID == 2 && sess.fars[i].applyAction&ActionDuplicate != 0 {
			t.Errorf("FAR 2 applyAction = %#x, want the SMF's own action untouched",
				sess.fars[i].applyAction)
		}
	}
}

// TestCanApplyRefusesUnresolvableCriteria checks the refusal path at the point it
// matters: before the task is acknowledged. A task accepted here and unmatchable
// afterwards is an interception that reports success and produces nothing.
func TestCanApplyRefusesUnresolvableCriteria(t *testing.T) {
	f := newEnablerFixture(t)

	cases := []struct {
		name string
		task types.InterceptTask
	}{
		{"no criteria at all", types.InterceptTask{XID: "W1"}},
		{"a criterion this datapath cannot resolve", types.InterceptTask{
			XID:     "W1",
			Targets: []types.TargetIdentifier{{Type: types.TargetUEIPv6, Value: "2001:db8::9"}},
		}},
		{"one good criterion and one bad", types.InterceptTask{
			XID: "W1",
			Targets: []types.TargetIdentifier{
				ueAddr("10.250.0.9"),
				{Type: types.TargetPDR, Value: "0a01"},
			},
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := f.e.canApply(c.task); err == nil {
				t.Error("canApply accepted a task this element cannot carry out")
			}
		})
	}

	// And a criterion that resolves but selects nothing yet is *not* refused: the
	// subscriber may attach later.
	if err := f.e.canApply(types.InterceptTask{
		XID: "W1", Targets: []types.TargetIdentifier{ueAddr("10.250.0.99")},
	}); err != nil {
		t.Errorf("canApply refused a criterion that simply has no session yet: %v", err)
	}
}

// TestRetaskSkipsUnchangedSessions checks that re-deriving duplication does not
// reprogram sessions whose answer did not change. Rewriting rules the datapath
// already has is work that can fail, and by then there is no acknowledgement left
// to refuse.
func TestRetaskSkipsUnchangedSessions(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.putSession(t, unmarkedSession(200, "10.250.0.10"))

	f.activate(t, "W1", ueAddr("10.250.0.9"))
	after := len(f.pushed)
	if after != 1 {
		t.Fatalf("pushed %d sessions, want just the tasked one", after)
	}

	// Nothing about the answer changes, so nothing should be pushed again.
	f.e.retask()
	if len(f.pushed) != after {
		t.Errorf("pushed %d times, want %d — unchanged sessions were reprogrammed",
			len(f.pushed), after)
	}
}

// TestLookupFindsTaskByNonSessionCriterion is the step without which the rest of
// this is useless. The datapath tags every copy with the session it came from, so
// a task keyed by anything else — an address, a tunnel, a network instance — has to
// be found by resolving its criteria against that session. Failing to would leave
// the CC-POI duplicating a subject's traffic, reporting every copy as untasked
// content, and delivering none of it.
func TestLookupFindsTaskByNonSessionCriterion(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.putSession(t, unmarkedSession(200, "10.250.0.10"))
	f.activate(t, "W1", ueAddr("10.250.0.9"))

	task, covering, ok := lookupTrigger(f.tasks, f.e, 100)
	if !ok {
		t.Fatal("a copy from the tasked session was not attributed to its warrant")
	}
	if task.XID != "W1" || covering != 1 {
		t.Errorf("attributed to %q (%d covering), want W1 (1)", task.XID, covering)
	}

	// The other subscriber's session is not covered, and a copy from it must stay
	// unattributed rather than be labelled with someone else's warrant.
	if _, _, ok := lookupTrigger(f.tasks, f.e, 200); ok {
		t.Error("a copy from an untasked session was attributed to a warrant")
	}
	// Nor may a session this element has never heard of resolve to anything.
	if _, _, ok := lookupTrigger(f.tasks, f.e, 999); ok {
		t.Error("a copy tagged with an unknown session was attributed to a warrant")
	}
}

// TestLookupOrderIsStableAcrossWarrants checks that when several warrants cover one
// session the same one is chosen every time. Choosing differently per packet
// scatters a session's product across the covering warrants, leaving every agency
// with a partial stream and none with a usable one — which is a defect that has
// occurred here before.
func TestLookupOrderIsStableAcrossWarrants(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.activate(t, "W-b", ueAddr("10.250.0.9"))
	f.activate(t, "W-a", types.TargetIdentifier{Type: types.TargetFSEID, Value: "100"})

	first, covering, ok := lookupTrigger(f.tasks, f.e, 100)
	if !ok {
		t.Fatal("no task found")
	}
	if covering != 2 {
		t.Errorf("covering = %d, want both warrants counted so the overlap is reported", covering)
	}
	for range 20 {
		task, _, _ := lookupTrigger(f.tasks, f.e, 100)
		if task.XID != first.XID {
			t.Fatalf("attribution moved between warrants: %q then %q", first.XID, task.XID)
		}
	}
	if first.XID != "W-a" {
		t.Errorf("chose %q, want the lowest XID W-a", first.XID)
	}
}

// TestLookupCountsOnlyCoveringWarrants checks that the overlap report counts
// warrants that actually cover the session. Counting every active task would report
// an overlap whenever two unrelated subscribers were under interception, which
// tells an ADMF that a warrant is receiving nothing when it is receiving
// everything.
func TestLookupCountsOnlyCoveringWarrants(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.putSession(t, unmarkedSession(200, "10.250.0.10"))
	f.activate(t, "W1", ueAddr("10.250.0.9"))
	f.activate(t, "W2", ueAddr("10.250.0.10"))

	if _, covering, _ := lookupTrigger(f.tasks, f.e, 100); covering != 1 {
		t.Errorf("covering = %d for a session under one warrant, want 1", covering)
	}
}
