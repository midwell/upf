// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
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
	// changes is deliberately not written back to the session store — see transact —
	// so a test reading the store would report an interception as absent while it was
	// running.
	//
	// Guarded, because the pushes come from the enabler's worker while the test
	// asserts on them, and because a test of concurrent tasking changes drives them
	// from more than one goroutine.
	mu       sync.Mutex
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
		f.mu.Lock()
		f.pushed = append(f.pushed, updated)
		f.mu.Unlock()
		f.record(updated)
	})
	f.e.addSource(f.store)
	// The worker belongs to the element, so it must not outlive it — a test that
	// leaves one running is the shape of a process that would.
	t.Cleanup(f.e.stop)

	return f
}

// record applies to the fake datapath what a push would program.
func (f *enablerFixture) record(rules PacketForwardingRules) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i := range rules.fars {
		ref := farRef{seid: rules.fars[i].fseID, farID: rules.fars[i].farID}
		f.datapath[ref] = rules.fars[i].Duplicates()
	}
}

// pushCount is how many times rules have been programmed to the datapath.
func (f *enablerFixture) pushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.pushed)
}

// putSession installs a session, running the same tasking step the PFCP
// establishment handler runs, so what the test sees is what a real establishment
// would produce.
func (f *enablerFixture) putSession(t *testing.T, s PFCPSession) {
	t.Helper()
	f.derive(&s)
	f.commit(t, s)
}

// derive runs the first half of a PFCP session establishment: duplication is
// re-derived for the session and the rules the handler is about to push are
// programmed. The session is deliberately not stored — messages_session.go:182
// stores it afterwards, and the interval between the two is where the
// reproductions below act.
func (f *enablerFixture) derive(s *PFCPSession) {
	updated := PacketForwardingRules{
		pdrs: append([]pdr(nil), s.pdrs...),
		fars: append([]far(nil), s.fars...),
	}
	f.e.applyTasking(s, &updated)
	// An establishment programs the datapath from the session's own rules — the
	// datapath's add path takes those, and only its modify path takes the update
	// subset. Recording the wrong one here would leave the session-side marking
	// untested.
	f.record(s.PacketForwardingRules)
}

// deriveModification is the same first half for a session modification: the SMF
// restates rules, duplication is re-derived over them, and only the changed
// subset reaches the datapath. messages_session.go:386 orders it exactly as :182
// does, so it leaves the same interval open — but on a session the store already
// holds, which is the half a rule keyed on absence would miss.
func (f *enablerFixture) deriveModification(s *PFCPSession) {
	// A separate slice, as the handler has: it accumulates the FARs it parsed from
	// the request and pushes those, while the session holds its own copies.
	updated := PacketForwardingRules{fars: append([]far(nil), s.fars...)}
	f.e.applyTasking(s, &updated)
	f.record(updated)
}

// commit is the second half: the session becomes visible to GetAllSessions, and
// only then is what was programmed recorded — the order both handlers use, and
// the order the carry-over in transact depends on.
func (f *enablerFixture) commit(t *testing.T, s PFCPSession) {
	t.Helper()
	if err := f.store.PutSession(s); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	f.e.sessionProgrammed(&s)
}

// recorded is what the element believes it last told the datapath about a FAR,
// and whether it holds any record of it at all. A missing entry is not a
// bookkeeping blemish — transact reads it as "not duplicating" and therefore as
// an instruction to do nothing.
func (f *enablerFixture) recorded(seid uint64, farID uint32) (value, held bool) {
	f.e.mu.Lock()
	defer f.e.mu.Unlock()

	v, ok := f.e.programmed[farRef{seid: seid, farID: farID}]

	return v.duplicating, ok
}

// settle waits for the element to stop re-deriving of its own accord. A pass that
// preserves live duplication asks for one more, so the state that matters is the
// one after the element has stopped rather than the one after the pass the test
// asked for.
func (f *enablerFixture) settle(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		f.e.mu.Lock()
		idle := f.e.requested == f.e.completed
		f.e.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the element never stopped re-deriving")
		}
		time.Sleep(time.Millisecond)
	}
}

// windowed replaces the fixture's session source with one that can hold a pass
// after it has read the sessions.
func (f *enablerFixture) windowed(t *testing.T) *windowSource {
	t.Helper()
	w := &windowSource{
		SessionsStore: f.store,
		hold:          make(chan struct{}, 1),
		read:          make(chan struct{}),
		release:       make(chan struct{}),
	}
	f.e.removeSource(f.store)
	f.e.addSource(w)

	return w
}

// duplicates reports whether the datapath is currently duplicating the traffic of
// a FAR — that is, whether interception is actually happening for it.
func (f *enablerFixture) duplicates(t *testing.T, seid uint64, farID uint32) bool {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()

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
	task := ccTask(xid, ids...)
	if err := f.e.canApply(task); err != nil {
		t.Fatalf("canApply(%v): %v", ids, err)
	}
	if !f.tasks.Activate(task) {
		t.Fatal("Activate failed")
	}
	f.e.retaskAndWait()
}

func (f *enablerFixture) deactivate(t *testing.T, xid types.XID) {
	t.Helper()
	if !f.tasks.Deactivate(xid) {
		t.Fatalf("Deactivate(%q) found no task", xid)
	}
	f.e.retaskAndWait()
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
				downlinkPDR(seid, 2, addr),
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
	if f.pushCount() == 0 {
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

	// Every case requires content, so what is under test is the criteria check and
	// not the product check TestCanApplyRefusesTaskingWithoutContent covers.
	cases := []struct {
		name    string
		targets []types.TargetIdentifier
	}{
		{"no criteria at all", nil},
		{
			"a criterion this datapath cannot resolve",
			[]types.TargetIdentifier{{Type: types.TargetUEIPv6, Value: "2001:db8::9"}},
		},
		{
			"one good criterion and one bad",
			[]types.TargetIdentifier{ueAddr("10.250.0.9"), {Type: types.TargetPDR, Value: "0a01"}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := f.e.canApply(ccTask("W1", c.targets...)); err == nil {
				t.Error("canApply accepted a task this element cannot carry out")
			}
		})
	}

	// And a criterion that resolves but selects nothing yet is *not* refused: the
	// subscriber may attach later.
	if err := f.e.canApply(ccTask("W1", ueAddr("10.250.0.99"))); err != nil {
		t.Errorf("canApply refused a criterion that simply has no session yet: %v", err)
	}
}

// ccTask is tasking for the product this point of interception makes — the X1
// deliveryType X3Only, or X2andX3 as far as this element is concerned.
func ccTask(xid types.XID, ids ...types.TargetIdentifier) types.InterceptTask {
	return types.InterceptTask{
		XID: xid, Targets: ids,
		Products: []types.ProductType{types.ProductCC},
	}
}

// iriOnlyTask is tasking for a product this point of interception does not make.
// The X1 deliveryType X2Only maps to exactly this.
func iriOnlyTask(xid types.XID, ids ...types.TargetIdentifier) types.InterceptTask {
	return types.InterceptTask{
		XID: xid, Targets: ids,
		Products: []types.ProductType{types.ProductIRI},
	}
}

// TestCanApplyRefusesTaskingWithoutContent covers the product question, which is
// prior to the criteria one: a CC-POI produces xCC and nothing else, so tasking
// that does not require content is tasking it cannot honour. Accepting it tells the
// triggering function an interception is running that will deliver nothing, and has
// the datapath duplicate a subject's traffic so every copy can be discarded.
//
// li/x1's TestCanApplyRefusesBeforeAcknowledging is the other half: an error from
// here reaches the triggering function as a refusal carrying this reason, and the
// task is not stored.
func TestCanApplyRefusesTaskingWithoutContent(t *testing.T) {
	f := newEnablerFixture(t)

	if err := f.e.canApply(iriOnlyTask("W1", ueAddr("10.250.0.9"))); err == nil {
		t.Error("canApply accepted a task that does not require content of communication")
	}

	// The same criteria with content required is accepted, so the refusal is about
	// the product and not about anything else in the task.
	if err := f.e.canApply(types.InterceptTask{
		XID: "W1", Targets: []types.TargetIdentifier{ueAddr("10.250.0.9")},
		Products: []types.ProductType{types.ProductIRI, types.ProductCC},
	}); err != nil {
		t.Errorf("canApply refused a task that does require content: %v", err)
	}
}

// TestNoDuplicationForTaskingWithoutContent asserts the programmed state rather
// than the refusal: a task admitted before canApply asked the product question must
// not still be duplicating. The task is put straight into the store, which is what
// such a leftover looks like.
func TestNoDuplicationForTaskingWithoutContent(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))

	if !f.tasks.Activate(iriOnlyTask("W1", ueAddr("10.250.0.9"))) {
		t.Fatal("Activate failed")
	}
	f.e.retaskAndWait()

	if f.duplicates(t, 100, 1) || f.duplicates(t, 100, 2) {
		t.Error("a task that does not require content is duplicating a subject's traffic")
	}
	if _, _, _, ok := lookupTrigger(f.tasks, f.e, 100); ok {
		t.Error("a copy was attributed to a task with no content product to deliver")
	}
}

// TestTaskingWithoutContentDoesNotStealAttribution is the sharp edge of the same
// filter. Attribution takes the first covering task in XID order, so a leftover
// non-content task sorting ahead of a real one would swallow the whole session's
// product: every copy attributed to a task with no X3 destination, and the warrant
// that has one receiving nothing.
func TestTaskingWithoutContentDoesNotStealAttribution(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))

	if !f.tasks.Activate(iriOnlyTask("W-a", ueAddr("10.250.0.9"))) {
		t.Fatal("Activate failed")
	}
	f.activate(t, "W-b", ueAddr("10.250.0.9"))

	task, _, covering, ok := lookupTrigger(f.tasks, f.e, 100)
	if !ok {
		t.Fatal("no task found for a session under a content warrant")
	}
	if task.XID != "W-b" {
		t.Errorf("attributed to %q, want the warrant that requires content", task.XID)
	}
	if covering != 1 {
		t.Errorf("covering = %d, want 1 — a task this POI cannot serve is not an overlap", covering)
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
	after := f.pushCount()
	if after != 1 {
		t.Fatalf("pushed %d sessions, want just the tasked one", after)
	}

	// Nothing about the answer changes, so nothing should be pushed again.
	f.e.retaskAndWait()
	if f.pushCount() != after {
		t.Errorf("pushed %d times, want %d — unchanged sessions were reprogrammed",
			f.pushCount(), after)
	}
}

// TestConcurrentTaskingChangesDoNotLoseAnUpdate is the lost update, which only
// appears under interleaving and so was worth nothing as a fix until it had been
// observed.
//
// Two provisioning requests arrive at once. When only the individual reads and
// writes were protected, the pass that began earlier could program and publish
// last: it derived duplication from a task set that no longer existed, cleared it
// for a task that was still active, and nothing re-derived until some unrelated
// event happened to trigger another pass. Nothing downstream could notice — a
// dropped copy produces no record for anybody to miss — so it could hold for the
// life of the warrant.
func TestConcurrentTaskingChangesDoNotLoseAnUpdate(t *testing.T) {
	for round := range 50 {
		f := newEnablerFixture(t)
		// One pass is made slow, so the losing interleaving is reached rather than
		// hoped for: the slow pass reads the tasking, the other changes it and
		// finishes, and the slow one then publishes over the top.
		paced := &pacedSource{SessionsStore: f.store, delayOne: make(chan struct{}, 1)}
		f.e.removeSource(f.store)
		f.e.addSource(paced)

		f.putSession(t, unmarkedSession(100, "10.250.0.9"))
		f.putSession(t, unmarkedSession(200, "10.250.0.10"))
		f.activate(t, "W1", ueAddr("10.250.0.9"))

		paced.delayOne <- struct{}{}

		// One request withdraws W1, the other activates W2 for a different subscriber,
		// in both orders. Which of the two is the delayed pass decides which way the
		// loss goes — duplication cleared for a task that is still active, or
		// surviving one that was withdrawn — and they are the same lost update.
		requests := []func(){
			func() { f.tasks.Deactivate("W1"); f.e.retaskAndWait() },
			func() {
				f.tasks.Activate(ccTask("W2", ueAddr("10.250.0.10")))
				f.e.retaskAndWait()
			},
		}
		if round%2 == 1 {
			requests[0], requests[1] = requests[1], requests[0]
		}

		var wg sync.WaitGroup
		for _, request := range requests {
			wg.Add(1)
			go func() {
				defer wg.Done()
				request()
			}()
		}
		wg.Wait()

		// Whichever ran first, the tasking that stands at the end is W2 alone, and
		// that is what the datapath must be doing.
		if !f.duplicates(t, 200, 1) || !f.duplicates(t, 200, 2) {
			t.Fatal("duplication was cleared for a task that is still active")
		}
		if f.duplicates(t, 100, 1) || f.duplicates(t, 100, 2) {
			t.Fatal("duplication survived the withdrawal of the task that required it")
		}
	}
}

// pacedSource delays one pass over the sessions, on request. The tasking is read
// before the sessions are, so a delayed pass is one holding a snapshot the world
// has moved past — which is the whole shape of the lost update.
type pacedSource struct {
	SessionsStore
	delayOne chan struct{}
}

func (p *pacedSource) GetAllSessions() []PFCPSession {
	select {
	case <-p.delayOne:
		time.Sleep(5 * time.Millisecond)
	default:
	}

	return p.SessionsStore.GetAllSessions()
}

// heldSource stops a transaction inside the worker until the test lets it go, so a
// burst of requests provably arrives while one pass is running rather than by
// hoping the scheduler arranges it.
type heldSource struct {
	SessionsStore
	entered chan struct{}
	release chan struct{}
}

func (h *heldSource) GetAllSessions() []PFCPSession {
	h.entered <- struct{}{}
	<-h.release

	return h.SessionsStore.GetAllSessions()
}

// windowSource holds one pass *after* it has read the sessions, which is what
// distinguishes it from heldSource: the interval being driven is the one in which
// a session is already programmed into the datapath and recorded, and is not yet
// visible to GetAllSessions. Both PFCP handlers leave it open — derive, push,
// store — and it is a few instructions wide, so racing two goroutines does not
// reach it. A pass is held only while a token has been placed in hold, so a test
// can hold one and then let the element settle.
type windowSource struct {
	SessionsStore
	hold    chan struct{}
	read    chan struct{}
	release chan struct{}
}

func (w *windowSource) GetAllSessions() []PFCPSession {
	all := w.SessionsStore.GetAllSessions()

	select {
	case <-w.hold:
		w.read <- struct{}{}
		<-w.release
	default:
	}

	return all
}

// TestRecordOfDuplicationSurvivesAPassThatCouldNotSeeIt is the narrow half of the
// lost update: a session established while a re-derivation is walking is invisible
// to it, so the wholesale publish at the end of that pass discards the fact that
// duplication was enabled for it. The element then holds no evidence of having
// enabled duplication it did enable.
//
// Asserted on the record rather than on the datapath, because the record is what
// the next section changes and because at this point the datapath is still right —
// it is the *next* re-derivation, finding nothing to change, that leaves the
// traffic being copied. The test that pins that is below.
func TestRecordOfDuplicationSurvivesAPassThatCouldNotSeeIt(t *testing.T) {
	f := newEnablerFixture(t)
	w := f.windowed(t)

	f.activate(t, "W1", ueAddr("10.250.0.9"))

	// A pass begins and reads the sessions. There are none.
	w.hold <- struct{}{}
	gen := f.e.request()
	<-w.read

	// The PFCP goroutine establishes a session the tasking covers: duplication
	// derived, rules programmed, session not yet in the store.
	sess := unmarkedSession(100, "10.250.0.9")
	f.derive(&sess)
	f.commit(t, sess)

	// The pass now publishes a conclusion it drew before the session existed.
	w.release <- struct{}{}
	f.e.await(gen)
	f.settle(t)

	for _, farID := range []uint32{1, 2} {
		value, held := f.recorded(100, farID)
		if !held {
			t.Errorf("FAR %d: the element forgot duplication it had enabled, because a pass that could not have seen the session published afterwards", farID)

			continue
		}
		if !value {
			t.Errorf("FAR %d: the element records duplication as off while the datapath is duplicating", farID)
		}
	}
}

// TestDuplicationStopsForASessionEstablishedInsideTheWithdrawalsOwnPass is the one
// that matters, and it is deliberately arranged so that the pass which loses the
// record is the pass serving the withdrawal itself.
//
// That is what makes preserving the record insufficient on its own. Tasking
// changes are what ask for a re-derivation, and this tasking change has already
// been consumed: after the pass publishes, nothing schedules another. So an
// element that merely remembers correctly is an element whose account is accurate
// about a datapath that is still copying a subject's traffic under no tasking at
// all.
//
// The assertion is therefore on the datapath and not on the record. A fix that
// made the bookkeeping right while leaving duplication running would pass a test
// that pinned the record, and that is the failure this exists to catch.
func TestDuplicationStopsForASessionEstablishedInsideTheWithdrawalsOwnPass(t *testing.T) {
	f := newEnablerFixture(t)
	w := f.windowed(t)

	f.activate(t, "W1", ueAddr("10.250.0.9"))

	// The PFCP goroutine derives duplication for a new session and programs it.
	sess := unmarkedSession(100, "10.250.0.9")
	f.derive(&sess)
	if !f.duplicates(t, 100, 1) || !f.duplicates(t, 100, 2) {
		t.Fatal("the establishment did not start the interception it was tasked with")
	}

	// The withdrawal arrives inside the interval before the session is stored, and
	// its own pass is the one that cannot see the session.
	w.hold <- struct{}{}
	if !f.tasks.Deactivate("W1") {
		t.Fatal("Deactivate found no task")
	}
	gen := f.e.request()
	<-w.read

	f.commit(t, sess)
	w.release <- struct{}{}
	f.e.await(gen)

	// Nothing else asks for a re-derivation. Anything that happens from here the
	// element does on its own account, which is the whole point.
	f.settle(t)

	if f.duplicates(t, 100, 1) || f.duplicates(t, 100, 2) {
		t.Error("duplication outlived the tasking that authorised it: the datapath is copying a subject's traffic under no task at all")
	}
}

// TestDuplicationStopsForAStoredSessionBroughtWithinTheTasking is the window the
// establishment case does not reach, and the reason the carry-over rule is about
// recency rather than about presence.
//
// Here the session is already in the store, so the pass does see it — as it stood
// before the modification. A modification that brings it within a criterion has
// the session path record duplication while the pass holds the conclusion it drew
// from the older copy, and the publish overwrites the newer value with the staler
// one. The ref is present in the pass's own result, so a rule that carried over
// only entries *absent* from it preserves nothing here and this stays broken.
func TestDuplicationStopsForAStoredSessionBroughtWithinTheTasking(t *testing.T) {
	f := newEnablerFixture(t)
	w := f.windowed(t)

	f.activate(t, "W1", ueAddr("10.250.0.9"))
	// A session the tasking does not cover, and which the store already holds.
	f.putSession(t, unmarkedSession(100, "10.250.0.99"))
	if f.duplicates(t, 100, 1) || f.duplicates(t, 100, 2) {
		t.Fatal("an untasked subscriber's traffic is being duplicated")
	}

	// A pass begins and reads the session in its pre-modification state.
	w.hold <- struct{}{}
	gen := f.e.request()
	<-w.read

	// The modification brings the session within the criterion.
	modified := unmarkedSession(100, "10.250.0.9")
	f.deriveModification(&modified)
	f.commit(t, modified)
	if !f.duplicates(t, 100, 1) || !f.duplicates(t, 100, 2) {
		t.Fatal("the modification did not start the interception the tasking now covers")
	}

	// The pass publishes the conclusion it drew from the copy it read.
	w.release <- struct{}{}
	f.e.await(gen)
	f.settle(t)

	f.deactivate(t, "W1")
	f.settle(t)

	if f.duplicates(t, 100, 1) || f.duplicates(t, 100, 2) {
		t.Error("duplication outlived the tasking that authorised it: the withdrawal found a record a staler pass had published over, and had nothing to change")
	}
}

// TestAStalePassDoesNotEndAnInterceptionTheTaskingRequires is the same window in
// the other direction, and it is the sharper failure of the two.
//
// A re-derivation compares its conclusion against the record as it stands at the
// moment it compares, not as it stood when it read the sessions. While the record
// was written before the session was stored, a modification bringing a session
// within a criterion gave a pass holding the pre-modification copy a *newer* value
// to disagree with — so the pass did not merely forget, it pushed the FAR off,
// ending an interception the tasking still required. No withdrawal is needed for
// this one, and nothing downstream can see it: the triggering function was told
// the task was applied, and the product that would be missing was never made.
//
// It also pins the second half of that: what the pass would have pushed is the
// FAR body from its own stale snapshot, so restating it would put the SMF's
// pre-modification forwarding back on the datapath.
func TestAStalePassDoesNotEndAnInterceptionTheTaskingRequires(t *testing.T) {
	f := newEnablerFixture(t)
	w := f.windowed(t)

	f.activate(t, "W1", ueAddr("10.250.0.9"))
	f.putSession(t, unmarkedSession(100, "10.250.0.99"))

	w.hold <- struct{}{}
	gen := f.e.request()
	<-w.read

	modified := unmarkedSession(100, "10.250.0.9")
	f.deriveModification(&modified)
	f.commit(t, modified)

	w.release <- struct{}{}
	f.e.await(gen)
	f.settle(t)

	// W1 is still active and covers this session.
	if !f.duplicates(t, 100, 1) || !f.duplicates(t, 100, 2) {
		t.Error("a re-derivation holding a pre-modification copy of the session ended an interception that active tasking requires")
	}
}

// TestDepartedSessionsDropOutOfTheRecord is the property the wholesale replace
// existed for, and the one carrying entries over could quietly cost. The old code
// could not leak because it discarded everything each pass; this asserts the
// comparison that replaces that guarantee gets the other direction right.
func TestDepartedSessionsDropOutOfTheRecord(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.activate(t, "W1", ueAddr("10.250.0.9"))

	if _, held := f.recorded(100, 1); !held {
		t.Fatal("the tasked session was never recorded, so this asserts nothing")
	}

	if err := f.store.DeleteSession(100); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	f.e.retaskAndWait()
	f.settle(t)

	for _, farID := range []uint32{1, 2} {
		if _, held := f.recorded(100, farID); held {
			t.Errorf("FAR %d of a released session is still in the record, which grows for the life of the process", farID)
		}
	}
}

// TestTheRecordDoesNotGrowUnderSessionChurn is the direct assertion the risk
// register asks for: the map's bound moved from a rebuild to a comparison, so
// anything wrongly judged newer leaks until the process ends.
func TestTheRecordDoesNotGrowUnderSessionChurn(t *testing.T) {
	f := newEnablerFixture(t)
	f.activate(t, "W1", ueAddr("10.250.0.9"))

	for seid := uint64(1); seid <= 200; seid++ {
		// Alternating between traffic the task covers and traffic it does not, so the
		// churn exercises both the entries that are carried over and those that are not.
		ue := "10.250.0.9"
		if seid%2 == 0 {
			ue = "10.250.0.10"
		}
		f.putSession(t, unmarkedSession(seid, ue))
		if seid > 1 {
			if err := f.store.DeleteSession(seid - 1); err != nil {
				t.Fatalf("DeleteSession: %v", err)
			}
		}
	}
	if err := f.store.DeleteSession(200); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	f.e.retaskAndWait()
	f.settle(t)

	f.e.mu.Lock()
	size := len(f.e.programmed)
	f.e.mu.Unlock()

	// No sessions are left, so nothing should be recorded about any.
	if size != 0 {
		t.Errorf("the record holds %d entries with no sessions left; entries are being carried over that should have dropped", size)
	}
}

// TestAnEstablishmentDuringARederivationTerminates: the request the session path
// makes is a feedback edge — a pass can cause a pass — so it is worth pinning that
// it stops. The second pass sees the session, so it records nothing new and asks
// for nothing.
func TestAnEstablishmentDuringARederivationTerminates(t *testing.T) {
	f := newEnablerFixture(t)
	w := f.windowed(t)

	f.activate(t, "W1", ueAddr("10.250.0.9"))
	before := f.e.transactions()

	w.hold <- struct{}{}
	gen := f.e.request()
	<-w.read

	sess := unmarkedSession(100, "10.250.0.9")
	f.derive(&sess)
	f.commit(t, sess)

	w.release <- struct{}{}
	f.e.await(gen)
	f.settle(t)

	// The pass the test asked for, and the one the establishment asked for. A third
	// would mean the follow-up is asking for its own follow-up.
	if got := f.e.transactions() - before; got != 2 {
		t.Errorf("one establishment during a re-derivation performed %d further re-derivations, want 2", got)
	}
}

// TestAnUntaskedElementNeverAsksForARederivation is what makes the request
// affordable. An element holding no tasking is the state it is in almost all of
// the time, and there a session establishment must cost nothing beyond itself:
// the alternative is a walk of every session behind every attach.
func TestAnUntaskedElementNeverAsksForARederivation(t *testing.T) {
	f := newEnablerFixture(t)
	before := f.e.transactions()

	for seid := uint64(1); seid <= 50; seid++ {
		f.putSession(t, unmarkedSession(seid, "10.250.0.9"))
		if err := f.store.DeleteSession(seid); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
	}
	f.settle(t)

	if got := f.e.transactions() - before; got != 0 {
		t.Errorf("session churn on an untasked element performed %d re-derivations, want none", got)
	}
}

// TestConcurrentRequestsAreCoalesced pins the semantics that make one worker
// correct rather than merely serial. A re-derivation is a full evaluation from
// current tasking, so N pending requests and one imply the same work — and what
// must hold is that the state programmed is the one the last of them implies.
func TestConcurrentRequestsAreCoalesced(t *testing.T) {
	held := &heldSource{
		SessionsStore: NewInMemoryStore(),
		entered:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	e := newCCEnabler(store.New(), func(_, _ PacketForwardingRules) {})
	t.Cleanup(e.stop)
	e.addSource(held)

	e.retask()
	<-held.entered // one pass is now inside the transaction

	const burst = 32
	for range burst {
		e.retask()
	}

	held.release <- struct{}{} // the first pass finishes
	<-held.entered             // and one more answers for the whole burst
	held.release <- struct{}{}

	e.await(burst + 1)
	if got := e.transactions(); got != 2 {
		t.Errorf("%d requests during one pass performed %d transactions in all, want 2",
			burst, got)
	}
}

// TestEnablerStopEndsTheWorker: the worker belongs to the element, so it must not
// outlive it, and a caller waiting on a re-derivation must not be left blocked on
// one that will never happen.
func TestEnablerStopEndsTheWorker(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.activate(t, "W1", ueAddr("10.250.0.9"))

	f.e.stop()
	f.e.stop() // idempotent: the fixture's cleanup calls it again

	// A request after shutdown is not performed and does not block the caller.
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.e.retaskAndWait()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a re-derivation requested after shutdown never returned")
	}
}

// TestStopLetsATransactionInFlightFinish covers the half of shutdown that matters:
// a pass already programming the datapath is allowed to complete, rather than being
// abandoned half-applied — and shutdown does not hang waiting for it.
//
// Asserted because stop waits on the worker, so a transaction that could not finish
// would wedge the shutdown, and the idle-worker case says nothing about that.
func TestStopLetsATransactionInFlightFinish(t *testing.T) {
	held := &heldSource{
		SessionsStore: NewInMemoryStore(),
		entered:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	e := newCCEnabler(store.New(), func(_, _ PacketForwardingRules) {})
	e.addSource(held)

	e.retask()
	<-held.entered // a pass is now inside the transaction

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		e.stop()
	}()

	// Nothing else can release it, so if stop returned before this the pass was
	// abandoned rather than completed.
	held.release <- struct{}{}

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown never returned; a transaction in flight wedged it")
	}

	if got := e.transactions(); got != 1 {
		t.Errorf("performed %d transactions, want the one in flight to have completed", got)
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

	task, _, covering, ok := lookupTrigger(f.tasks, f.e, 100)
	if !ok {
		t.Fatal("a copy from the tasked session was not attributed to its warrant")
	}
	if task.XID != "W1" || covering != 1 {
		t.Errorf("attributed to %q (%d covering), want W1 (1)", task.XID, covering)
	}

	// The other subscriber's session is not covered, and a copy from it must stay
	// unattributed rather than be labelled with someone else's warrant.
	if _, _, _, ok := lookupTrigger(f.tasks, f.e, 200); ok {
		t.Error("a copy from an untasked session was attributed to a warrant")
	}
	// Nor may a session this element has never heard of resolve to anything.
	if _, _, _, ok := lookupTrigger(f.tasks, f.e, 999); ok {
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

	first, _, covering, ok := lookupTrigger(f.tasks, f.e, 100)
	if !ok {
		t.Fatal("no task found")
	}
	if covering != 2 {
		t.Errorf("covering = %d, want both warrants counted so the overlap is reported", covering)
	}
	for range 20 {
		task, _, _, _ := lookupTrigger(f.tasks, f.e, 100)
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

	if _, _, covering, _ := lookupTrigger(f.tasks, f.e, 100); covering != 1 {
		t.Errorf("covering = %d for a session under one warrant, want 1", covering)
	}
}

// TestModifyTaskChangesCriteriaInPlace covers table 6.2.3-8's allowance for a
// ModifyTask to replace a task's detection criteria. The interception must follow
// the new criteria without being torn down and rebuilt: traffic the superseded
// criteria selected stops, traffic only the new ones select starts, and the product
// stays attributed to the same warrant throughout — a mediation function selects by
// warrant identifier, so a change of attribution across a modify would split the
// product in two.
func TestModifyTaskChangesCriteriaInPlace(t *testing.T) {
	f := newEnablerFixture(t)
	// Both directions through one FAR, so direction filtering is doing real work: the
	// copies the criteria do not select still arrive and have to be dropped.
	f.putSession(t, sharedFARSession())

	inbound := types.TargetIdentifier{Type: types.TargetGTPTunnelDirection, Value: x1.GTPDirectionInbound}
	outbound := types.TargetIdentifier{Type: types.TargetGTPTunnelDirection, Value: x1.GTPDirectionOutbound}

	task := types.InterceptTask{
		XID: "trigger-1", ProductID: "warrant-1", CorrelationID: 7,
		Targets:  []types.TargetIdentifier{inbound},
		Products: []types.ProductType{types.ProductCC},
	}
	if err := f.e.canApply(task); err != nil {
		t.Fatalf("canApply: %v", err)
	}
	f.tasks.Activate(task)
	f.e.retaskAndWait()

	_, filter, _, ok := lookupTrigger(f.tasks, f.e, 100)
	if !ok {
		t.Fatal("the task does not cover the session")
	}
	if !filter.matches(farForwardUAndDuplicate, uplinkCopy(443)) {
		t.Error("uplink content is not delivered for an inbound criterion")
	}
	if filter.matches(farForwardDAndDuplicate, downlinkCopy(443)) {
		t.Error("downlink content is delivered for an inbound criterion")
	}
	if !f.duplicates(t, 100, 9) {
		t.Fatal("duplication was not enabled")
	}

	// The ModifyTask: same XID, different criteria. This is what x1 does with a
	// retarget — the task is replaced in place, never deactivated.
	task.Targets = []types.TargetIdentifier{outbound}
	if err := f.e.canApply(task); err != nil {
		t.Fatalf("canApply after modify: %v", err)
	}
	f.tasks.Activate(task)
	f.e.retaskAndWait()

	got, filter, _, ok := lookupTrigger(f.tasks, f.e, 100)
	if !ok {
		t.Fatal("the modified task no longer covers the session")
	}
	if filter.matches(farForwardUAndDuplicate, uplinkCopy(443)) {
		t.Error("content the superseded criteria selected is still delivered")
	}
	if !filter.matches(farForwardDAndDuplicate, downlinkCopy(443)) {
		t.Error("content the new criteria select is not delivered")
	}
	// Still duplicating: the modify narrowed which copies are delivered, not whether
	// the traffic is copied at all.
	if !f.duplicates(t, 100, 9) {
		t.Error("the modify withdrew duplication the task still needs")
	}
	// And the labels a mediation function joins on are unchanged.
	if got.DeliveryXID() != "warrant-1" || got.CorrelationID != 7 {
		t.Errorf("attribution changed across the modify: XID %q, correlation %d",
			got.DeliveryXID(), got.CorrelationID)
	}
}

// TestModifyToACriterionSelectingNothingStopsContent checks the other end of a
// modify: criteria that no longer select anything in the session must stop the
// content, not leave the previous enablement running. Continuing would deliver
// traffic under a warrant whose criteria no longer describe it.
func TestModifyToACriterionSelectingNothingStopsContent(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.activate(t, "W1", ueAddr("10.250.0.9"))
	if !f.duplicates(t, 100, 1) {
		t.Fatal("duplication was not enabled")
	}

	// Retargeted at a subscriber that is not here.
	f.activate(t, "W1", ueAddr("10.250.0.99"))

	if f.duplicates(t, 100, 1) || f.duplicates(t, 100, 2) {
		t.Error("duplication continued for criteria the task no longer carries")
	}
	if _, _, _, ok := lookupTrigger(f.tasks, f.e, 100); ok {
		t.Error("copies of the session are still attributed to the retargeted warrant")
	}
}

// removeSession is the teardown half of the fixture: the session leaves the store
// and the element is told, exactly as PFCPConn.RemoveSession does it.
func (f *enablerFixture) removeSession(t *testing.T, s PFCPSession) {
	t.Helper()
	if err := f.store.DeleteSession(s.localSEID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	f.e.sessionForgotten(&s)
}

// TestUntaskedChurnDoesNotAccumulate is the leak itself, in the shape that
// produces it: LI configured, tasking that does not change, and ordinary
// subscribers attaching and detaching.
//
// Every session writes an entry per FAR, but a pass over the sessions — which is
// the only thing that used to shrink the record — is requested only when a FAR is
// duplicating or has just stopped. For a session no task covers that is never, so
// nothing ever asked, and nothing was ever reclaimed. Note there is no tasking
// change anywhere in this test: adding one would hide the defect by triggering
// the very pass whose absence is the point.
func TestUntaskedChurnDoesNotAccumulate(t *testing.T) {
	f := newEnablerFixture(t)

	// A warrant exists and is stable — the element is doing its job throughout.
	f.activate(t, "warrant-1", ueAddr("10.45.0.99"))

	for i := range 200 {
		s := unmarkedSession(uint64(0x1000+i), "10.45.0.2")
		f.putSession(t, s)
		f.removeSession(t, s)
	}
	f.settle(t)

	f.e.mu.Lock()
	held := len(f.e.programmed)
	f.e.mu.Unlock()

	if held != 0 {
		t.Errorf("the element holds %d programmed-FAR entries after 200 untasked sessions "+
			"came and went, want 0 — nothing reclaims them, and a long-running UPF "+
			"accumulates one per FAR per subscriber that has ever attached", held)
	}
}

// TestReleasedSessionRecordIsReclaimed covers both halves of what teardown must
// drop: a session the tasking covered and one it did not. The duplicating one
// matters because its entries are the ones that exist for a reason, so an
// implementation that only prunes what it considers uninteresting keeps them.
func TestReleasedSessionRecordIsReclaimed(t *testing.T) {
	f := newEnablerFixture(t)
	f.activate(t, "warrant-1", ueAddr("10.45.0.7"))

	tasked := unmarkedSession(0x2000, "10.45.0.7")   // the warrant covers this one
	untasked := unmarkedSession(0x2001, "10.45.0.8") // and not this one
	f.putSession(t, tasked)
	f.putSession(t, untasked)
	f.settle(t)

	if dup, held := f.recorded(0x2000, 1); !held || !dup {
		t.Fatalf("test setup: the tasked session's FAR should be recorded as duplicating, got (%v, %v)", dup, held)
	}

	f.removeSession(t, tasked)
	f.removeSession(t, untasked)

	for _, seid := range []uint64{0x2000, 0x2001} {
		for _, farID := range []uint32{1, 2} {
			if _, held := f.recorded(seid, farID); held {
				t.Errorf("session %#x FAR %d is still recorded after release", seid, farID)
			}
		}
	}
}

// TestForgettingASessionLeavesTheCarryOverIntact: the record is not only a size
// problem, it is what stops a re-derivation drawing on older information from
// discarding what a newer one programmed. Pruning must not weaken that. A session
// established while a pass is in flight still ends up recorded, whether or not an
// unrelated session was torn down in the meantime.
func TestForgettingASessionLeavesTheCarryOverIntact(t *testing.T) {
	f := newEnablerFixture(t)
	w := f.windowed(t)

	live := unmarkedSession(0x3000, "10.45.0.7")
	f.putSession(t, live)
	f.settle(t)

	doomed := unmarkedSession(0x3001, "10.45.0.8")
	f.putSession(t, doomed)
	f.settle(t)

	// Hold a pass after it has read the sessions, so its conclusion is drawn from a
	// view that predates everything below.
	w.hold <- struct{}{}
	f.e.retask()
	<-w.read

	// A session is torn down and another established, both while the pass is held.
	f.removeSession(t, doomed)
	fresh := unmarkedSession(0x3002, "10.45.0.9")
	f.putSession(t, fresh)

	w.release <- struct{}{}
	f.settle(t)

	// The session established under the stale pass keeps its record: the carry-over
	// is what makes duplication for it stoppable later.
	for _, farID := range []uint32{1, 2} {
		if _, held := f.recorded(0x3002, farID); !held {
			t.Errorf("the session established while a pass was in flight lost FAR %d's "+
				"record — a later re-derivation would read the absence as "+
				"'nothing to do' and leave duplication running", farID)
		}
	}
	// The torn-down one is re-added by that pass, which drew its conclusion before
	// the teardown: the publish at the end of a pass adds, and a deletion is not
	// something it can represent. That residue is bounded rather than a return of
	// the leak, and the boundary is worth stating precisely, because it is the
	// difference between the two. A pass is running, so tasking is changing or a
	// tasked session is coming or going; the next pass rebuilds the record from the
	// live sessions and the residue goes. Under the condition that produced the
	// leak — stable tasking, untasked churn — no pass runs at all, so no teardown
	// can land inside one and nothing accumulates in the first place.
	if _, held := f.recorded(0x3001, 1); !held {
		t.Log("a session torn down mid-pass left no residue; the assertion below is then trivially true")
	}
	f.e.retaskAndWait()
	if _, held := f.recorded(0x3001, 1); held {
		t.Error("a session torn down while a pass was in flight is still recorded after a " +
			"further re-derivation — the residue is not being reclaimed, which would " +
			"make it a slower form of the same leak")
	}
}
