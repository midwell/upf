// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	"github.com/wmnsk/go-pfcp/ie"
)

// A triggered CC-POI cannot rely on the SMF having marked the traffic it is told to
// intercept. Only one of the detection criteria of TS 33.128 table 6.2.3-7 — the
// PFCP Session ID — is something our own CC Triggering Function derives from a
// session it has already marked; a criterion naming an address, a tunnel or a
// network instance may well identify traffic nothing has asked to be duplicated.
//
// Acknowledging such a task and producing nothing is the failure this file exists
// to prevent: the triggering function has been told the interception is running and
// has no way to discover that it is not. So the CC-POI enables duplication itself,
// on the FARs the criteria resolve to.
//
// Duplication is an apply-action on a FAR, and several PDRs may forward through
// one, so enabling it can copy more traffic than the criteria identify. That is
// accepted here and corrected downstream by filtering: the alternative — cloning a
// FAR and repointing a PDR at it — mutates the subscriber's own forwarding, which
// is the area two visible-to-the-target defects came from.
//
// The tasking is the single source of truth. Nothing here remembers which FARs it
// enabled: every point that could change the answer re-derives it from the live
// tasks and the session's current rules. A remembered set would be one more thing
// to drift out of step with reality, and its drifting would be silent.

// ccEnabler enables duplication for LI_T3 tasking on the FARs a task's detection
// criteria select, and keeps it enabled across the SMF's own session
// modifications.
type ccEnabler struct {
	tasks *store.Store

	// parsed is the live tasking with every task's detection criteria already parsed,
	// as an immutable snapshot behind an atomic pointer.
	//
	// The shipping path reads it per duplicated copy, on four workers. Parsing there
	// meant a strconv or a hex decode per criterion per copy — and for a PDR criterion
	// an IE parse and a throwaway address pool per copy — on the one path in this
	// element whose cost is per packet, in front of a socket queue that holds ten
	// datagrams by default and whose overflow is intercept product. A snapshot swapped
	// on tasking changes costs the hot path one atomic load.
	parsed atomic.Pointer[[]parsedTask]

	// epoch changes when the tasking changes, and stamps the memo below. A memo entry
	// from an older epoch is recomputed rather than trusted, so the memo cannot answer
	// from tasking that has been withdrawn — and a writer that forgot to bump this
	// would invalidate nothing rather than invalidate one thing wrongly, which is the
	// failure direction an index maintained incrementally does not have.
	epoch atomic.Uint64

	// coveredMu guards covered, which memoises the per-session attribution answer.
	// Separate from mu because it is taken per copy and mu is held across walks of
	// every session this element holds.
	coveredMu sync.Mutex
	covered   map[uint64]coveredEntry

	mu sync.Mutex
	// sources are the per-association session stores. A task's criteria are
	// resolved against every session this element holds, since most criteria do not
	// name one.
	sources []SessionsStore
	// programmed records which FARs this element has told the datapath to duplicate.
	// It is not the authority on what *should* be duplicated — that is recomputed
	// from the live tasking every time — only a record of what the datapath was last
	// told, so that a re-derivation producing the same answer does not reprogram it.
	//
	// It is nonetheless load-bearing in one direction: a re-derivation skips a FAR
	// whose recorded value already equals what the tasking implies, so a *missing*
	// entry is an instruction to do nothing — and doing nothing is wrong exactly
	// when the datapath is duplicating and the tasking says it should not be.
	programmed map[farRef]programmedFAR
	// writes counts writes to programmed, and is what lets a re-derivation tell an
	// entry the session path wrote while it ran from one it read itself.
	//
	// Deliberately not requested/served/completed. Those count *requests for a
	// re-derivation*; this counts *writes to the record*. A pass serving generation
	// G would see its own G on entries written during it and discard them anyway,
	// so conflating the two silently defeats the carry-over below.
	writes uint64
	// forgotten records, per session, the write stamp at which this element learned the
	// session was gone. It is what lets a pass planned from an older view be told that the
	// session it planned for no longer exists: the pass's own map still holds the entries
	// it built, and without this the carry-over could not see the deletion — so
	// `e.programmed = fresh` put them back and the pass's push could re-add the FAR to the
	// datapath after the delete.
	//
	// Entries are dropped by the pass that acts on them, so this is bounded by the
	// deletions a single pass can miss rather than by uptime.
	forgotten map[uint64]uint64
	// everDuplicated is every FAR this element has ever told the datapath to duplicate, and it
	// is never cleared while the process lives.
	//
	// **It exists because `programmed` is the only memory of what the datapath holds, and a
	// record that is wrong in the "not duplicating" direction is unrecoverable.** The
	// re-derivation skips any FAR whose recorded value already equals what the tasking implies,
	// so once the record says "off" while the datapath is duplicating, no later pass mentions
	// that FAR again: the element computes "nothing should duplicate", sees its record agreeing,
	// and does nothing while a subscriber's traffic goes on being copied. Nothing on either side
	// can see it — the element's own account says duplication is off, and the copies are dropped
	// as unattributable rather than delivered, so no agency sees them either.
	//
	// That state was reached on a live deployment. What produced it is *not* established: it did
	// not reproduce in seven consecutive runs of the section that exposed it against a freshly
	// started pod, and this set is deliberately not a fix for any particular path. It is a fix
	// for the *permanence*, which is the part that makes the harm unbounded — with it, the
	// element tells the datapath "off" for every FAR it has ever turned on, whatever it believes,
	// so a divergence lasts until the next re-derivation instead of until the pod restarts.
	//
	// **Monotone on purpose.** The bug class is an entry being wrongly overwritten to false, and
	// a set that only grows has no such path. It is not pruned when a session goes away either,
	// because a later session can be allocated the same SEID and inherit a stale datapath rule —
	// which is the most plausible route to the state observed. It costs one map entry per FAR
	// ever intercepted, which for lawful interception is a handful.
	everDuplicated map[farRef]bool
	// forgottenFARs is the same record one level down: the write stamp at which a session
	// *modification* removed one FAR while the session itself carried on.
	//
	// A separate map because the two cannot be expressed as one. `forgotten` answers "is
	// anything about this SEID stale", which a pass uses to discard its whole conclusion for
	// that session — right when the session is gone, and wrong here: this pass may already
	// have pushed duplication for the session's *other* FARs, and discarding the record of
	// that push would leave the datapath duplicating with nothing able to turn it off. So a
	// removed FAR invalidates that FAR and nothing else.
	//
	// It is needed at all because a deletion is invisible to the carry-over, exactly as the
	// session-level case documents: without it the pass's own `fresh` map still holds the
	// entry it planned from the pre-modification FAR list, `e.programmed = fresh` puts it
	// back, and the record then claims duplication for a FAR the SMF has removed. The next
	// pass would compare against that claim and conclude there was nothing to do — and if
	// the session later re-creates a FAR with the same identifier, which a path switch
	// does routinely, the claim says duplication is already in place and the freshly created
	// FAR is never programmed. Interception silently stops for that traffic while this
	// element's own account says it is running.
	//
	// Bounded like the map above: entries are dropped by the pass that acts on them.
	forgottenFARs map[farRef]uint64
	// push writes changed rules to the datapath and answers with the datapath's
	// cause. Separate field so a test can observe what would be programmed without a
	// datapath.
	//
	// **The answer is the point.** This record exists so the element knows what to
	// change, and a re-derivation programs only the difference between what the
	// tasking implies and what the record says is in place. Recording a refused
	// program as done therefore does not lose one attempt — it removes the rule from
	// every subsequent difference, so nothing ever retries it. Duplication for that
	// traffic never happens, this element's own account says it is happening, and the
	// only event that could correct the record is a change in tasking.
	push func(all, updated PacketForwardingRules) uint8
	// report surfaces an LI-plane fault to the ADMF. nil when no ADMF is configured.
	report func(issueType, description string)

	// The three counters that make a re-derivation atomic with respect to another,
	// and let a caller find out when the one it asked for has happened. requested is
	// bumped by every request; served is the request the running transaction is
	// answering for; completed is the last one that finished. A request is coalesced
	// rather than queued — a transaction is a full re-derivation from current
	// tasking, so N pending requests and one imply the same work, and what must hold
	// is that the state programmed is the state the last of them implies.
	requested uint64
	served    uint64
	completed uint64
	// passes counts the transactions actually performed, so "N requests are the same
	// work as one" is assertable rather than asserted.
	passes uint64
	// closing stops the worker taking new work and releases anyone waiting on a
	// generation that will now never arrive.
	closing bool
	// pending wakes the worker when a request arrives; settled wakes callers when a
	// transaction finishes. Both guarded by mu.
	pending *sync.Cond
	settled *sync.Cond
	worker  sync.WaitGroup
}

// parsedTask is one content task with its criteria in the form the agent compares
// against PFCP state. Parsed when the tasking changes rather than when a copy
// arrives; a task whose criteria do not parse contributes none, which canApply
// already refused at tasking time.
type parsedTask struct {
	task     types.InterceptTask
	criteria []criterion
}

// coveredEntry is the attribution answer for one session, stamped with the tasking
// epoch it was computed under.
type coveredEntry struct {
	epoch uint64
	tasks []coveredTask
}

// programmedFAR is what this element last told the datapath about one FAR, and
// when it said so.
type programmedFAR struct {
	duplicating bool
	// written is the value of writes at the moment the entry was recorded.
	written uint64
}

func newCCEnabler(
	tasks *store.Store,
	push func(all, updated PacketForwardingRules) uint8,
	report func(issueType, description string),
) *ccEnabler {
	e := &ccEnabler{
		tasks:          tasks,
		everDuplicated: make(map[farRef]bool),
		push:           push,
		report:         report,
		programmed:     make(map[farRef]programmedFAR),
		forgotten:      make(map[uint64]uint64),
		forgottenFARs:  make(map[farRef]uint64),
		covered:        make(map[uint64]coveredEntry),
	}
	e.reparse()
	e.pending = sync.NewCond(&e.mu)
	e.settled = sync.NewCond(&e.mu)
	e.worker.Add(1)
	go e.run()

	return e
}

// run performs re-derivations, one at a time and never concurrently with another.
//
// A single worker is what makes the transaction atomic with respect to itself.
// Provisioning requests arrive concurrently, and when only the individual reads and
// writes were protected the pass that began earlier could program and publish last
// — clearing duplication for a task that is still active, with nothing re-deriving
// until some unrelated event happened to trigger another pass. That loss is silent
// by nature: a dropped copy produces no record for any downstream function to miss,
// so it could persist for the life of the warrant.
//
// The alternative was a mutex around the transaction, which is simpler and wrong
// here: the transaction walks every session of every source, so an X1 request's
// latency would become a function of session count on the element holding the most
// sessions.
func (e *ccEnabler) run() {
	defer e.worker.Done()

	for {
		e.mu.Lock()
		for e.requested == e.served && !e.closing {
			e.pending.Wait()
		}
		if e.closing {
			e.mu.Unlock()

			return
		}
		// Taken before the transaction reads the tasking, so completed can only
		// understate which requests this pass answered for. A caller waiting on a
		// later generation then waits for the next pass, which is the safe direction:
		// the unsafe one is reporting that tasking has been programmed when it has not.
		gen := e.requested
		e.served = gen
		e.mu.Unlock()

		e.transact()

		e.mu.Lock()
		e.completed = gen
		e.passes++
		e.mu.Unlock()
		e.settled.Broadcast()
	}
}

// transactions is how many re-derivations have been performed.
func (e *ccEnabler) transactions() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.passes
}

// stop ends the worker. A transaction already in flight finishes — leaving the
// datapath half-programmed would be worse than waiting for one bounded pass — and
// nothing new starts. Callers waiting on a generation are released rather than left
// blocked on one that will never arrive. Safe to call more than once.
func (e *ccEnabler) stop() {
	if e == nil {
		return
	}

	e.mu.Lock()
	e.closing = true
	e.mu.Unlock()
	e.pending.Broadcast()
	e.settled.Broadcast()

	e.worker.Wait()
}

// request registers a re-derivation and returns the generation it was given.
func (e *ccEnabler) request() uint64 {
	e.mu.Lock()
	e.requested++
	gen := e.requested
	e.mu.Unlock()
	e.pending.Signal()

	return gen
}

// await blocks until a transaction that answers for gen has finished.
func (e *ccEnabler) await(gen uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for e.completed < gen && !e.closing {
		e.settled.Wait()
	}
}

// addSource registers an association's session store, so tasking already held
// applies to its sessions and tasking that arrives later can find them.
func (e *ccEnabler) addSource(s SessionsStore) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sources = append(e.sources, s)
}

// removeSource forgets an association's session store when it goes away. Its
// sessions are gone with it, so no duplication needs undoing — but keeping the
// store would have this resolve criteria against sessions the datapath no longer
// has.
func (e *ccEnabler) removeSource(s SessionsStore) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, have := range e.sources {
		if have == s {
			e.sources = append(e.sources[:i], e.sources[i+1:]...)

			break
		}
	}
}

// canApply reports whether this CC-POI can carry out a task, and is what refuses
// one it cannot. It answers on two things: the task must require the product this
// point of interception makes, and every detection criterion must be something the
// agent can resolve against PFCP state.
//
// It deliberately does *not* require that the criteria select something now. A
// criterion may name a subscriber who has not attached yet, and refusing that
// would make tasking depend on the order in which the triggering function and the
// UE happen to act.
func (e *ccEnabler) canApply(task types.InterceptTask) error {
	if e == nil {
		// No datapath to resolve against, which happens only in a test that builds a
		// shipper directly. Answering "yes" keeps that path as it was.
		return nil
	}
	if !producesCC(task) {
		// Accepting it would cost in both directions: the triggering function is told an
		// interception is running that will deliver nothing, and the datapath duplicates
		// a subject's traffic so that every copy can be discarded for want of an X3
		// destination. Duplicating a subject's traffic is the act interception authority
		// licenses, and doing it for a task that did not ask for content is doing it
		// without that authority even though nothing leaves the element.
		return fmt.Errorf("li: task does not require content of communication, which is the only product this point of interception produces")
	}
	if len(task.Targets) == 0 {
		return fmt.Errorf("li: task carries no detection criteria")
	}
	for _, id := range task.Targets {
		if _, err := parseCriterion(id); err != nil {
			return err
		}
	}

	return nil
}

// producesCC reports whether a task asks for the product this point of interception
// makes. Every place that reads tasking to decide what the datapath does asks this
// first, so a task admitted before canApply checked it cannot still cause
// duplication, and cannot take attribution of a copy away from a task that can
// actually be delivered for.
func producesCC(t types.InterceptTask) bool {
	return t.WantsProduct(types.ProductCC)
}

// criteriaOf returns the parsed criteria of every active task that requires content,
// dropping any that no longer parse. canApply refused both of those at tasking time,
// so a leftover can only come from a task installed before those checks existed.
func (e *ccEnabler) criteriaOf(tasks []types.InterceptTask) []criterion {
	var out []criterion
	for _, t := range tasks {
		if !producesCC(t) {
			continue
		}
		for _, id := range t.Targets {
			if c, err := parseCriterion(id); err == nil {
				out = append(out, c)
			}
		}
	}

	return out
}

// setTasks gives the enabler the task store and parses what it holds.
//
// Assigning the field alone would leave the parsed snapshot empty until the first
// tasking change, and until then every copy would fall through to the store lookup
// that only the session-identity criterion can answer — an interception narrower
// than the one accepted, for as long as nothing happened to change the tasking.
func (e *ccEnabler) setTasks(tasks *store.Store) {
	if e == nil {
		return
	}

	e.tasks = tasks
	e.reparse()
}

// reparse rebuilds the parsed snapshot from the live tasking and moves the epoch on.
//
// The epoch moves *after* the snapshot is published, so a memo entry stamped with the
// new epoch cannot have been computed from the old snapshot. The other order would
// let a copy arriving in between be memoised under the new stamp from the old
// tasking, and nothing would recompute it.
func (e *ccEnabler) reparse() {
	if e == nil || e.tasks == nil {
		return
	}

	tasks := e.tasks.Snapshot()
	fresh := make([]parsedTask, 0, len(tasks))

	for _, t := range tasks {
		if !producesCC(t) {
			// A task that does not require content must not take attribution of a copy
			// away from one that does — the caller takes the first covering task, and a
			// task with no X3 destination would swallow the whole stream of the warrant
			// that has one.
			continue
		}

		criteria := make([]criterion, 0, len(t.Targets))
		for _, id := range t.Targets {
			if c, err := parseCriterion(id); err == nil {
				criteria = append(criteria, c)
			}
		}
		if len(criteria) == 0 {
			continue
		}
		fresh = append(fresh, parsedTask{task: t, criteria: criteria})
	}

	e.parsed.Store(&fresh)
	e.epoch.Add(1)
}

// forgetCovered drops the memoised attribution answer for one session.
//
// Called where a session's own rules change or the session goes away, which is
// precise: those events affect that session's answer and no other's. A change in
// *tasking* affects every session's, and moves the epoch instead.
func (e *ccEnabler) forgetCovered(seid uint64) {
	if e == nil {
		return
	}

	e.coveredMu.Lock()
	defer e.coveredMu.Unlock()
	delete(e.covered, seid)
}

// applyTasking sets duplication on every FAR of the session whose traffic live
// tasking selects, and clears the duplication this element enabled on the rest.
//
// Both halves matter. Setting is what makes an accepted task intercept, including
// after an SMF modification has replaced the FAR with its own view of it. Clearing
// is what makes a withdrawn task stop — and clearing only liDuplicate is what
// keeps it from stopping duplication the SMF itself asked for.
//
// updated, when non-nil, is the subset of rules the caller is about to push to the
// datapath; FARs in it are changed alongside the session's own copies, because the
// datapath acts on what it is pushed and PacketForwardingRules holds values rather
// than pointers.
//
// It deliberately does not record what it derived. The caller does that, through
// sessionProgrammed, once the session is in the store — see there for why the
// ordering is the whole of this file's coherence.
func (e *ccEnabler) applyTasking(s *PFCPSession, updated *PacketForwardingRules) {
	if e == nil || s == nil {
		return
	}

	criteria := e.criteriaOf(e.tasks.Snapshot())

	// One session, so the resolver is given just this one: a criterion selecting
	// another session's traffic is that session's business.
	one := []PFCPSession{*s}
	want := make(map[uint32]bool, len(s.fars))
	for _, c := range criteria {
		for _, ref := range c.resolve(one) {
			want[ref.farID] = true
		}
	}

	for i := range s.fars {
		s.fars[i].liDuplicate = want[s.fars[i].farID]
	}
	if updated != nil {
		for i := range updated.fars {
			updated.fars[i].liDuplicate = want[updated.fars[i].farID]
		}
	}
}

// sessionProgrammed records what the datapath was told about a session's FARs, and
// asks for a re-derivation where what it was told is something the element must be
// able to withdraw.
//
// **It must be called after the session is in the store, and that ordering is the
// whole point.** Recording inside applyTasking — before the push and before the
// store — leaves an interval in which the record says a session's traffic is being
// duplicated and GetAllSessions does not yet return it. A re-derivation beginning
// in that interval reads one structure and writes the other, and no stamp can save
// it: the write it would have to be newer than has already happened. Recording once
// the session is visible is what makes "written after this pass began looking" imply
// "this pass cannot have seen the session", which is what transact's carry-over
// relies on.
//
// The same ordering is why transact no longer sees a value the session path wrote
// mid-flight. It used to, and the consequence was the sharper half of the defect
// this closes: the pass compared its own stale conclusion against the newer record,
// found a difference, and pushed the FAR *off* — ending an interception the tasking
// still required, with nothing logged and the triggering function still believing it
// was running.
//
// The re-derivation is asked for here rather than by the pass that lost the race,
// because here is the only place ordered after PutSession. It is gated so that an
// element holding no tasking never asks for one: every FAR reads false, nothing
// changed, and the walk of every session that a request implies does not happen.
//
// **pushed is the rules the caller actually sent to the datapath, and it is an argument
// because the caller is the only party that knows.** This used to walk the session's whole FAR
// list, which is right for an establishment — everything the session has was just pushed — and
// wrong for a modification, which pushes only the rules the SMF restated. For every other FAR
// in that session the record was then rewritten from what this element *intends*, not from what
// the datapath was last told, and the two are only the same when nothing has gone wrong.
//
// The direction of the error is what makes it worth a signature change. A FAR the datapath
// refused, or one whose push was lost, is duplicating what it was duplicating before — and the
// record would now claim the tasking's intended value for it. Where the intent is "not
// duplicating", the next pass compares the record against the tasking, finds them equal, and
// concludes there is nothing to do: copies keep being made for a session no warrant covers,
// nothing in the element can turn them off, and the element's own account says duplication is
// off. That is over-collection recorded as compliance. farsPushed exists for a neighbouring
// case and already documents this as the one direction the record must never be wrong in; it is
// now the same rule here, made unstateable rather than remembered.
//
// **The request for a pass still considers the whole session**, and that is not an oversight in
// the other direction. What the record answers is "what does the datapath hold"; what the
// request answers is "might the right answer have changed here". A modification that restates
// one FAR can change what a criterion matches for the session's others — a UE address moves, a
// PDR is replaced — so a pass is wanted whenever the session's FARs and the record disagree,
// including for FARs this call did not push.
func (e *ccEnabler) sessionProgrammed(s *PFCPSession, pushed []far) {
	if e == nil || s == nil {
		return
	}

	e.mu.Lock()
	e.writes++
	stamp := e.writes
	for i := range pushed {
		ref := farRef{seid: s.localSEID, farID: pushed[i].farID}
		e.programmed[ref] = programmedFAR{duplicating: pushed[i].liDuplicate, written: stamp}
		if pushed[i].liDuplicate {
			e.everDuplicated[ref] = true
		}
	}
	// Duplicating, because a copy running under tasking that may since have been
	// withdrawn is the thing that must be re-derived. Changed, because a
	// modification that took a session *out* of scope has to survive a pass holding
	// the older view just as much.
	//
	// Over the session rather than over pushed, per the note above: a FAR nobody pushed can
	// still be one whose answer this modification changed.
	// **And a FAR this element has ever turned on is notable whatever the record says**, for the
	// same reason the pass no longer trusts the record in the "off" direction: in the diverged
	// state both the record and the session's own flag read false, so neither of the two tests
	// above fires, no pass is requested, and the remedy in transact never gets the chance to
	// run. Distrusting the record when deciding what to *do* and trusting it when deciding
	// whether to *look* would leave the fix half-wired — it would work only when some other
	// event happened to ask for a pass.
	//
	// Bounded by the same small set: one pass request per session event touching a FAR that has
	// ever been intercepted, which is what a re-derivation is cheap enough for.
	notable := false
	for i := range s.fars {
		ref := farRef{seid: s.localSEID, farID: s.fars[i].farID}
		if s.fars[i].liDuplicate || e.programmed[ref].duplicating != s.fars[i].liDuplicate ||
			e.everDuplicated[ref] {
			notable = true

			break
		}
	}
	e.mu.Unlock()

	// This session's rules have changed, so an attribution answer computed from the
	// previous ones is wrong for it — and for it alone, which is why this is a delete
	// rather than a move of the epoch.
	e.forgetCovered(s.localSEID)

	if notable {
		e.request()
	}
}

// sessionForgotten drops what this element recorded about a session's FARs,
// because the session is gone and no re-derivation will ever mention it again.
//
// Without this the record only shrinks inside transact, which rebuilds it from
// the live sessions — and transact only runs when something asks for it. Nothing
// asks on the strength of an untasked session: sessionProgrammed requests a pass
// only when a FAR is duplicating or has stopped duplicating, which for a session
// no task covers is never. So an element with LI configured and its tasking
// stable — one long-lived warrant, or a target provisioned and not yet active,
// both ordinary — accumulates an entry per FAR per session for every subscriber
// that has ever attached, and reclaims none of it. The element keeps intercepting
// correctly the entire time, which is why nothing about it looks like a fault
// until the process dies and takes every warrant it holds with it.
//
// Keyed off the session's own FARs rather than scanning the record for a matching
// SEID: the same walk sessionProgrammed does to write them, so teardown costs
// what establishment did and not a pass over every session the element holds.
//
// The entries are only a record of what the datapath was last told. Dropping them
// for a session that no longer exists cannot lose an instruction, because there
// is nothing left to instruct.
//
// **It moves the write counter, and that is what makes the deletion visible to a pass
// already running.** A pass takes `mark` from `writes` at its start, rebuilds `fresh` from
// the sessions it walked, and at the end carries over any entry stamped past the mark. A
// deletion that did not move the counter was therefore invisible to the carry-over: the
// pass's own `fresh` map still held the entries it had planned from the session before it
// went, `e.programmed = fresh` put them back, and the push could re-add the FAR to the
// datapath *after* the delete — duplication reinstated on a session that has been torn
// down, recorded as programmed, with nothing left to turn it off.
func (e *ccEnabler) sessionForgotten(s *PFCPSession) {
	if e == nil || s == nil {
		return
	}

	e.forgetCovered(s.localSEID)

	e.mu.Lock()
	defer e.mu.Unlock()

	// The same stamp sessionProgrammed takes, for the same reason: a pass holding an older
	// view must lose to a writer that has seen the session's real state — and a deletion is
	// the most authoritative statement about a session there is.
	e.writes++
	e.forgotten[s.localSEID] = e.writes

	for i := range s.fars {
		delete(e.programmed, farRef{seid: s.localSEID, farID: s.fars[i].farID})
	}
}

// farsRemoved drops what this element recorded about FARs a session modification removed,
// while the session itself carried on.
//
// Nothing else reclaims them. sessionProgrammed walks the session's *remaining* FARs, so it
// never sees the one that went; sessionForgotten walks the same list at teardown, so the
// entry outlives the session that owned it; and transact rebuilds the record from live
// sessions, but only when something asks for a pass — and a removal that leaves nothing
// duplicating asks for none.
//
// So the record grows with every FAR any subscriber's session has ever had removed, and an
// element whose tasking is stable — one long-lived warrant, which is the ordinary case —
// reclaims none of it. That is the same leak sessionForgotten exists to prevent, reached
// through a different door, and it has the same shape: the element keeps intercepting
// correctly the whole time, so nothing looks like a fault until the process dies and takes
// every warrant it holds with it.
//
// **What the stale entry does not do is suppress a later interception**, and the distinction
// is worth stating because it is the first thing this looks like. Every path that creates a
// FAR pushes it to the datapath unconditionally — the record is consulted only to decide
// what a re-derivation needs to *change* — so a FAR re-created under the same identifier is
// programmed from the tasking either way. This is a leak, not a missed copy.
//
// It moves the write counter for the reason sessionForgotten documents: a deletion is
// invisible to transact's carry-over otherwise, and a pass planned from the pre-modification
// FAR list would put the entry straight back. That carry-over is not the only thing the
// stamp buys — a pass holding the older FAR list may be about to push the removed FAR, and
// the datapath's modify path programs what it is given, so it would re-create a rule the SMF
// has deleted.
func (e *ccEnabler) farsRemoved(seid uint64, removed []far) {
	if e == nil || len(removed) == 0 {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.writes++

	for i := range removed {
		ref := farRef{seid: seid, farID: removed[i].farID}
		delete(e.programmed, ref)
		e.forgottenFARs[ref] = e.writes
	}
}

// farsPushed records duplication the datapath has been told to apply, for FARs whose session
// may never reach the store.
//
// The modification handler pushes its created and updated rules to the datapath *before* it
// processes the removals, and a failure in that removal stage returns a rejection — before
// PutSession, and so before sessionProgrammed, which is the only thing that would have
// recorded the push. The datapath is left duplicating and this element holds no record of
// it. A later pass then computes the tasking's answer, finds no entry, reads that as "not
// duplicating", and where the tasking says it should not be duplicating either, concludes
// there is nothing to do. The copies keep being made for a session no warrant covers, which
// is over-collection, and nothing in the element can turn it off.
//
// Only the FARs that were actually pushed. Recording the session's whole FAR list here would
// claim the datapath holds what this element *wants* for FARs it never sent — and a claim of
// "not duplicating" against a FAR that is duplicating is the one direction the record must
// never be wrong in.
//
// That rule is general, and all three recorders now have the shape that enforces it rather than
// stating it: this one and farsRemoved take the rules they concern, and sessionProgrammed takes
// the pushed rules as an argument for the same reason. It used to walk the session, which was
// right for an establishment and wrong for every modification — so the argument this function
// has always had is what the other one was missing.
//
// It does not ask for a pass, deliberately. The handler that calls this has just failed to
// store the session, so the store still holds the pre-modification rules; a pass reading
// them would plan FAR bodies the datapath has already replaced, which is the one thing
// transact's own contract says it must not do. The record is what matters here — the next
// tasking change or the SMF's retry of the modification reconciles the datapath, and both
// now have something correct to reconcile against.
func (e *ccEnabler) farsPushed(seid uint64, fars []far) {
	if e == nil || len(fars) == 0 {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.writes++
	stamp := e.writes

	for i := range fars {
		ref := farRef{seid: seid, farID: fars[i].farID}
		e.programmed[ref] = programmedFAR{
			duplicating: fars[i].liDuplicate,
			written:     stamp,
		}
		if fars[i].liDuplicate {
			e.everDuplicated[ref] = true
		}
	}
}

// retask asks for duplication to be re-derived for every session this element
// holds, and returns as soon as the request is registered. It is called when the
// tasking changes — a task activated, modified or withdrawn — which is when a
// session's rules are correct but the answer about them is not.
//
// The work happens on the enabler's worker, so this does not block an X1 request
// behind a walk of every session. Where the caller's own report depends on the
// datapath having actually been reprogrammed, use retaskAndWait: with the worker,
// this returning no longer means the datapath is programmed.
func (e *ccEnabler) retask() {
	if e == nil {
		return
	}

	// Before the request, not after: a transaction that began first would otherwise
	// derive duplication from the previous snapshot while the request that prompted it
	// was already counted as served.
	e.reparse()
	e.request()
}

// retaskAndWait asks for the same re-derivation and waits for it to be programmed.
//
// It exists for the deactivation path, where the element reports that interception
// has stopped: that report is the outcome being reported, so it must follow the
// datapath having actually stopped duplicating rather than merely a request to.
func (e *ccEnabler) retaskAndWait() {
	if e == nil {
		return
	}

	e.reparse()
	e.await(e.request())
}

// transact is the re-derivation itself: read the current tasking, derive the rules
// it implies, program the difference, and record what was programmed. The worker
// runs one at a time, which is what makes those four steps atomic with respect to
// another pass.
//
// It does not write to the session store. It runs while the PFCP goroutine may be
// part-way through its own read-modify-write of the same session, and writing back a
// session read before that started would discard the SMF's update — corrupting a
// subscriber's own forwarding to serve an interception, which is the one thing this
// must never do. The datapath's modify path takes only the rules being changed, so a
// FAR can be reprogrammed without restating the session.
//
// The store therefore does not learn about duplication enabled this way. It does
// not need to: every path that rebuilds a FAR re-derives duplication from the
// tasking as it goes.
func (e *ccEnabler) transact() {
	e.mu.Lock()
	sources := append([]SessionsStore(nil), e.sources...)
	// Taken before any session is read, so an entry written later belongs to a
	// session this pass cannot have seen — sessionProgrammed writes only once the
	// session is in the store.
	mark := e.writes
	e.mu.Unlock()

	// Parsed once: the criteria are the same for every session, and re-parsing them
	// per session would put string handling in the loop.
	criteria := e.criteriaOf(e.tasks.Snapshot())

	// Rebuilt rather than amended, so FARs of sessions that have gone away drop out
	// instead of accumulating.
	fresh := make(map[farRef]programmedFAR)

	for _, src := range sources {
		for _, sess := range src.GetAllSessions() {
			one := []PFCPSession{sess}
			want := make(map[uint32]bool, len(sess.fars))
			for _, c := range criteria {
				for _, ref := range c.resolve(one) {
					want[ref.farID] = true
				}
			}

			var changed []far
			// What the record said before this pass touched it, for the FARs this pass
			// is about to program. If the datapath refuses them, the record has to go
			// back to describing what the datapath actually holds — not forward to
			// what was intended, and not to nothing: an entry deleted for a rule the
			// element was *turning off* would leave the next pass finding nothing to
			// do while the datapath went on duplicating.
			type priorEntry struct {
				ref  farRef
				held bool
				was  programmedFAR
			}

			var prior []priorEntry

			e.mu.Lock()
			for i := range sess.fars {
				ref := farRef{seid: sess.localSEID, farID: sess.fars[i].farID}
				if cur, held := e.programmed[ref]; held && cur.written > mark {
					// The session path re-derived this FAR from rules this pass did not
					// read, and programmed the datapath accordingly. Leave both alone: the
					// FAR body held here is the pre-modification one, so pushing it would
					// restate the SMF's own forwarding from a copy that has been replaced.
					// The carry-over at the end keeps the record; the request
					// sessionProgrammed made brings a pass that has read the new rules.
					continue
				}
				fresh[ref] = programmedFAR{duplicating: want[ref.farID], written: mark}
				if want[ref.farID] {
					// Told to duplicate, so it joins the set that is never trusted-to-be-off
					// again. Recorded before the push: a push that is refused leaves the
					// datapath as it was, and a FAR wrongly *in* this set costs one redundant
					// write per pass, while one wrongly out of it costs unbounded
					// over-collection.
					e.everDuplicated[ref] = true
				}
				// A record that agrees is normally enough to skip — that is what the record is
				// for. **Except when the answer is "off" and this element has ever turned this
				// FAR on**, in which case the record is exactly what cannot be trusted: if it
				// wrongly says "off" the datapath keeps duplicating and no later pass will ever
				// look again. See everDuplicated. The cost is one redundant write per pass per
				// FAR that has been turned off, which is a small and shrinking set; the harm it
				// removes is a subscriber's traffic being copied under no authority at all.
				recordIsEnough := want[ref.farID] || !e.everDuplicated[ref]
				if e.programmed[ref].duplicating == want[ref.farID] && recordIsEnough {
					continue
				}
				f := sess.fars[i]
				f.liDuplicate = want[ref.farID]
				changed = append(changed, f)
				was, held := e.programmed[ref]
				prior = append(prior, priorEntry{ref: ref, held: held, was: was})
			}
			e.mu.Unlock()

			if len(changed) > 0 && e.push != nil {
				// **Re-read immediately before the push, because the plan above and the
				// push below are not one step.** The lock is dropped between them — it
				// has to be, since the push is a round trip to the datapath and holding
				// e.mu across it would serialise every session handler behind one gRPC
				// call — so the session path can complete its own read-modify-write of
				// one of these FARs in the interval, program the datapath with the new
				// body, and record the write. This pass would then restate the body it
				// planned from a snapshot that has been replaced: the interception plane
				// corrupting the subscriber's own forwarding, which is the one thing this
				// function's own contract says it must never do.
				//
				// The same test the plan applies, at the moment it matters: an entry
				// written past this pass's mark belongs to a writer that has read rules
				// this pass did not, so the last writer to PutSession wins. The
				// carry-over at the end keeps its record; the request its write made
				// brings a pass that has read the new rules.
				// Set only by tests, and it exists because this interleaving is a few
				// instructions wide: a property this consequential asserted by racing two
				// goroutines and hoping is one that passes against the defect. See
				// TestATaskingPassDoesNotRestateAStaleForwardingBody.
				if beforeTransactPush != nil {
					beforeTransactPush()
				}

				e.mu.Lock()
				// **The session itself, before any of its FARs.** This extends the
				// per-FAR test below to the one thing that test cannot express: a session
				// *deleted* mid-pass has no FARs left to compare stamps against, so
				// nothing in the per-FAR loop would notice, and the push would re-add a
				// FAR to the datapath after the delete — duplication reinstated on a
				// session that has been torn down, with nothing left to turn it off.
				//
				// sessionForgotten stamps the deletion into the same counter the writes
				// use, so "the session went after this pass started" is the same
				// comparison as "this FAR was written after this pass started".
				if gone, deleted := e.forgotten[sess.localSEID]; deleted && gone > mark {
					e.mu.Unlock()

					// Its entries must not be carried into the conclusion either: the
					// deletion already removed them from e.programmed, and fresh is this
					// pass's own map.
					for i := range sess.fars {
						delete(fresh, farRef{seid: sess.localSEID, farID: sess.fars[i].farID})
					}

					continue
				}

				kept := make([]far, 0, len(changed))
				keptPrior := make([]priorEntry, 0, len(prior))
				for i := range changed {
					ref := farRef{seid: sess.localSEID, farID: changed[i].farID}
					if cur, held := e.programmed[ref]; held && cur.written > mark {
						continue
					}
					// Removed while this pass ran. Pushing it would not merely restate a
					// stale body — the datapath's modify path programs what it is given,
					// so it would re-create a FAR the SMF has deleted, on the strength of
					// the interception plane wanting to duplicate it.
					if gone, removed := e.forgottenFARs[ref]; removed && gone > mark {
						delete(fresh, ref)

						continue
					}
					kept = append(kept, changed[i])
					keptPrior = append(keptPrior, prior[i])
				}
				e.mu.Unlock()

				changed, prior = kept, keptPrior
			}

			if len(changed) > 0 && e.push != nil {
				// Only the changed FARs: the datapath's modify path programs what it is
				// given, and restating the rest would rewrite rules it already has.
				cause := e.push(PacketForwardingRules{}, PacketForwardingRules{fars: changed})
				if cause != ie.CauseRequestAccepted {
					// The datapath answered, and the answer was that none of this was
					// programmed. It is one cause for the whole write, so the whole
					// write is what is refused. fresh is this pass's own map and no
					// other goroutine reads it, so no lock is needed; the carry-over
					// below still lets a newer write win over this restoration, which
					// is what keeps a session modified mid-pass authoritative.
					for _, p := range prior {
						if p.held {
							fresh[p.ref] = p.was
						} else {
							delete(fresh, p.ref)
						}
					}
					if e.report != nil {
						e.report(x1.NEIssueDuplicationRefused,
							"the datapath refused a duplication rule for an accepted interception task")
					}
				}
			}
		}
	}

	e.mu.Lock()
	// An entry written while this pass ran wins over its conclusion, whether or not
	// it reached one: a session established mid-pass is invisible to it, and a
	// session modified mid-pass was read in a state that has been replaced. Entries
	// older than the mark and absent from fresh belong to sessions that have gone
	// away and drop, which is what rebuilding the map was for.
	for ref, cur := range e.programmed {
		if cur.written > mark {
			fresh[ref] = cur
		}
	}
	// And the deletions, which the loop above cannot express: an entry that is *gone* from
	// e.programmed is not there to be carried over, so a pass that planned one from a view
	// predating the deletion would write its own copy straight back.
	//
	// The push block already does this for the sessions and FARs it pushed. It is not
	// enough on its own: that block runs only when this pass had something to push, and a
	// pass that concluded nothing was to be changed still planned an entry for every FAR it
	// walked. That is the ordinary case for an element whose tasking is stable, which is
	// also the case sessionForgotten exists to reclaim.
	for ref := range fresh {
		if gone, deleted := e.forgotten[ref.seid]; deleted && gone > mark {
			delete(fresh, ref)

			continue
		}
		if gone, removed := e.forgottenFARs[ref]; removed && gone > mark {
			delete(fresh, ref)
		}
	}
	e.programmed = fresh

	// The deletions that predate this pass: it read the world after them, so no pass will
	// ever need to be told about them again. The ones stamped *during* this pass were acted
	// on above and are dropped by the next pass, whose mark is past them — the worker is
	// serial, so no pass with an older mark can still be running.
	//
	// Reclaimed at all because a map that grows with every released session and is never
	// emptied is precisely the leak sessionForgotten exists to prevent, reintroduced by its
	// own bookkeeping.
	for seid, gone := range e.forgotten {
		if gone <= mark {
			delete(e.forgotten, seid)
		}
	}
	for ref, gone := range e.forgottenFARs {
		if gone <= mark {
			delete(e.forgottenFARs, ref)
		}
	}
	e.mu.Unlock()
}

// beforeTransactPush is called after a pass has planned a session's FAR bodies and
// before it re-reads them for the push. Set only by tests; nil otherwise.
//
// **What this remedy closes and what it does not.** The re-read means a modification
// that has completed its PutSession by this point wins: the pass drops that FAR and
// leaves the datapath holding the SMF's body. What remains is the width of the push
// itself — two writers whose round trips genuinely overlap reach the datapath in an
// order neither controls — and closing that would mean serialising the interception
// plane's pushes against the session handler's, which is a lock on the session
// signalling path rather than a change here. The residual is stated rather than
// implied: "last writer to PutSession wins" is the property, and it is only meaningful
// where one of the two has finished writing.
var beforeTransactPush func()

// lostContent reports a copy this element made and did not deliver, through the condition
// every other content loss uses. Nil-safe in both directions: an enabler without a reporter
// says nothing, which is the certificate-less/no-ADMF case.
func (e *ccEnabler) lostContent() {
	if e == nil || e.report == nil {
		return
	}
	e.report(x1.NEIssueX3DeliveryLost,
		"a fragment of an authorised datagram was discarded because its first fragment "+
			"had not been seen")
}

// sessionFor returns the session with the given SEID from whichever association
// holds it.
func (e *ccEnabler) sessionFor(seid uint64) (PFCPSession, bool) {
	e.mu.Lock()
	sources := append([]SessionsStore(nil), e.sources...)
	e.mu.Unlock()

	for _, src := range sources {
		if sess, ok := src.GetSession(seid); ok {
			return sess, true
		}
	}

	return PFCPSession{}, false
}

// coveredTask is a task that covers a session, with the criteria resolved against
// that session so each copy can be decided without resolving them again.
type coveredTask struct {
	task   types.InterceptTask
	filter copyFilter
}

// tasksCovering returns the active tasks whose detection criteria select traffic in
// the session the datapath tagged a copy with, in XID order.
//
// **The answer is memoised per session, and the objection this used to carry is the
// reason it is stamped rather than indexed.** An index maintained incrementally has to
// be invalidated at every site that changes tasking or session rules, and a site that
// forgets goes stale silently — product attributed to the wrong warrant, or dropped as
// untasked, neither visible from outside this element. An entry stamped with the
// tasking epoch it was computed under cannot: a forgotten bump invalidates *everything*
// rather than one thing wrongly, which fails toward recomputation.
//
// Two writers, and they invalidate different amounts because they affect different
// amounts. A change in tasking moves the epoch, which retires every session's answer.
// A change in one session's own rules, or that session going away, drops that session's
// entry — reparse would be the wrong instrument there, since the tasking has not moved.
//
// What this replaced, and why the previous comment's cost estimate was the wrong way
// round. Per copy it did: a full store snapshot with a deep clone of every task's four
// slices, then a parse of every criterion of every task, then a resolve over every PDR,
// then filterFor parsing the same criteria a second time — and for a PDR criterion an
// IE parse and a throwaway address pool. Measured at about 95 allocations per copy for
// three warrants against one session, where framing is one allocation and a memcpy and
// delivery amortises across a 32-PDU batch. This is the one path in this element whose
// cost is per packet, in front of a socket queue holding ten datagrams by default whose
// overflow is intercept product nothing downstream can recover.
func (e *ccEnabler) tasksCovering(seid uint64) []coveredTask {
	if e == nil || e.tasks == nil {
		return nil
	}

	// The epoch is read first. Reading it after computing would let a tasking change
	// that landed during the computation be stamped as though it had been accounted
	// for, and nothing would recompute it.
	epoch := e.epoch.Load()

	e.coveredMu.Lock()
	held, ok := e.covered[seid]
	e.coveredMu.Unlock()

	if ok && held.epoch == epoch {
		return held.tasks
	}

	out := e.resolveCovering(seid)

	e.coveredMu.Lock()
	// Only where the session still exists. A session that has gone away is dropped by
	// forgetCovered, and storing an answer for it here would put back the entry that
	// just removed — an entry nothing would ever remove again, since the events that
	// prune this map have both already happened for that session.
	if out != nil {
		e.covered[seid] = coveredEntry{epoch: epoch, tasks: out}
	}
	e.coveredMu.Unlock()

	return out
}

// resolveCovering is tasksCovering's answer computed from scratch: which of the live
// content tasks' criteria select traffic in this session, in XID order.
//
// The order is the snapshot's, which is ordered by XID — the caller picks one task
// when several cover a session, and picking a different one per packet would split a
// session's product across the covering warrants so that no agency gets a whole
// stream.
func (e *ccEnabler) resolveCovering(seid uint64) []coveredTask {
	sess, ok := e.sessionFor(seid)
	if !ok {
		// The session went away between the datapath duplicating the packet and this
		// running. Nothing to attribute the copy to.
		return nil
	}

	parsed := e.parsed.Load()
	if parsed == nil {
		return nil
	}

	one := []PFCPSession{sess}

	var out []coveredTask
	for _, pt := range *parsed {
		for _, c := range pt.criteria {
			if len(c.resolve(one)) > 0 {
				out = append(out, coveredTask{
					task: pt.task,
					// The reporter is this element's, so the memo built inside can report a
					// fragment it had to discard through the same channel every other content
					// loss uses.
					filter: filterFrom(pt.criteria, sess, e.lostContent),
				})

				break
			}
		}
	}

	return out
}

// taskFaults answers what is wrong with one task's interception, now, for the triggering
// function that asks — see x1.WithTaskFaults.
//
// **Computed, never stored, and the two conditions it reports are the ones a CC-POI can
// re-observe.** A refusal from the datapath is an event; whether this element is duplicating
// what a task requires is a state, and it is the state that matters — it is equally true after a
// refusal, after a push that was lost, and after a FAR that was never programmed at all. So the
// question asked here is not "did something fail" but "does the record of what the datapath was
// told match what this task's criteria select":
//
//   - Traffic this task selects that the datapath is not duplicating. The record is only an
//     account of what the datapath was last told, which is exactly the right authority for this
//     question: an entry saying `duplicating: false`, or no entry at all, means no copy is being
//     made whatever the tasking says should happen.
//   - No session at all that this task's criteria select. A CC-POI's task is installed by a
//     triggering function against traffic that exists, so a task selecting nothing is an
//     interception producing nothing — and the answer says what was observed rather than
//     accusing anybody, because a session torn down and one never established look the same from
//     here.
//
// **Reported against the task and nowhere else.** Both conditions are already reported at
// element scope, which is what a triggering function has had to work with: it learns that
// something at this point of interception is wrong and cannot tell which of the warrants it
// installed is affected. That attribution is the whole difference, and it is why `triggerFaulty`
// could not be raised for one warrant.
//
// It reads the parsed snapshot rather than re-parsing, so the criteria are the same ones the
// shipping path resolves copies against — an answer computed from a second parse could differ
// from the interception it describes.
//
// A task the snapshot does not carry answers nothing: either it requires no content, in which
// case this element has nothing to say about it, or its criteria do not parse, which activation
// already refuses.
func (e *ccEnabler) taskFaults(xid types.XID) []x1.X1Error {
	if e == nil {
		return nil
	}
	snapshot := e.parsed.Load()
	if snapshot == nil {
		return nil
	}

	var criteria []criterion
	for i := range *snapshot {
		if (*snapshot)[i].task.XID == xid {
			criteria = (*snapshot)[i].criteria

			break
		}
	}
	if len(criteria) == 0 {
		return nil
	}

	e.mu.Lock()
	sources := append([]SessionsStore(nil), e.sources...)
	e.mu.Unlock()

	selecting, undup := 0, 0
	for _, src := range sources {
		if src == nil {
			continue
		}
		for _, sess := range src.GetAllSessions() {
			one := []PFCPSession{sess}
			want := map[uint32]bool{}
			for _, c := range criteria {
				for _, ref := range c.resolve(one) {
					want[ref.farID] = true
				}
			}
			if len(want) == 0 {
				continue
			}
			selecting++

			e.mu.Lock()
			for farID := range want {
				if p, held := e.programmed[farRef{seid: sess.localSEID, farID: farID}]; !held || !p.duplicating {
					undup++
				}
			}
			e.mu.Unlock()
		}
	}

	switch {
	case selecting == 0:
		return []x1.X1Error{x1.TaskFault(x1.TaskIssueNoTrafficSelected,
			"no session this element holds carries traffic this task selects, so this "+
				"interception is producing nothing")}
	case undup > 0:
		return []x1.X1Error{x1.TaskFault(x1.TaskIssueDuplicationNotProgrammed, fmt.Sprintf(
			"the datapath is not duplicating %d forwarding rule(s) this task requires, across "+
				"%d session(s) it selects", undup, selecting))}
	}

	return nil
}
