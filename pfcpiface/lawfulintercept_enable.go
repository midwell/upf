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
		tasks:      tasks,
		push:       push,
		report:     report,
		programmed: make(map[farRef]programmedFAR),
		covered:    make(map[uint64]coveredEntry),
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
func (e *ccEnabler) sessionProgrammed(s *PFCPSession) {
	if e == nil || s == nil {
		return
	}

	e.mu.Lock()
	e.writes++
	stamp := e.writes
	// Duplicating, because a copy running under tasking that may since have been
	// withdrawn is the thing that must be re-derived. Changed, because a
	// modification that took a session *out* of scope has to survive a pass holding
	// the older view just as much.
	notable := false
	for i := range s.fars {
		ref := farRef{seid: s.localSEID, farID: s.fars[i].farID}
		if s.fars[i].liDuplicate || e.programmed[ref].duplicating != s.fars[i].liDuplicate {
			notable = true
		}
		e.programmed[ref] = programmedFAR{duplicating: s.fars[i].liDuplicate, written: stamp}
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
func (e *ccEnabler) sessionForgotten(s *PFCPSession) {
	if e == nil || s == nil {
		return
	}

	e.forgetCovered(s.localSEID)

	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range s.fars {
		delete(e.programmed, farRef{seid: s.localSEID, farID: s.fars[i].farID})
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
				if e.programmed[ref].duplicating == want[ref.farID] {
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
				kept := make([]far, 0, len(changed))
				keptPrior := make([]priorEntry, 0, len(prior))
				for i := range changed {
					ref := farRef{seid: sess.localSEID, farID: changed[i].farID}
					if cur, held := e.programmed[ref]; held && cur.written > mark {
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
	e.programmed = fresh
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
					task:   pt.task,
					filter: filterFrom(pt.criteria, sess),
				})

				break
			}
		}
	}

	return out
}
