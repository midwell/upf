// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"fmt"
	"sync"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
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
	// push writes changed rules to the datapath. Separate field so a test can
	// observe what would be programmed without a datapath.
	push func(all, updated PacketForwardingRules)

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

// programmedFAR is what this element last told the datapath about one FAR, and
// when it said so.
type programmedFAR struct {
	duplicating bool
	// written is the value of writes at the moment the entry was recorded.
	written uint64
}

func newCCEnabler(tasks *store.Store, push func(all, updated PacketForwardingRules)) *ccEnabler {
	e := &ccEnabler{tasks: tasks, push: push, programmed: make(map[farRef]programmedFAR)}
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

	if notable {
		e.request()
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
			}
			e.mu.Unlock()

			if len(changed) > 0 && e.push != nil {
				// Only the changed FARs: the datapath's modify path programs what it is
				// given, and restating the rest would rewrite rules it already has.
				e.push(PacketForwardingRules{}, PacketForwardingRules{fars: changed})
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
// Computed per copy rather than kept as an index. An index would have to be
// invalidated wherever tasking or session rules change, and going stale would show
// up as product attributed to the wrong warrant or dropped as untasked — neither
// visible from outside this element. The work is a map lookup and a handful of
// integer comparisons against rules already in memory, which is small beside the
// framing and delivery each copy costs anyway.
func (e *ccEnabler) tasksCovering(seid uint64) []coveredTask {
	if e == nil || e.tasks == nil {
		return nil
	}

	sess, ok := e.sessionFor(seid)
	if !ok {
		// The session went away between the datapath duplicating the packet and this
		// running. Nothing to attribute the copy to.
		return nil
	}

	one := []PFCPSession{sess}

	// Snapshot is ordered by XID, so the order here is too — the caller picks one
	// task when several cover a session, and picking a different one per packet would
	// split a session's product across warrants so that no agency gets a whole
	// stream.
	var out []coveredTask
	for _, task := range e.tasks.Snapshot() {
		// Same filter as criteriaOf, and for a sharper reason here: a task that cannot
		// be delivered for must not take attribution of a copy away from one that can.
		// Snapshot is XID-ordered and the caller takes the first, so a leftover
		// non-CC task covering the same session would silently swallow the whole
		// stream of the warrant that does have a destination.
		if !producesCC(task) {
			continue
		}
		for _, id := range task.Targets {
			c, err := parseCriterion(id)
			if err != nil {
				continue
			}
			if len(c.resolve(one)) > 0 {
				out = append(out, coveredTask{task: task, filter: filterFor(task, sess)})

				break
			}
		}
	}

	return out
}
