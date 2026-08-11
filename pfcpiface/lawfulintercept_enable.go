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
	programmed map[farRef]bool
	// push writes changed rules to the datapath. Separate field so a test can
	// observe what would be programmed without a datapath.
	push func(all, updated PacketForwardingRules)
}

func newCCEnabler(tasks *store.Store, push func(all, updated PacketForwardingRules)) *ccEnabler {
	return &ccEnabler{tasks: tasks, push: push, programmed: make(map[farRef]bool)}
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
// one it cannot. It answers on the criteria alone: every one must be something the
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

// criteriaOf returns the parsed criteria of every active task, dropping any that
// no longer parse. canApply refused those at tasking time, so a leftover can only
// come from a task installed before this check existed.
func (e *ccEnabler) criteriaOf(tasks []types.InterceptTask) []criterion {
	var out []criterion
	for _, t := range tasks {
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

	// The caller pushes these rules itself, so record them as programmed: otherwise
	// the next re-derivation would find a difference that does not exist and rewrite
	// rules the datapath already has.
	e.mu.Lock()
	for i := range s.fars {
		e.programmed[farRef{seid: s.localSEID, farID: s.fars[i].farID}] = s.fars[i].liDuplicate
	}
	e.mu.Unlock()
}

// retask re-derives duplication for every session this element holds and programs
// the difference into the datapath. It runs when the tasking changes — a task
// activated, modified or withdrawn — which is when a session's rules are correct
// but the answer about them is not.
//
// It does not write to the session store. It runs on the X1 goroutine while the
// PFCP goroutine may be part-way through its own read-modify-write of the same
// session, and writing back a session read before that started would discard the
// SMF's update — corrupting a subscriber's own forwarding to serve an interception,
// which is the one thing this must never do. The datapath's modify path takes only
// the rules being changed, so a FAR can be reprogrammed without restating the
// session.
//
// The store therefore does not learn about duplication enabled this way. It does
// not need to: every path that rebuilds a FAR re-derives duplication from the
// tasking as it goes.
func (e *ccEnabler) retask() {
	if e == nil {
		return
	}

	e.mu.Lock()
	sources := append([]SessionsStore(nil), e.sources...)
	e.mu.Unlock()

	// Parsed once: the criteria are the same for every session, and re-parsing them
	// per session would put string handling in the loop.
	criteria := e.criteriaOf(e.tasks.Snapshot())

	// Rebuilt rather than amended, so FARs of sessions that have gone away drop out
	// instead of accumulating.
	fresh := make(map[farRef]bool)

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
				fresh[ref] = want[ref.farID]
				if e.programmed[ref] == want[ref.farID] {
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
