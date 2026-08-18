// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Intel Corporation

package pfcpiface

import (
	"fmt"

	"github.com/omec-project/upf-epc/logger"
	"github.com/omec-project/upf-epc/pfcpiface/metrics"
)

type PacketForwardingRules struct {
	pdrs []pdr
	fars []far
	qers []qer
}

// privateCopy returns the same rules over backing arrays no other goroutine holds.
//
// **A stored session is shared memory, and its rule slices are the shared part.** The
// store keeps a PFCPSession by value in a sync.Map, so every getter hands out a copy of
// the struct — but a slice header copied by value still points at the one array. The
// arrays are allocated at cap(MaxItems) in NewPFCPSession and never grow past it, so
// append never reallocates and the sharing is total rather than intermittent: the
// writer's array *is* every reader's array, for the life of the session.
//
// A path that mutates a stored session's rules in place therefore mutates what every
// concurrent reader is reading, however carefully the two paths are ordered above that
// point — UpdateFAR writes a whole far struct into the array, and RemoveFAR shifts the
// remainder down inside it. What a reader can then observe is a rule half-replaced, or
// a rule at an index that now belongs to a different one, and what it does with it is
// program the user plane. Ordering arguments about which path may touch which session
// are necessary and not sufficient: they operate on whole sessions, and this operates
// on the bytes of one rule.
//
// So the copy goes on the writer, which is the only one of the two there is. The
// alternative — copying in the getters — is both the wrong end and not a fix: GetSession
// is on the packet path through resolveCovering, so it pays per reader for a hazard that
// exists per writer, and copying an array another goroutine is mutating in place is
// still a racing read. Narrowing the window is not closing it.
//
// The readers this protects are ccEnabler.transact, which reads sess.fars on the
// enabler's worker, and resolveCovering, which reaches the same arrays from a framing
// worker through sessionFor. Neither file mentions this one, which is why the property
// is written down at both ends.
func (p PacketForwardingRules) privateCopy() PacketForwardingRules {
	return PacketForwardingRules{
		pdrs: cloneRules(p.pdrs),
		fars: cloneRules(p.fars),
		qers: cloneRules(p.qers),
	}
}

// cloneRules copies a rule slice, keeping its capacity.
//
// Capacity rather than length, because the headroom is load-bearing: the store
// allocates these at cap(MaxItems) and CreateFAR appends into it. A copy sized to its
// length would reallocate on the next append — harmless in itself, but it would change
// behaviour this copy has no business changing.
func cloneRules[T any](in []T) []T {
	out := make([]T, len(in), cap(in))
	copy(out, in)

	return out
}

// PFCPSession implements one PFCP session.
type PFCPSession struct {
	localSEID  uint64
	remoteSEID uint64
	metrics    *metrics.Session
	PacketForwardingRules
}

func (p PacketForwardingRules) String() string {
	return fmt.Sprintf("PDRs=%v, FARs=%v, QERs=%v", p.pdrs, p.fars, p.qers)
}

// NewPFCPSession allocates an session with ID.
func (pConn *PFCPConn) NewPFCPSession(rseid uint64) (PFCPSession, bool) {
	for i := 0; i < pConn.maxRetries; i++ {
		lseid := pConn.rng.Uint64()
		// Check if it already exists
		if _, ok := pConn.store.GetSession(lseid); ok {
			continue
		}

		s := PFCPSession{
			localSEID:  lseid,
			remoteSEID: rseid,
			PacketForwardingRules: PacketForwardingRules{
				pdrs: make([]pdr, 0, MaxItems),
				fars: make([]far, 0, MaxItems),
				qers: make([]qer, 0, MaxItems),
			},
		}
		s.metrics = metrics.NewSession(pConn.nodeID.remote)

		// Metrics update
		pConn.SaveSessions(s.metrics)

		return s, true
	}

	return PFCPSession{}, false
}

// RemoveSession removes session using lseid.
func (pConn *PFCPConn) RemoveSession(session PFCPSession) {
	// Metrics update
	session.metrics.Delete()
	pConn.SaveSessions(session.metrics)

	if err := pConn.store.DeleteSession(session.localSEID); err != nil {
		logger.PfcpLog.Errorf("failed to delete PFCP session from store: %v", err)
	}

	// Lawful Interception CC-POI: the duplication record for this session's FARs
	// describes a session that no longer exists. Silent no-op unless LI is
	// configured.
	pConn.upf.ccEnabler.sessionForgotten(&session)
}
