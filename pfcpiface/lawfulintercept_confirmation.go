// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"sync/atomic"

	"github.com/wmnsk/go-pfcp/ie"
)

// A batch of datapath writes has two outcomes that must not be collapsed into one: the
// PFCP cause the SMF is told, and whether this element can say the writes were applied.
//
// They differ on exactly one case, and it is the common one. A worker whose RPC did not
// complete -- bessd down, or a context deadline reached before GRPCJoin's own timer --
// learns nothing about what the datapath did with the rule. SendMsgToUPF deliberately
// answers that as accepted, because rejecting it would have the caller forget a session
// whose rules may still be installed. For an interception that leniency is unsafe in the
// other direction: a duplication FAR recorded as programmed drops out of every later
// re-derivation, so no pass retries it, and an accepted warrant produces nothing while
// this element reports itself healthy.
//
// ETSI TS 103 221-1 clause 5.3 requires the element to hold that as a fault rather than a
// warning -- "any issue which loses traffic is categorized as a fault" -- and clause
// 6.5.2.2 names the category: "currently unable to collect traffic but not terminating".
// Clause 5.2.2 gives the element room to resolve it, since an action that cannot complete
// within TIME1 (five seconds by default) is answered "OK - Acknowledged" with a status
// report to follow; the PFCP batch deadline is one second, so the next re-derivation has
// time to confirm or to keep the fault standing.
//
// The flag rides on the batch's own context so that the workers' `done` contract and
// GRPCJoin stay exactly as upstream wrote them: this adds a second, out-of-band answer
// rather than changing the one they already give.
type batchConfirmation struct {
	unconfirmed atomic.Bool
}

type batchConfirmationKey struct{}

// withBatchConfirmation attaches a fresh confirmation to one batch's context. Per batch,
// not per bess: SendMsgToUPF may be running concurrently for several sessions.
func withBatchConfirmation(ctx context.Context) (context.Context, *batchConfirmation) {
	batch := &batchConfirmation{}

	return context.WithValue(ctx, batchConfirmationKey{}, batch), batch
}

// noteUnconfirmed records that one write in this batch was neither accepted nor refused.
// Silent when the context carries no confirmation, so a caller that builds its own
// context -- clearState, the slice-meter setup -- needs no change.
func noteUnconfirmed(ctx context.Context) {
	if batch, ok := ctx.Value(batchConfirmationKey{}).(*batchConfirmation); ok {
		batch.unconfirmed.Store(true)
	}
}

// confirmingDatapath is the optional half of the datapath contract: a datapath that can
// distinguish a write it saw acknowledged from one it merely failed to have refused.
//
// Optional, and deliberately not part of the datapath interface, which stays exactly as
// upstream defines it -- this is a lawful-interception concern and every other caller is
// served by the cause alone. A datapath that does not implement it is taken at its word.
type confirmingDatapath interface {
	sendMsgToUPFConfirmed(
		method upfMsgType, all, updated PacketForwardingRules,
	) (uint8, bool)
}

// sendDuplicationWrite is SendMsgToUPF for a batch an interception depends on: the same
// PFCP cause, and separately whether the datapath acknowledged every write in it.
//
// Only the BESS datapath can tell the two apart. Any other -- the test fakes, and any
// datapath added later -- is taken at its word, so an accepted batch counts as confirmed
// and every caller keeps the behaviour it had before this existed.
func (u *upf) sendDuplicationWrite(
	method upfMsgType, all, updated PacketForwardingRules,
) (uint8, bool) {
	if c, ok := u.datapath.(confirmingDatapath); ok {
		return c.sendMsgToUPFConfirmed(method, all, updated)
	}

	cause := u.SendMsgToUPF(method, all, updated)

	return cause, cause == ie.CauseRequestAccepted
}
