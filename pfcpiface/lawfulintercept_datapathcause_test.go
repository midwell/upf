// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"github.com/wmnsk/go-pfcp/ie"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// bessWithNoDatapath is a real bess talking real gRPC to nothing.
//
// **Deliberately not a fake push.** The remedy this exercises — record what the
// datapath accepted, and retry what it refused — was written, tested and shipped
// while its refusal branch was unreachable, because SendMsgToUPF initialised its
// cause to accepted and never assigned it again, and because addFAR signalled
// success to GRPCJoin whatever the datapath answered. Both tests of it drove a
// stubbed `push`, so both passed against a path production does not take. The only
// test that can tell the difference is one that goes through SendMsgToUPF with the
// gRPC call actually failing.
//
// A dead address rather than a hand-written client: it is one line, and what is
// under test is precisely how a genuine gRPC failure travels.
func bessWithNoDatapath(t *testing.T) *bess {
	t.Helper()

	// A port nothing is listening on. Bound and closed, so the address is real and
	// nothing can have taken it in between.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() }) //nolint:errcheck // test

	return &bess{conn: conn, client: pb.NewBESSControlClient(conn)}
}

// TestARefusedDatapathWriteIsReportedAsRefused is 1.1 and 1.3 together: the cause
// SendMsgToUPF returns has to describe what the datapath did.
//
// Before this, a failed batch was logged and reported as CauseRequestAccepted. That
// made three rejection branches unreachable — the session establishment handler's,
// the modification handler's, and the interception enabler's record of what was
// programmed — and the last one is the one that cannot be recovered from: a refused
// FAR recorded as programmed drops out of every subsequent difference, so no
// re-derivation ever retries it and the interception silently never starts.
func TestARefusedDatapathWriteIsReportedAsRefused(t *testing.T) {
	b := bessWithNoDatapath(t)

	rules := PacketForwardingRules{fars: []far{{farID: 1, fseID: 0x2632898145f4d191, applyAction: ActionForward}}}

	if cause := b.SendMsgToUPF(upfMsgTypeMod, PacketForwardingRules{}, rules); cause != ie.CauseRequestRejected {
		t.Errorf("SendMsgToUPF returned cause %d for a write to a datapath that is not there, "+
			"want %d (rejected): every caller that tests for a refusal has an unreachable branch "+
			"while this is accepted, and an interception refused by the datapath is recorded as "+
			"running", cause, ie.CauseRequestRejected)
	}
}

// TestAnAcceptedDatapathWriteStaysAccepted is 1.4, the non-LI regression guard: the
// success path must return exactly what it returned before, because the session
// handlers consume this value to decide whether to answer the SMF with a refusal.
//
// An empty batch is the one shape that reaches the success path without a datapath:
// no calls are made, so nothing can fail, and the value returned is the initialised
// one. That is what makes it the right guard — it pins that the change did not move
// the default.
func TestAnAcceptedDatapathWriteStaysAccepted(t *testing.T) {
	b := bessWithNoDatapath(t)

	if cause := b.SendMsgToUPF(upfMsgTypeMod, PacketForwardingRules{}, PacketForwardingRules{}); cause != ie.CauseRequestAccepted {
		t.Errorf("SendMsgToUPF returned cause %d for a write with nothing in it, want %d "+
			"(accepted): the non-LI callers read this value, and a batch the datapath was never "+
			"asked about is not a refusal", cause, ie.CauseRequestAccepted)
	}
}

// TestARefusedDuplicationFARIsRetriedAndReported is the whole of group 1's first
// claim, driven end to end: the enabler's push is bess.SendMsgToUPF against a
// datapath that is not there.
//
// Two properties, and the second is the one the stubbed test could not establish.
// The refusal is reported to the ADMF as duplicationRefused — an interception the
// element has acknowledged is producing nothing, which is invisible from outside.
// And the FAR stays in the difference, so the next re-derivation pushes it again:
// an interception refused once must not be recorded as running.
func TestARefusedDuplicationFARIsRetriedAndReported(t *testing.T) {
	b := bessWithNoDatapath(t)

	tasks := store.New()
	sessions := NewInMemoryStore()

	var reported []string
	reportedAt := make(chan string, 8)
	// Wrapped exactly as production wraps it (see startLIShipper): the enabler pushes
	// a modification, and what it gets back is the datapath's own cause.
	e := newCCEnabler(tasks, func(all, updated PacketForwardingRules) uint8 {
		return b.SendMsgToUPF(upfMsgTypeMod, all, updated)
	}, func(issueType, _ string) {
		reportedAt <- issueType
	})
	t.Cleanup(e.stop)
	e.addSource(sessions)

	// A whole session, PDRs included: a criterion resolves through the PDRs to the FARs
	// carrying their traffic, so a session of bare FARs would produce no difference at
	// all and this test would assert nothing.
	const seid = uint64(0x2632898145f4d191)
	if err := sessions.PutSession(unmarkedSession(seid, "10.250.0.9")); err != nil {
		t.Fatal(err)
	}

	// A warrant naming the session itself, which is what this deployment's own
	// triggering function sends.
	task := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
		Targets: []types.TargetIdentifier{
			{Type: types.TargetFSEID, Value: "2752413510594253201"}, // the SEID above, in decimal
		},
	}
	if !tasks.Activate(task) {
		t.Fatal("Activate failed")
	}

	e.retaskAndWait()

	select {
	case issue := <-reportedAt:
		reported = append(reported, issue)
		if issue != x1.NEIssueDuplicationRefused {
			t.Errorf("the refusal was reported as %q, want %q", issue, x1.NEIssueDuplicationRefused)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the datapath refused a duplication rule for an accepted interception task and " +
			"nothing was reported: the element holds a warrant it has acknowledged, produces " +
			"nothing for it, and no channel says so")
	}

	// The FAR must still be eligible. The record of what was programmed is what the
	// next pass differences against, so a refusal recorded as success is the end of
	// that interception — nothing re-derives it, because nothing has changed.
	e.retaskAndWait()

	select {
	case issue := <-reportedAt:
		reported = append(reported, issue)
	case <-time.After(5 * time.Second):
		t.Fatalf("the second re-derivation pushed nothing: the refused FAR was recorded as "+
			"programmed and has dropped out of the difference, so this interception will never "+
			"be retried. reported so far: %v", reported)
	}
}

// TestARefusedFARProgramReachesGRPCJoin pins the link the two remedies above rest
// on, at the level below them: addFAR must tell GRPCJoin what the datapath said.
//
// It used to send `done <- true` unconditionally — processFAR logged the error and
// returned nothing — so GRPCJoin could not fail on a refusal at all, and a cause
// derived from it would still have been accepted. This is why 1.1 alone was not
// enough, and it is worth its own assertion because the two are separately
// revertible.
func TestARefusedFARProgramReachesGRPCJoin(t *testing.T) {
	b := bessWithNoDatapath(t)

	done := make(chan bool, 1)
	b.addFAR(t.Context(), done, far{farID: 1, fseID: 1, applyAction: ActionForward})

	select {
	case ok := <-done:
		if ok {
			t.Error("addFAR signalled success for a FAR the datapath never received: " +
				"GRPCJoin cannot fail, so no cause derived from it can report a refusal")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("addFAR signalled nothing")
	}

	// And the error names the interface it came from, so an operator reading the log
	// is not left with a bare failure.
	if err := b.processFAR(t.Context(), nil, upfMsgTypeAdd); err == nil {
		t.Error("processFAR reported success against a datapath that is not there")
	} else if strings.TrimSpace(err.Error()) == "" {
		t.Error("processFAR returned an error with no message")
	}
}
