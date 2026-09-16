// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
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
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
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

// TestAnUnconfirmedDatapathWriteIsNotCountedAsProgrammed is the property the datapath
// owes an interception, now that the two answers are separate.
//
// A write whose RPC never completed says nothing about what the datapath did, and
// SendMsgToUPF answers it as **accepted** on purpose: rejecting an uncertain result would
// have the caller tear down a session whose rules may still be installed, and the context
// these calls carry expires before GRPCJoin's own timer, so a merely slow datapath reaches
// this branch routinely.
//
// The interception record cannot take that answer. ETSI TS 103 221-1 clause 5.3 makes an
// issue that loses traffic a fault rather than a warning, and clause 6.5.2.2 names the
// state exactly -- "currently unable to collect traffic but not terminating". So the cause
// stays accepted and the confirmation is false, and it is the confirmation the enabler
// records against.
func TestAnUnconfirmedDatapathWriteIsNotCountedAsProgrammed(t *testing.T) {
	b := bessWithNoDatapath(t)

	rules := PacketForwardingRules{fars: []far{{farID: 1, fseID: 0x2632898145f4d191, applyAction: ActionForward}}}

	cause, confirmed := b.sendMsgToUPFConfirmed(upfMsgTypeMod, PacketForwardingRules{}, rules)

	if cause != ie.CauseRequestAccepted {
		t.Errorf("SendMsgToUPF returned cause %d for a write whose RPC did not complete, want %d "+
			"(accepted): an uncertain result must not have the caller forget a session the "+
			"datapath may still be forwarding for", cause, ie.CauseRequestAccepted)
	}

	if confirmed {
		t.Error("the batch reported itself confirmed for a write to a datapath that is not " +
			"there: a duplication FAR recorded as programmed drops out of every later " +
			"difference, so no re-derivation retries it and an accepted warrant produces " +
			"nothing while this element reports itself healthy")
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

// TestAnUnconfirmedDuplicationFARIsRetriedAndReported is the whole of it driven end to
// end: the enabler's push is the real datapath call against a datapath that is not there,
// so the batch comes back accepted-but-unconfirmed — the case the PFCP cause alone cannot
// express.
//
// Three properties. The ADMF is told, because an interception this element has
// acknowledged and cannot confirm is invisible from outside; ETSI TS 103 221-1 clause 5.3
// requires the element to raise that rather than hold it. The FAR stays in the difference,
// so the next re-derivation pushes it again — an unconfirmed write recorded as programmed
// drops out of every later pass, and nothing would ever retry it. And an interrogation of
// the task answers with a fault rather than claiming the warrant is served.
func TestAnUnconfirmedDuplicationFARIsRetriedAndReported(t *testing.T) {
	b := bessWithNoDatapath(t)

	tasks := store.New()
	sessions := NewInMemoryStore()

	var reported []string
	reportedAt := make(chan string, 8)
	// Wired exactly as production wires it (see the enabler's push in lawfulintercept.go):
	// the enabler pushes a modification and gets back both the datapath's cause and whether
	// the write was acknowledged. Not confirmedPush, which is for tests whose subject is the
	// cause: here the cause is accepted and the confirmation is the whole point.
	e := newCCEnabler(tasks, func(all, updated PacketForwardingRules) (uint8, bool) {
		return b.sendMsgToUPFConfirmed(upfMsgTypeMod, all, updated)
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
			t.Errorf("the unconfirmed write was reported as %q, want %q", issue, x1.NEIssueDuplicationRefused)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the datapath did not confirm a duplication rule for an accepted interception " +
			"task and nothing was reported: the element holds a warrant it has acknowledged, " +
			"cannot say whether it is being served, and no channel says so")
	}

	// And the task itself answers with a fault. TS 103 221-1 clause 6.5.2.2's category for
	// this is "currently unable to collect traffic but not terminating", which x1.TaskFault
	// carries as issue code 9020.
	faults := e.taskFaults(task.XID)
	if len(faults) == 0 {
		t.Fatal("a task whose duplication the datapath did not confirm reports no fault, so an " +
			"interrogation is told it is provisioned and faultless while it may be producing " +
			"nothing")
	}
	if !strings.Contains(faults[0].ErrorDescription, "not duplicating") {
		t.Errorf("the fault does not say what is wrong: %q", faults[0].ErrorDescription)
	}
	if faults[0].ErrorCode != 9020 {
		t.Errorf("the fault carries issue code %d, want 9020 (generic non-terminating fault): "+
			"an element that cannot currently collect for a task is in a non-terminating fault, "+
			"not a warning (TS 103 221-1 clause 5.3) and not a terminating one",
			faults[0].ErrorCode)
	}

	// The FAR must still be eligible. The record of what was programmed is what the
	// next pass differences against, so a refusal recorded as success is the end of
	// that interception — nothing re-derives it, because nothing has changed.
	e.retaskAndWait()

	select {
	case issue := <-reportedAt:
		reported = append(reported, issue)
		if issue != x1.NEIssueDuplicationRefused {
			t.Errorf("the retry was reported as %q, want %q", issue, x1.NEIssueDuplicationRefused)
		}
		if len(reported) != 2 {
			t.Errorf("the ADMF was told %d time(s), want twice: a write that is retried and "+
				"still unconfirmed is still an interception that may not be running", len(reported))
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the second re-derivation pushed nothing: the unconfirmed FAR was recorded as "+
			"programmed and has dropped out of the difference, so this interception will never "+
			"be retried. reported so far: %v", reported)
	}
}

// TestAnUnconfirmedFARDoesNotChangeWhatTheJoinIsTold pins both halves of the split at the
// level below, because they are separately revertible.
//
// addFAR must go on telling GRPCJoin the write succeeded -- that is upstream's contract and
// the reason an uncertain batch is not rejected -- while the batch separately records that
// it could not be confirmed. A change that made the worker report failure instead would
// pass the second assertion and break the first, which is precisely the regression this
// guards.
func TestAnUnconfirmedFARDoesNotChangeWhatTheJoinIsTold(t *testing.T) {
	b := bessWithNoDatapath(t)

	ctx, batch := withBatchConfirmation(t.Context())

	done := make(chan bool, 1)
	b.addFAR(ctx, done, far{farID: 1, fseID: 1, applyAction: ActionForward})

	select {
	case ok := <-done:
		if !ok {
			t.Error("addFAR reported a failure to the join for an RPC that did not complete: " +
				"the batch is then rejected, and the establishment handler forgets a session " +
				"whose rules the datapath may hold")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("addFAR signalled nothing")
	}

	if !batch.unconfirmed.Load() {
		t.Error("the write was not recorded as unconfirmed, so nothing downstream can tell it " +
			"apart from one the datapath acknowledged")
	}
}
