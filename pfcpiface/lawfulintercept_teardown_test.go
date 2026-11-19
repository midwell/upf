// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/omec-project/upf-epc/pfcpiface/metrics"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// teardownSEID is the session these tests tear down. Arbitrary, but fixed: the warrant names it.
const teardownSEID = uint64(0x51a7e5ea10c0ffee)

// deleteAnswer is one answer to a deletion batch: the cause, whether the batch finished, and
// whether a FAR delete in it went unanswered.
type deleteAnswer struct {
	cause       uint8
	finished    bool
	unconfirmed bool
}

var (
	deleteRefused    = deleteAnswer{cause: ie.CauseRequestRejected, finished: true}
	deleteUnfinished = deleteAnswer{cause: ie.CauseRequestAccepted, finished: false}
	deleteDone       = deleteAnswer{cause: ie.CauseRequestAccepted, finished: true}
	// deleteUnanswered is what BESS gives for a FAR delete whose RPC returned Unavailable or
	// DeadlineExceeded: the worker still signals the join, so the batch is accepted and
	// finished, and only the confirmation says the rule may still be there.
	deleteUnanswered = deleteAnswer{cause: ie.CauseRequestAccepted, finished: true, unconfirmed: true}
)

// scriptedLIDeleteDP answers deletion batches from a script, in order, and leaves what the
// datapath duplicates untouched by any delete that did not finish cleanly -- a refused or
// unfinished removal is exactly the one whose rules may survive. Everything else, including the
// enabler's pushes, goes to the refusing datapath it wraps. The teardown retry sends its batches
// concurrently, so the script is locked.
type scriptedLIDeleteDP struct {
	*liRefusingDP

	scriptMu sync.Mutex
	deletes  []deleteAnswer
	// asked counts the deletion batches, so a test can tell a retry from none.
	asked int
}

func (d *scriptedLIDeleteDP) SendMsgToUPFWithCompletion(
	method upfMsgType, all, updated PacketForwardingRules,
) (uint8, bool) {
	if method != upfMsgTypeDel {
		return d.liRefusingDP.SendMsgToUPFWithCompletion(method, all, updated)
	}

	answer := d.next()

	return answer.cause, answer.finished
}

// sendMsgToUPFRemoval makes this fake a removingDatapath, as BESS is, so a deletion can come
// back accepted and finished with its FAR delete unanswered.
func (d *scriptedLIDeleteDP) sendMsgToUPFRemoval(PacketForwardingRules) (uint8, bool, bool) {
	answer := d.next()

	return answer.cause, answer.finished,
		answer.finished && answer.cause == ie.CauseRequestAccepted && !answer.unconfirmed
}

func (d *scriptedLIDeleteDP) next() deleteAnswer {
	d.scriptMu.Lock()
	defer d.scriptMu.Unlock()

	d.asked++

	answer := deleteDone
	if len(d.deletes) > 0 {
		answer, d.deletes = d.deletes[0], d.deletes[1:]
	}

	return answer
}

func (d *scriptedLIDeleteDP) deletesAsked() int {
	d.scriptMu.Lock()
	defer d.scriptMu.Unlock()

	return d.asked
}

// teardownWithDuplicationTurnedOnLater is an association holding one session that was
// established with no warrant covering it, and that a warrant activated afterwards turned on --
// so duplication was enabled by a re-derivation pass, which writes the element's record and not
// the session store. That is the ordinary operational order (the UE attaches, then the warrant
// arrives), and it is the one where the stored session's FARs all still say liDuplicate=false
// while the datapath duplicates.
//
// The precondition is asserted rather than assumed: if a later change makes the pass write the
// store too, these tests would otherwise go on passing without exercising the gap they exist for.
func teardownWithDuplicationTurnedOnLater(
	t *testing.T, deletes ...deleteAnswer,
) (*PFCPConn, *[]string, *[]string) {
	t.Helper()

	pConn, dp, e, reported, described := rejectionConnDescribed(t)

	// executeShutdown reads the peer address and closes the socket, and RemoveSession saves
	// the session's metrics.
	pConn.Conn = teardownConn(t, nil).Conn
	pConn.shutdown = make(chan struct{})
	pConn.InstrumentPFCP = noopMetrics{}
	pConn.upf.datapath = &scriptedLIDeleteDP{liRefusingDP: dp, deletes: deletes}

	s := unmarkedSession(teardownSEID, testUEIPv4)
	s.metrics = &metrics.Session{}

	if err := pConn.store.PutSession(s); err != nil {
		t.Fatal(err)
	}

	if !e.tasks.Activate(types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
		Targets: []types.TargetIdentifier{
			{Type: types.TargetFSEID, Value: strconv.FormatUint(teardownSEID, 10)},
		},
	}) {
		t.Fatal("Activate failed")
	}

	e.retaskAndWait()

	dp.mu.Lock()
	duplicating := dp.duplicating[1] || dp.duplicating[2]
	dp.mu.Unlock()

	if !duplicating {
		t.Fatal("precondition: the warrant did not turn duplication on, so nothing here " +
			"would test a teardown of a duplicating session")
	}

	stored, ok := pConn.store.GetSession(teardownSEID)
	if !ok {
		t.Fatal("precondition: the session is not stored")
	}

	for _, f := range stored.fars {
		if f.liDuplicate {
			t.Fatal("precondition: the stored session says it is duplicating, so this is not " +
				"the case where only the element's record knows")
		}
	}

	*reported, *described = nil, nil

	return pConn, reported, described
}

// TestATeardownReportsARefusedRemovalOfDuplicationTurnedOnLater is the gap: a warrant activated
// after attach, an association teardown, and a datapath that refuses the delete. The rules stay,
// the session is forgotten, and nothing can stop the copies -- which is what the report exists to
// say. Gating it on the stored session's flag kept it silent for exactly this session.
func TestATeardownReportsARefusedRemovalOfDuplicationTurnedOnLater(t *testing.T) {
	pConn, reported, described := teardownWithDuplicationTurnedOnLater(t, deleteRefused)

	pConn.executeShutdown()

	assertOneAbandonedReport(t, *reported, *described, "a refused teardown removal", refusedWording)
}

// TestATeardownReportsARefusedRetryOfDuplicationTurnedOnLater: the first removal ran out of time,
// and the retry was refused. Same gap, on the second pass.
func TestATeardownReportsARefusedRetryOfDuplicationTurnedOnLater(t *testing.T) {
	pConn, reported, described := teardownWithDuplicationTurnedOnLater(t, deleteUnfinished, deleteRefused)

	pConn.executeShutdown()

	assertOneAbandonedReport(t, *reported, *described, "a refused teardown retry", refusedWording)
}

// TestATeardownReportsARemovalOfDuplicationThatNeverFinished: neither the removal nor its retry
// finished. The address is held because a surviving rule may still match it; a surviving
// duplication rule is the same uncertainty, and once the session is forgotten it has no other
// representation anywhere.
func TestATeardownReportsARemovalOfDuplicationThatNeverFinished(t *testing.T) {
	pConn, reported, described := teardownWithDuplicationTurnedOnLater(t, deleteUnfinished, deleteUnfinished)

	pConn.executeShutdown()

	assertOneAbandonedReport(t, *reported, *described, "a teardown removal that never finished",
		unconfirmedWording)
}

// TestATeardownRetriesAFARDeleteThatWasNotAnswered: the first removal finished, but the delete of
// a FAR that may be duplicating was not answered. That batch is accepted and finished, so the
// teardown used to forget the session there; it is retried with the unfinished ones instead, and
// a retry that removes the rule leaves nothing to report.
func TestATeardownRetriesAFARDeleteThatWasNotAnswered(t *testing.T) {
	pConn, reported, _ := teardownWithDuplicationTurnedOnLater(t, deleteUnanswered, deleteDone)
	dp := pConn.upf.datapath.(*scriptedLIDeleteDP)

	pConn.executeShutdown()

	if n := dp.deletesAsked(); n != 2 {
		t.Errorf("the teardown asked for %d removals, want 2: a removal whose FAR delete was "+
			"not answered was taken as done, and the session forgotten while its duplication "+
			"rule may still be in the datapath", n)
	}

	if len(*reported) != 0 {
		t.Errorf("a retry that removed the rule still reported %v", *reported)
	}
}

// TestATeardownReportsAFARDeleteThatWasNeverAnswered: neither the removal nor its retry had its FAR
// delete answered, so the session is forgotten with its duplication rule possibly in place.
func TestATeardownReportsAFARDeleteThatWasNeverAnswered(t *testing.T) {
	pConn, reported, described := teardownWithDuplicationTurnedOnLater(t, deleteUnanswered, deleteUnanswered)

	pConn.executeShutdown()

	assertOneAbandonedReport(t, *reported, *described, "a teardown whose FAR delete was never "+
		"answered", unconfirmedWording)
}

// TestASessionDeletionReportsAFARDeleteThatWasNotAnswered: the SMF deletes a duplicating session
// and the FAR delete is not answered. The deletion is still accepted, as before, but the record is
// dropped with the session, so the ADMF is told.
func TestASessionDeletionReportsAFARDeleteThatWasNotAnswered(t *testing.T) {
	pConn, reported, described := teardownWithDuplicationTurnedOnLater(t, deleteUnanswered)

	if _, err := pConn.handleSessionDeletionRequest(
		message.NewSessionDeletionRequest(0, 0, teardownSEID, 3, 0)); err != nil {
		t.Fatalf("the deletion was refused: %v", err)
	}

	assertOneAbandonedReport(t, *reported, *described, "a session deletion whose FAR delete "+
		"was not answered", unconfirmedWording)
}

// TestALocalDeletionReportsAFARDeleteThatWasNotAnswered: the session-report-response path deletes
// the session locally, with the same consequence as the SMF's deletion.
func TestALocalDeletionReportsAFARDeleteThatWasNotAnswered(t *testing.T) {
	pConn, reported, described := teardownWithDuplicationTurnedOnLater(t, deleteUnanswered)

	if err := pConn.handleSessionReportResponse(message.NewSessionReportResponse(0, 0, teardownSEID, 1, 0,
		ie.NewCause(ie.CauseSessionContextNotFound))); err != nil {
		t.Fatalf("the local deletion was refused: %v", err)
	}

	if _, held := pConn.store.GetSession(teardownSEID); held {
		t.Fatal("precondition: the session was not deleted locally")
	}

	assertOneAbandonedReport(t, *reported, *described, "a local deletion whose FAR delete "+
		"was not answered", unconfirmedWording)
}

// TestARefusedEstablishmentReportsARollbackThatWasNotAnswered: a warrant covers the UE, the
// establishment is refused, and the rollback's FAR delete is not answered. The session is never
// stored, so a duplication rule the rollback left is reported.
func TestARefusedEstablishmentReportsARollbackThatWasNotAnswered(t *testing.T) {
	pConn, dp, e, _, described := rejectionConnDescribed(t)

	const ue = "10.250.0.17"

	if !e.tasks.Activate(types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
		Targets:  []types.TargetIdentifier{ueAddr(ue)},
	}) {
		t.Fatal("Activate failed")
	}

	e.reparse()

	dp.mu.Lock()
	dp.refuse = true
	dp.mu.Unlock()

	pConn.upf.datapath = &scriptedLIDeleteDP{liRefusingDP: dp, deletes: []deleteAnswer{deleteUnanswered}}

	_, err := pConn.handleSessionEstablishmentRequest(
		message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
			ie.NewNodeID("1.1.1.1", "", ""),
			ie.NewFSEID(203, net.ParseIP("1.1.1.1"), nil),
			ie.NewCreatePDR(
				ie.NewPDRID(1),
				ie.NewPrecedence(0),
				ie.NewPDI(
					ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x2, ue, "", 0, 0),
				),
				ie.NewFARID(1),
			),
			ie.NewCreateFAR(
				ie.NewFARID(1),
				ie.NewApplyAction(ActionForward),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess)),
			),
		))
	if err == nil {
		t.Fatal("the refused establishment was reported as succeeding")
	}

	if n := len(pConn.store.GetAllSessions()); n != 0 {
		t.Fatalf("the handler holds %d sessions; this test is about the branch that forgets it", n)
	}

	for _, d := range *described {
		if strings.Contains(d, unconfirmedWording) && strings.Contains(d, "a refused session establishment") {
			return
		}
	}

	t.Errorf("a refused establishment whose rollback left its FAR delete unanswered was forgotten "+
		"without saying so. Reported: %v", *described)
}

// TestATeardownThatRemovedTheDuplicationReportsNothing: the removal finished, late or not, so
// nothing was abandoned and the ADMF hears nothing.
func TestATeardownThatRemovedTheDuplicationReportsNothing(t *testing.T) {
	for _, tt := range []struct {
		name    string
		deletes []deleteAnswer
	}{
		{"removed at once", []deleteAnswer{deleteDone}},
		{"removed on the retry", []deleteAnswer{deleteUnfinished, deleteDone}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pConn, reported, _ := teardownWithDuplicationTurnedOnLater(t, tt.deletes...)

			pConn.executeShutdown()

			if len(*reported) != 0 {
				t.Errorf("a teardown whose removal finished reported %v", *reported)
			}
		})
	}
}

// TestATeardownOfAnUntaskedSessionReportsNothing: a refused or unanswered delete of a session no
// warrant ever covered is the datapath's business, not the ADMF's -- reading the record must not
// turn routine PFCP churn into LI faults. Nor is an unanswered one retried: a UPF without LI tears
// down as it did before.
func TestATeardownOfAnUntaskedSessionReportsNothing(t *testing.T) {
	for _, answer := range []deleteAnswer{deleteRefused, deleteUnanswered} {
		pConn, dp, _, reported := rejectionConn(t)

		pConn.Conn = teardownConn(t, nil).Conn
		pConn.shutdown = make(chan struct{})
		pConn.InstrumentPFCP = noopMetrics{}
		scripted := &scriptedLIDeleteDP{liRefusingDP: dp, deletes: []deleteAnswer{answer}}
		pConn.upf.datapath = scripted

		s := unmarkedSession(teardownSEID, testUEIPv4)
		s.metrics = &metrics.Session{}

		if err := pConn.store.PutSession(s); err != nil {
			t.Fatal(err)
		}

		pConn.executeShutdown()

		if len(*reported) != 0 {
			t.Errorf("%+v: a removal of a session no warrant covered reported %v", answer, *reported)
		}

		if n := scripted.deletesAsked(); n != 1 {
			t.Errorf("%+v: an untasked session's removal was asked %d times, want 1", answer, n)
		}
	}
}

// The two reports differ only in what they say happened, and an operator acts on that: a
// refusal and a removal that ran out of time point at different faults.
const (
	refusedWording     = "did not accept the removal of a duplication rule"
	unconfirmedWording = "did not confirm the removal of a duplication rule"
)

func assertOneAbandonedReport(t *testing.T, reported, described []string, what, wording string) {
	t.Helper()

	if len(reported) != 1 {
		t.Fatalf("%s of a duplicating session reported %v, want exactly one %q: the session "+
			"is forgotten and its rules may still be copying a subscriber's traffic with "+
			"nothing able to stop them", what, reported, x1.NEIssueDuplicationRefused)
	}

	if reported[0] != x1.NEIssueDuplicationRefused {
		t.Errorf("%s reported %q, want %q", what, reported[0], x1.NEIssueDuplicationRefused)
	}

	if !strings.Contains(described[0], wording) {
		t.Errorf("%s was described as %q, want it to say it %q", what, described[0], wording)
	}
}
