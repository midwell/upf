// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/omec-project/upf-epc/pfcpiface/metrics"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
	"github.com/wmnsk/go-pfcp/ie"
)

// teardownSEID is the session these tests tear down. Arbitrary, but fixed: the warrant names it.
const teardownSEID = uint64(0x51a7e5ea10c0ffee)

// deleteAnswer is one answer to a deletion batch: the cause, and whether the batch finished.
type deleteAnswer struct {
	cause    uint8
	finished bool
}

var (
	deleteRefused    = deleteAnswer{cause: ie.CauseRequestRejected, finished: true}
	deleteUnfinished = deleteAnswer{cause: ie.CauseRequestAccepted, finished: false}
	deleteDone       = deleteAnswer{cause: ie.CauseRequestAccepted, finished: true}
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
}

func (d *scriptedLIDeleteDP) SendMsgToUPFWithCompletion(
	method upfMsgType, all, updated PacketForwardingRules,
) (uint8, bool) {
	if method != upfMsgTypeDel {
		return d.liRefusingDP.SendMsgToUPFWithCompletion(method, all, updated)
	}

	d.scriptMu.Lock()
	defer d.scriptMu.Unlock()

	answer := deleteDone
	if len(d.deletes) > 0 {
		answer, d.deletes = d.deletes[0], d.deletes[1:]
	}

	return answer.cause, answer.finished
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

// TestATeardownOfAnUntaskedSessionReportsNothing: a refused delete of a session no warrant ever
// covered is the datapath's business, not the ADMF's -- reading the record must not turn routine
// PFCP churn into LI faults.
func TestATeardownOfAnUntaskedSessionReportsNothing(t *testing.T) {
	pConn, dp, _, reported := rejectionConn(t)

	pConn.Conn = teardownConn(t, nil).Conn
	pConn.shutdown = make(chan struct{})
	pConn.InstrumentPFCP = noopMetrics{}
	pConn.upf.datapath = &scriptedLIDeleteDP{liRefusingDP: dp, deletes: []deleteAnswer{deleteRefused}}

	s := unmarkedSession(teardownSEID, testUEIPv4)
	s.metrics = &metrics.Session{}

	if err := pConn.store.PutSession(s); err != nil {
		t.Fatal(err)
	}

	pConn.executeShutdown()

	if len(*reported) != 0 {
		t.Errorf("a refused removal of a session no warrant covered reported %v", *reported)
	}
}

// The two reports differ only in what they say happened, and an operator acts on that: a
// refusal and a removal that ran out of time point at different faults.
const (
	refusedWording     = "did not accept the removal of a duplication rule"
	unconfirmedWording = "did not confirm the removal of a duplication rule in time"
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
