// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
)

// divergeThenModify builds the one state in which the record's authority matters: a FAR the
// datapath is duplicating that this element's tasking says should not be duplicated.
//
// Reached the way it is reached in production — a warrant is withdrawn and the datapath refuses
// the write that turns duplication off. transact restores the record to what the datapath
// actually holds, which is the whole reason it keeps prior values rather than writing its
// intent. From here the record and the intent disagree, and every mechanism that reads one in
// place of the other becomes visible.
//
// Then the SMF modifies the session, restating FAR 1 and not FAR 2. Only FAR 1 reaches the
// datapath. What the element records about FAR 2 is the subject of both tests below.
func divergeThenModify(t *testing.T, f *enablerFixture) {
	t.Helper()

	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.activate(t, "W1", ueAddr("10.250.0.9"))
	f.settle(t)

	if !f.duplicates(t, 100, 1) || !f.duplicates(t, 100, 2) {
		t.Fatal("the tasked session is not duplicated, so nothing below is exercised")
	}

	// The datapath stops accepting, and the warrant is withdrawn. The write that would turn
	// duplication off is refused, so the datapath goes on duplicating both FARs.
	f.mu.Lock()
	f.cause = ie.CauseRequestRejected
	f.mu.Unlock()
	f.deactivate(t, "W1")
	f.settle(t)

	if !f.duplicates(t, 100, 1) || !f.duplicates(t, 100, 2) {
		t.Fatal("the fake datapath applied a write it refused; this fixture is not modelling a " +
			"refusal and the divergence this test needs does not exist")
	}
	for _, farID := range []uint32{1, 2} {
		if value, held := f.recorded(100, farID); !held || !value {
			t.Fatalf("after a refused withdrawal the record for FAR %d says held=%v duplicating=%v; "+
				"it must still describe the datapath, which is duplicating", farID, held, value)
		}
	}

	// The modification. There is no tasking now, so applyTasking marks nothing: the session's
	// own FARs all read "not duplicating", which is this element's *intent* and not the
	// datapath's state.
	sess, ok := f.store.GetSession(100)
	if !ok {
		t.Fatal("the session went missing")
	}
	restated := far{farID: 1, fseID: 100, applyAction: ActionForward}
	for i := range sess.fars {
		if sess.fars[i].farID == 1 {
			sess.fars[i] = restated
		} else {
			sess.fars[i].liDuplicate = false
		}
	}
	pushed := PacketForwardingRules{fars: []far{restated}}
	f.e.applyTasking(&sess, &pushed)
	f.record(pushed)
	f.commitModification(t, sess, pushed.fars)
}

// TestAPartialModificationLeavesTheOtherRulesRecordAlone: the record says what the datapath was
// told, not what this element wants.
//
// A Session Modification restates only the rules the SMF is changing, and its copies carry no
// notion of duplication. The handler pushes those and only those — so a record rewritten from
// the session's whole FAR list claims the datapath was told this element's intended value for
// every rule the message did not contain.
//
// **The error runs in the one direction that cannot be recovered from.** A FAR still duplicating
// whose record says otherwise is invisible to the next pass: the pass compares the record
// against the tasking, and where the tasking agrees, concludes there is nothing to do. The
// copies go on being made under no warrant, and the element's own account says duplication is
// off — over-collection recorded as compliance.
func TestAPartialModificationLeavesTheOtherRulesRecordAlone(t *testing.T) {
	f := newEnablerFixture(t)
	divergeThenModify(t, f)

	if value, held := f.recorded(100, 2); !held || !value {
		t.Errorf("a FAR the modification never pushed is recorded as held=%v duplicating=%v, and "+
			"the datapath is duplicating it. The record is this element's only account of what "+
			"the datapath holds, and it now describes what the element wanted instead",
			held, value)
	}
}

// TestARuleLeftUnpushedIsStillProgrammedOffWhenTheDatapathRecovers is the consequence.
//
// The record earns its keep at exactly one moment: a pass turning duplication off skips any FAR
// whose recorded value already equals what the tasking implies. A FAR recorded as "not
// duplicating" while the datapath duplicates it is therefore never pushed off — the warrant is
// gone, the copies continue, and nothing in the element will ask about that FAR again.
func TestARuleLeftUnpushedIsStillProgrammedOffWhenTheDatapathRecovers(t *testing.T) {
	f := newEnablerFixture(t)
	divergeThenModify(t, f)

	// The datapath starts accepting writes again, and something asks for a re-derivation — a
	// tasking change, or the periodic one. There is no tasking, so nothing should be duplicated.
	f.mu.Lock()
	f.cause = 0
	f.mu.Unlock()
	f.e.retaskAndWait()
	f.settle(t)

	if f.duplicates(t, 100, 1) {
		t.Error("the restated FAR is still duplicating with no warrant in place")
	}
	if f.duplicates(t, 100, 2) {
		t.Error("a FAR the modification did not push is still duplicating with no warrant in " +
			"place: its record said duplication was already off, so the pass that turns it off " +
			"had nothing to do. Content is being copied under no warrant at all, and nothing " +
			"left in this element can turn it off")
	}
}
