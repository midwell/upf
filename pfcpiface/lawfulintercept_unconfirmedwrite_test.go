// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import "testing"

// A modification whose push the datapath refuses leaves this element unable to say whether
// the rules were applied. What it records about that write decides whether it ever tries
// again: transact skips a FAR whose record already agrees with the tasking unless the
// answer is "off", so a record claiming the rules are duplicating agrees with a live task
// and every later pass skips it — for the life of the session.
//
// The subject then has a warrant against them producing nothing, and an element answering
// that it is healthy, which an agency cannot distinguish from a subject who has gone quiet.
func TestARefusedModificationIsRewrittenByTheNextPass(t *testing.T) {
	f := newEnablerFixture(t)
	sess := unmarkedSession(100, "10.250.0.9")
	f.putSession(t, sess)

	task := ccTask("W1", ueAddr("10.250.0.9"))
	if err := f.e.canApply(task); err != nil {
		t.Fatalf("canApply: %v", err)
	}
	if !f.tasks.Activate(task) {
		t.Fatal("Activate failed")
	}

	// The handler re-derives over the modification and pushes the changed subset. The
	// datapath refuses and — on this branch — nothing lands, so f.record is not called.
	modified := sess
	modified.fars = append([]far(nil), sess.fars...)
	updated := PacketForwardingRules{fars: append([]far(nil), modified.fars...)}
	f.e.applyTasking(&modified, &updated)

	// This is the whole of what the handler does on the refused branch: it returns before
	// PutSession, so sessionProgrammed never runs.
	f.e.farsAttempted(100, updated.fars)

	// Not fatal: the record is the mechanism, the rewrite below is the harm. Failing here
	// and stopping would leave the harm unproven, and it is the harm that matters.
	if value, held := f.recorded(100, 1); !held || value {
		t.Errorf("FAR 1 recorded as (duplicating=%v, held=%v) after a write whose outcome is "+
			"unknown; a record that claims the write landed is what stops the element retrying",
			value, held)
	}

	// A later pass runs — a session event, a tasking change, anything.
	f.e.request()
	f.settle(t)

	if !f.duplicates(t, 100, 1) {
		t.Fatal("the element never rewrote the rules, so the warrant produces nothing and " +
			"no later pass will look again")
	}
}

// The converse, without which the test above could be satisfied by rewriting everything on
// every pass — which would be unbounded datapath churn rather than a fix.
func TestAConfirmedWriteIsNotRewritten(t *testing.T) {
	f := newEnablerFixture(t)
	sess := unmarkedSession(101, "10.250.0.10")
	f.putSession(t, sess)

	task := ccTask("W1", ueAddr("10.250.0.10"))
	if err := f.e.canApply(task); err != nil {
		t.Fatalf("canApply: %v", err)
	}
	if !f.tasks.Activate(task) {
		t.Fatal("Activate failed")
	}

	modified := sess
	modified.fars = append([]far(nil), sess.fars...)
	updated := PacketForwardingRules{fars: append([]far(nil), modified.fars...)}
	f.e.applyTasking(&modified, &updated)
	f.record(updated)
	f.e.farsPushed(101, updated.fars)

	if !f.duplicates(t, 101, 1) {
		t.Fatal("the fixture did not start the interception")
	}

	before := f.pushCount()
	f.e.request()
	f.settle(t)

	if after := f.pushCount(); after != before {
		t.Errorf("a confirmed write was rewritten: pushes %d -> %d, with the tasking unchanged",
			before, after)
	}
}

// The protection that must survive the change above. A rule this element ever turned on is
// never trusted-to-be-off again, whatever the record says — that is what keeps a subscriber
// from being copied under no authority, and recording an unconfirmed write as "off" must
// not have weakened it.
func TestAnEverDuplicatedFARIsStillTurnedOffWhateverTheRecordSays(t *testing.T) {
	f := newEnablerFixture(t)
	sess := unmarkedSession(102, "10.250.0.11")
	f.putSession(t, sess)

	task := ccTask("W1", ueAddr("10.250.0.11"))
	if err := f.e.canApply(task); err != nil {
		t.Fatalf("canApply: %v", err)
	}
	if !f.tasks.Activate(task) {
		t.Fatal("Activate failed")
	}

	modified := sess
	modified.fars = append([]far(nil), sess.fars...)
	updated := PacketForwardingRules{fars: append([]far(nil), modified.fars...)}
	f.e.applyTasking(&modified, &updated)
	f.record(updated)

	// The refused branch records it as attempted, which leaves the record saying "off" while
	// the datapath is duplicating — the state the whole bounding remedy exists for.
	f.e.farsAttempted(102, updated.fars)

	if !f.duplicates(t, 102, 1) {
		t.Fatal("the fixture did not start the interception")
	}

	f.deactivate(t, "W1")
	f.settle(t)

	if f.duplicates(t, 102, 1) {
		t.Fatal("the withdrawal did not reach the datapath: a record saying \"off\" was trusted " +
			"for a FAR this element had turned on, so the subscriber is still being copied")
	}
}
