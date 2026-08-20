// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"strings"
	"testing"

	"github.com/omec-project/li/types"
)

// TestAWorkingTaskReportsNoFault comes first, because a supplier that reports a fault for
// everything satisfies every assertion below and is worthless.
func TestAWorkingTaskReportsNoFault(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.activate(t, "W1", ueAddr("10.250.0.9"))

	if !f.duplicates(t, 100, 1) {
		t.Fatal("the tasked session is not duplicated, so this test would pass for the wrong reason")
	}
	if faults := f.e.taskFaults("W1"); len(faults) != 0 {
		t.Errorf("a task whose traffic is being duplicated reports %d fault(s): %+v — a fault list "+
			"must be evidence of a fault rather than of the element having something to say",
			len(faults), faults)
	}
}

// TestATaskTheDatapathIsNotDuplicatingReportsAFault is the condition this supplier exists for.
//
// The datapath refuses the write, so nothing is duplicated and no copy is made — and until now
// the only account of that was an element-scoped report saying something at this point of
// interception was refused. A triggering function holding several warrants could not tell which
// of them had stopped producing.
func TestATaskTheDatapathIsNotDuplicatingReportsAFault(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))

	// The datapath refuses everything from here on.
	f.mu.Lock()
	f.cause = 64 // CauseRequestRejected
	f.mu.Unlock()

	f.activate(t, "W1", ueAddr("10.250.0.9"))
	f.settle(t)

	if f.duplicates(t, 100, 1) {
		t.Fatal("the fake datapath recorded a write it refused, so this test is asserting against " +
			"a datapath that accepted the rule")
	}

	faults := f.e.taskFaults("W1")
	if len(faults) == 0 {
		t.Fatal("a task whose duplication the datapath refused reports no fault, so a triggering " +
			"function is told the task is provisioned and carrying no faults while it produces nothing")
	}
	if !strings.Contains(faults[0].ErrorDescription, "not duplicating") {
		t.Errorf("the fault does not say what is wrong: %q", faults[0].ErrorDescription)
	}
	if faults[0].ErrorCode == 0 {
		t.Error("the fault carries no issue code, so it cannot be correlated with the pushed report")
	}
}

// TestATaskFaultIsAttributedToOneWarrant: two warrants, one session each, and only one of them
// refused. An answer that named both would be no more useful to a triggering function than the
// element-scoped report it already had.
func TestATaskFaultIsAttributedToOneWarrant(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.activate(t, "W1", ueAddr("10.250.0.9"))
	f.settle(t)

	if !f.duplicates(t, 100, 1) {
		t.Fatal("the first warrant's session is not duplicated")
	}

	// Now the datapath starts refusing, and a second warrant arrives.
	f.putSession(t, unmarkedSession(200, "10.250.0.10"))
	f.mu.Lock()
	f.cause = 64
	f.mu.Unlock()
	f.activate(t, "W2", ueAddr("10.250.0.10"))
	f.settle(t)

	if got := f.e.taskFaults("W2"); len(got) == 0 {
		t.Error("the refused warrant reports no fault")
	}
	if got := f.e.taskFaults("W1"); len(got) != 0 {
		t.Errorf("the warrant that is working reports %+v; a triggering function acting on this "+
			"would report triggerFaulty for a warrant whose interception is running", got)
	}
}

// TestATaskSelectingNoSessionSaysSo covers the other re-observable condition. A CC-POI's task is
// installed against traffic that exists, so a task selecting nothing is an interception
// producing nothing — which is exactly what a triggering function has no other way to learn,
// since a copy that is never made leaves no record anywhere.
func TestATaskSelectingNoSessionSaysSo(t *testing.T) {
	f := newEnablerFixture(t)
	f.activate(t, "W1", ueAddr("10.250.0.9"))

	faults := f.e.taskFaults("W1")
	if len(faults) == 0 {
		t.Fatal("a task no session carries traffic for reports nothing, so the element answers " +
			"that it is provisioned and has no faults while intercepting nothing")
	}
	if !strings.Contains(faults[0].ErrorDescription, "producing nothing") {
		t.Errorf("the fault does not say what was observed: %q", faults[0].ErrorDescription)
	}

	// And it clears by itself when the session appears: the answer is computed, so nothing has
	// to remember to retract it. This is the half a stored fault gets wrong.
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.e.retaskAndWait()
	f.settle(t)
	if got := f.e.taskFaults("W1"); len(got) != 0 {
		t.Errorf("the fault outlived the condition: %+v", got)
	}
}

// TestATaskFaultNamesNoSubject: the answer is scoped to the task, so it already identifies the
// warrant. The description is the only free-form field in it, and a criterion is a subject
// identifier — an address, a TEID, a SEID — so an implementation that quoted the criterion it
// resolved would put the subject on the X1 interface.
func TestATaskFaultNamesNoSubject(t *testing.T) {
	const ueIP = "10.250.0.9"

	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, ueIP))
	f.mu.Lock()
	f.cause = 64
	f.mu.Unlock()
	f.activate(t, "W1", ueAddr(ueIP))
	f.settle(t)

	faults := f.e.taskFaults("W1")
	if len(faults) == 0 {
		t.Fatal("no fault to check")
	}
	for _, fault := range faults {
		if strings.Contains(fault.ErrorDescription, ueIP) {
			t.Errorf("the fault names the subject's address (%q): %q", ueIP, fault.ErrorDescription)
		}
		if strings.Contains(fault.ErrorDescription, "100") {
			t.Errorf("the fault names the session identifier: %q", fault.ErrorDescription)
		}
	}
}

// TestATaskTheElementDoesNotHoldReportsNothing: a fault answered for an unknown XID would be a
// claim about a warrant this element was never given.
func TestATaskTheElementDoesNotHoldReportsNothing(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	f.activate(t, "W1", ueAddr("10.250.0.9"))

	if got := f.e.taskFaults(types.XID("W-never-installed")); len(got) != 0 {
		t.Errorf("the element answered %+v about a task it does not hold", got)
	}
}
