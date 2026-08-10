// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net"
	"testing"

	"github.com/omec-project/pfcpsim/pkg/pfcpsim/session"
	"github.com/omec-project/upf-epc/pkg/fake_bess"
	"github.com/wmnsk/go-pfcp/ie"
)

// Datapath action values the PFCP agent installs into the BESS farLookup table.
// These mirror the (unexported) farForward* constants in pfcpiface and the
// executeFAR gate numbers in the .bess pipeline configuration.
const (
	bessForwardD             uint8 = 0x0
	bessForwardU             uint8 = 0x1
	bessForwardDAndDuplicate uint8 = 0x5
	bessForwardUAndDuplicate uint8 = 0x6
)

// FAR IDs installed by testUEAttach: 1 forwards uplink, 2 forwards downlink.
const (
	uplinkFARID   uint32 = 1
	downlinkFARID uint32 = 2
)

// TestLawfulInterceptDuplicateFAR exercises the UPF's content-of-communication
// trigger over real PFCP: a FAR carrying the DUPL apply-action must install the
// forward-and-duplicate datapath action, which is what routes the packet through
// the LI X3 tee while the subscriber's copy keeps its direction. It covers
// mid-session activation and deactivation — the SMF sets or clears DUPL on the
// forwarding FARs of an already-established session and sends a modification, so
// the datapath action must flip both ways without disturbing the rest of the
// session.
func TestLawfulInterceptDuplicateFAR(t *testing.T) {
	setup(t, ConfigDefault)
	defer teardown(t)

	tc := testCase{
		input: &pfcpSessionData{
			sliceID:      1,
			nbAddress:    nodeBAddress,
			ueAddress:    ueAddress,
			upfN3Address: upfN3Address,
			sdfFilter:    defaultSDFFilter,
			ulTEID:       15,
			dlTEID:       16,

			QFI:              0x09,
			uplinkAppQerID:   1,
			downlinkAppQerID: 2,
			sessQerID:        4,
			sessGBR:          0,
			sessMBR:          500000,
			appGBR:           30000,
			appMBR:           50000,
		},
		expected: ueSessionConfig{
			appFilter: appFilter{
				proto:        0x11,
				appIP:        net.ParseIP("0.0.0.0"),
				appPrefixLen: 0,
				appPort: portRange{
					80, 80,
				},
			},
			tc: 3,
		},
	}

	testcase := fillExpected(&tc)
	testUEAttach(t, testcase)

	// Untasked subscriber: plain forwarding, no tee.
	assertFARAction(t, "no warrant", uplinkFARID, bessForwardU)
	assertFARAction(t, "no warrant", downlinkFARID, bessForwardD)

	// Mid-session CC activation: the SMF sets DUPL on both forwarding FARs.
	modifyForwardingFARs(t, testcase, ActionForward|ActionDuplicate, "activate")

	assertFARAction(t, "CC warrant active", uplinkFARID, bessForwardUAndDuplicate)
	assertFARAction(t, "CC warrant active", downlinkFARID, bessForwardDAndDuplicate)
	// The subscriber's own traffic must be unaffected on the wire. The downlink
	// one is the case that mattered: an undefined PDU type here crashed the RAN.
	assertFARPduType(t, "CC warrant active", uplinkFARID, bessForwardU)
	assertFARPduType(t, "CC warrant active", downlinkFARID, bessForwardD)
	// Duplication must not add, remove, or reshape any other session state.
	verifyEntries(t, testcase.expected)

	// Deactivation: DUPL is cleared once no CC warrant targets the session.
	modifyForwardingFARs(t, testcase, ActionForward, "deactivate")

	assertFARAction(t, "warrant deactivated", uplinkFARID, bessForwardU)
	assertFARAction(t, "warrant deactivated", downlinkFARID, bessForwardD)
	verifyEntries(t, testcase.expected)

	testUEDetach(t, testcase)
}

// modifyForwardingFARs updates both of the session's forwarding FARs with the
// given apply-action, as the SMF does when a CC warrant is activated or
// deactivated for a live session.
func modifyForwardingFARs(t *testing.T, testcase *testCase, action uint8, when string) {
	t.Helper()

	fars := []*ie.IE{
		session.NewFARBuilder().
			WithMethod(session.Update).WithID(uplinkFARID).
			WithDstInterface(ie.DstInterfaceCore).
			WithAction(action).BuildFAR(),
		session.NewFARBuilder().
			WithMethod(session.Update).WithID(downlinkFARID).
			WithDstInterface(ie.DstInterfaceAccess).
			WithAction(action).
			WithTEID(testcase.input.dlTEID).
			WithDownlinkIP(testcase.input.nbAddress).BuildFAR(),
	}

	if err := pfcpClient.ModifySession(testcase.session, nil, fars, nil, nil); err != nil {
		t.Fatalf("failed to modify PFCP session (%s): %v", when, err)
	}
}

// assertFARAction checks the value the pipeline's executeFAR splits on, which is
// where content duplication is signalled.
//
// Deliberately not ActionValue(): that is the attribute BESS's GtpuEncap also
// reads as the GTP-U PDU Session Container PDU Type, so it must never carry a
// duplication variant. assertFARPduType covers that half.
func assertFARAction(t *testing.T, when string, farID uint32, want uint8) {
	t.Helper()

	far := farOrFail(t, when, farID)

	if got := far.ForwardActionValue(); got != want {
		t.Errorf("%s: FAR %d datapath forward action = %#x, want %#x", when, farID, got, want)
	}
}

// assertFARPduType checks that whatever the FAR is doing, the value GtpuEncap
// turns into the GTP-U PDU Session Container PDU Type stays one of the two the
// wire format defines. A duplication value here reaches the RAN as an undefined
// PDU type, which crashed it.
func assertFARPduType(t *testing.T, when string, farID uint32, want uint8) {
	t.Helper()

	far := farOrFail(t, when, farID)

	if got := far.ActionValue(); got != want {
		t.Errorf("%s: FAR %d PDU-type-bearing action = %#x, want %#x", when, farID, got, want)
	}
}

func farOrFail(t *testing.T, when string, farID uint32) fake_bess.FakeFar {
	t.Helper()

	fars := bessFake.GetFarTableEntries()

	far, found := fars[farID]
	if !found {
		t.Fatalf("%s: FAR %d not installed in the datapath (entries: %v)", when, farID, fars)
	}

	return far
}
