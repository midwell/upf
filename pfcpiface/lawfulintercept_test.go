// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"bytes"
	"net"
	"testing"

	"github.com/omec-project/li/x2x3"
	"github.com/omec-project/upf-epc/logger"
	"github.com/wmnsk/go-pfcp/ie"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestParseFARDuplicate checks that a FAR carrying the DUPL apply-action plus
// Duplicating Parameters is recognised for Lawful Interception, and that a plain
// forwarding FAR is not.
func TestParseFARDuplicate(t *testing.T) {
	mockUpf := &upf{accessIP: net.ParseIP("192.168.0.1"), coreIP: net.ParseIP("10.0.10.1")}

	dupFAR := &far{}
	in := ie.NewCreateFAR(
		ie.NewFARID(7),
		ie.NewApplyAction(ActionForward|ActionDuplicate),
		ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess)),
		ie.NewDuplicatingParameters(ie.NewDestinationInterface(ie.DstInterfaceLIFunction)),
	)
	if err := dupFAR.parseFAR(in, 100, mockUpf, create); err != nil {
		t.Fatalf("parseFAR (dup): %v", err)
	}
	if !dupFAR.Duplicates() {
		t.Errorf("DUPL FAR: Duplicates() = false, want true")
	}
	if !dupFAR.Forwards() {
		t.Error("DUPL FAR must still forward the subscriber copy")
	}

	plainFAR := &far{}
	plain := ie.NewCreateFAR(
		ie.NewFARID(8),
		ie.NewApplyAction(ActionForward),
		ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess)),
	)
	if err := plainFAR.parseFAR(plain, 100, mockUpf, create); err != nil {
		t.Fatalf("parseFAR (plain): %v", err)
	}
	if plainFAR.Duplicates() {
		t.Error("plain forwarding FAR must not be marked for duplication")
	}
}

// TestParseFARDuplicateIsSilent enforces undetectability: parsing a DUPL (LI)
// FAR must emit no log output, so a tasked subscriber's session is
// indistinguishable from any other in the UPF's logs.
func TestParseFARDuplicateIsSilent(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	orig := logger.PfcpLog
	logger.PfcpLog = zap.New(core).Sugar()
	t.Cleanup(func() { logger.PfcpLog = orig })

	mockUpf := &upf{accessIP: net.ParseIP("192.168.0.1"), coreIP: net.ParseIP("10.0.10.1")}
	dup := &far{}
	in := ie.NewCreateFAR(
		ie.NewFARID(7),
		ie.NewApplyAction(ActionForward|ActionDuplicate),
		ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess)),
		ie.NewDuplicatingParameters(ie.NewDestinationInterface(ie.DstInterfaceLIFunction)),
	)
	if err := dup.parseFAR(in, 100, mockUpf, create); err != nil {
		t.Fatalf("parseFAR: %v", err)
	}
	if n := logs.Len(); n != 0 {
		t.Errorf("parsing a DUPL FAR emitted %d log entries, want 0 (undetectability): %v", n, logs.All())
	}
}

// TestSetActionValueDuplicate checks that DUPL forwarding FARs are programmed
// with the forward-and-duplicate BESS actions (which the pipeline routes to the
// LI tee), while plain forwarding FARs keep the normal actions.
func TestSetActionValueDuplicate(t *testing.T) {
	b := &bess{}
	cases := []struct {
		name   string
		f      far
		expect uint8
	}{
		{"downlink+dupl", far{applyAction: ActionForward | ActionDuplicate, dstIntf: ie.DstInterfaceAccess}, farForwardDAndDuplicate},
		{"uplink+dupl", far{applyAction: ActionForward | ActionDuplicate, dstIntf: ie.DstInterfaceCore}, farForwardUAndDuplicate},
		{"downlink plain", far{applyAction: ActionForward, dstIntf: ie.DstInterfaceAccess}, farForwardD},
		{"uplink plain", far{applyAction: ActionForward, dstIntf: ie.DstInterfaceCore}, farForwardU},
	}
	for _, c := range cases {
		if got := b.setActionValue(c.f); got != uint8(c.expect) {
			t.Errorf("%s: action = %d, want %d", c.name, got, c.expect)
		}
	}
}

func TestPayloadFormatOf(t *testing.T) {
	if got := payloadFormatOf([]byte{0x45, 0x00}); got != x2x3.PayloadFormatIPv4 {
		t.Errorf("IPv4 packet → %d, want %d", got, x2x3.PayloadFormatIPv4)
	}
	if got := payloadFormatOf([]byte{0x60, 0x00}); got != x2x3.PayloadFormatIPv6 {
		t.Errorf("IPv6 packet → %d, want %d", got, x2x3.PayloadFormatIPv6)
	}
	if got := payloadFormatOf(nil); got != x2x3.PayloadFormatIPv4 {
		t.Errorf("empty packet → %d, want IPv4 default", got)
	}
}

// TestShipperPDU checks that a teed datapath packet ([fseid(8)][action(1)][pkt])
// is framed as a valid X3 PDU: F-SEID as correlation id, the inner packet as
// payload, and — critically (finding R2) — the payload format + direction set
// from the FAR action, so the downlink copy is labeled GTP-U (not mislabeled as
// decapsulated inner IP) and the uplink copy is labeled inner IP.
func TestShipperPDU(t *testing.T) {
	fseid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	inner := []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	tag := func(action byte) []byte {
		return append(append(append([]byte{}, fseid...), action), inner...)
	}

	// Uplink (action 6): decapsulated inner IP → IPv4 + FromTarget.
	ul := shipperPDU(tag(farForwardUAndDuplicate))
	if ul.Type != x2x3.PDUTypeX3 {
		t.Errorf("PDU type = %d, want X3", ul.Type)
	}
	if ul.PayloadFormat != x2x3.PayloadFormatIPv4 || ul.Direction != x2x3.DirectionFromTarget {
		t.Errorf("uplink: format=%d direction=%d, want IPv4/FromTarget", ul.PayloadFormat, ul.Direction)
	}
	if !bytes.Equal(ul.CorrelationID[:], fseid) || !bytes.Equal(ul.Payload, inner) {
		t.Errorf("uplink: correlation=% x payload=% x", ul.CorrelationID, ul.Payload)
	}

	// Downlink (action 5): teed post-encap → GTP-U + ToTarget (must NOT be labeled inner IP).
	dl := shipperPDU(tag(farForwardDAndDuplicate))
	if dl.PayloadFormat != x2x3.PayloadFormatGTPU || dl.Direction != x2x3.DirectionToTarget {
		t.Errorf("downlink: format=%d direction=%d, want GTPU/ToTarget", dl.PayloadFormat, dl.Direction)
	}

	// Both must be well-formed X3 PDUs on the wire.
	for _, pdu := range []*x2x3.PDU{ul, dl} {
		if _, err := pdu.Marshal(); err != nil {
			t.Errorf("Marshal: %v", err)
		}
	}
}
