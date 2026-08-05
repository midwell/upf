// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"bytes"
	"net"
	"testing"

	"github.com/omec-project/li/x1"
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

// TestSetFwdActionValueDuplicate checks that DUPL forwarding FARs are routed to
// the LI tee, and — the part that matters — that this never reaches the "action"
// attribute.
//
// BESS's GtpuEncap reuses "action" as the GTP-U PDU Session Container PDU Type,
// where only 0 (downlink) and 1 (uplink) exist. Putting a duplication value there
// shipped an undefined PDU type to the RAN, which segfaulted parsing it (review
// R30). The duplication variants therefore belong on fwd_action alone, and the
// second half of this table is the regression guard for that.
func TestSetFwdActionValueDuplicate(t *testing.T) {
	b := &bess{}

	dlDup := far{applyAction: ActionForward | ActionDuplicate, dstIntf: ie.DstInterfaceAccess}
	ulDup := far{applyAction: ActionForward | ActionDuplicate, dstIntf: ie.DstInterfaceCore}
	dlPlain := far{applyAction: ActionForward, dstIntf: ie.DstInterfaceAccess}
	ulPlain := far{applyAction: ActionForward, dstIntf: ie.DstInterfaceCore}

	// What executeFAR splits on: duplication is visible here.
	for _, c := range []struct {
		name   string
		f      far
		expect uint8
	}{
		{"downlink+dupl", dlDup, farForwardDAndDuplicate},
		{"uplink+dupl", ulDup, farForwardUAndDuplicate},
		{"downlink plain", dlPlain, farForwardD},
		{"uplink plain", ulPlain, farForwardU},
	} {
		if got := b.setFwdActionValue(c.f); got != c.expect {
			t.Errorf("%s: fwd_action = %d, want %d", c.name, got, c.expect)
		}
	}

	// What GtpuEncap consumes as the PSC PDU type: duplication must be invisible,
	// and the value must stay one of the two the wire format defines.
	for _, c := range []struct {
		name   string
		f      far
		expect uint8
	}{
		{"downlink+dupl stays a valid PDU type", dlDup, farForwardD},
		{"uplink+dupl stays a valid PDU type", ulDup, farForwardU},
		{"downlink plain", dlPlain, farForwardD},
		{"uplink plain", ulPlain, farForwardU},
	} {
		if got := b.setActionValue(c.f); got != c.expect {
			t.Errorf("%s: action = %d, want %d (0 and 1 are the only defined PDU types)", c.name, got, c.expect)
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
	// The datapath prepends the F-SEID in host (little-endian) byte order; the X3
	// correlation ID carries it big-endian so it matches the SMF's X2 correlation
	// ID for the session (review R20 / design D12) — i.e. the tag bytes reversed.
	wantCorr := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	if !bytes.Equal(ul.CorrelationID[:], wantCorr) || !bytes.Equal(ul.Payload, inner) {
		t.Errorf("uplink: correlation=% x (want % x) payload=% x", ul.CorrelationID, wantCorr, ul.Payload)
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

// TestShipperPDUStripsLinkLayer covers what the datapath actually tees: BESS's
// GTP-U decap leaves the Ethernet header in place, so the teed copy is a full
// frame (observed on a live bessd pipeline, task 5.5). X3 carries the network
// layer, so the L2 header must be stripped — otherwise the MDF receives 14 extra
// bytes under a payload format claiming an IP packet.
func TestShipperPDUStripsLinkLayer(t *testing.T) {
	ip := []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	ethHeader := func(etherType ...byte) []byte {
		hdr := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2}

		return append(hdr, etherType...)
	}
	tag := func(action byte, payload []byte) []byte {
		return append(append(append([]byte{}, 1, 2, 3, 4, 5, 6, 7, 8), action), payload...)
	}

	tests := []struct {
		name       string
		action     byte
		payload    []byte
		wantFormat x2x3.PayloadFormat
		wantBody   []byte
	}{
		{
			name:       "ethernet framed uplink is stripped",
			action:     farForwardUAndDuplicate,
			payload:    append(ethHeader(0x08, 0x00), ip...),
			wantFormat: x2x3.PayloadFormatIPv4,
			wantBody:   ip,
		},
		{
			name:       "ethernet framed downlink is stripped and labelled GTP-U",
			action:     farForwardDAndDuplicate,
			payload:    append(ethHeader(0x08, 0x00), ip...),
			wantFormat: x2x3.PayloadFormatGTPU,
			wantBody:   ip,
		},
		{
			name:       "vlan tagged frame is stripped",
			action:     farForwardUAndDuplicate,
			payload:    append(append(ethHeader(0x81, 0x00), 0x00, 0x0a, 0x08, 0x00), ip...),
			wantFormat: x2x3.PayloadFormatIPv4,
			wantBody:   ip,
		},
		{
			name:       "bare ip packet is shipped unchanged",
			action:     farForwardUAndDuplicate,
			payload:    ip,
			wantFormat: x2x3.PayloadFormatIPv4,
			wantBody:   ip,
		},
		{
			name:       "unrecognised payload is labelled ethernet, not mislabelled as ip",
			action:     farForwardUAndDuplicate,
			payload:    append(ethHeader(0x12, 0x34), 0xaa, 0xbb),
			wantFormat: x2x3.PayloadFormatEthernet,
			wantBody:   append(ethHeader(0x12, 0x34), 0xaa, 0xbb),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdu := shipperPDU(tag(tt.action, tt.payload))
			if pdu.PayloadFormat != tt.wantFormat {
				t.Errorf("payload format = %d, want %d", pdu.PayloadFormat, tt.wantFormat)
			}
			if !bytes.Equal(pdu.Payload, tt.wantBody) {
				t.Errorf("payload = % x, want % x", pdu.Payload, tt.wantBody)
			}
			if _, err := pdu.Marshal(); err != nil {
				t.Errorf("Marshal: %v", err)
			}
		})
	}
}

// fakeNEIssueReporter records the LI-plane faults reported to the ADMF.
type fakeNEIssueReporter struct {
	issues []string
}

func (f *fakeNEIssueReporter) ReportNEIssue(issueType, _ string) error {
	f.issues = append(f.issues, issueType)

	return nil
}

// TestCheckTagReportsUnusableTag proves an unusable content tag is reported to the
// ADMF over X1 (design D11) instead of silently shipping product the MDF cannot
// correlate. A tag whose metadata never reached the datapath encap carries a zero
// correlation or an unknown action — interception runs but its product is useless.
func TestCheckTagReportsUnusableTag(t *testing.T) {
	tests := []struct {
		name       string
		tag        []byte
		wantReport bool
	}{
		{
			name:       "valid uplink tag is not reported",
			tag:        []byte{1, 0, 0, 0, 0, 0, 0, 0, farForwardUAndDuplicate},
			wantReport: false,
		},
		{
			name:       "unknown action is reported",
			tag:        []byte{1, 0, 0, 0, 0, 0, 0, 0, 16},
			wantReport: true,
		},
		{
			name:       "zero correlation is reported",
			tag:        []byte{0, 0, 0, 0, 0, 0, 0, 0, farForwardUAndDuplicate},
			wantReport: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeNEIssueReporter{}
			s := &liShipper{reporter: fake}

			s.checkTag(append(tt.tag, 0x45, 0x00))

			if got := len(fake.issues) > 0; got != tt.wantReport {
				t.Errorf("reported = %v (%v), want %v", got, fake.issues, tt.wantReport)
			}
			for _, issue := range fake.issues {
				if issue != x1.NEIssueX3TagInvalid {
					t.Errorf("issue type = %q, want %q", issue, x1.NEIssueX3TagInvalid)
				}
			}
		})
	}
}
