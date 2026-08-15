// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"

	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
)

// Frames the datapath tees, built to the layout the two directions actually carry:
// the uplink copy is the target's own IP packet, decapsulated, so the target is its
// source; the downlink copy is teed after GTP-U encapsulation, so the target's
// packet is inside the tunnel and the target is its destination.

// ethIPv4 wraps a network-layer packet in the Ethernet header the datapath tees.
func ethIPv4(l3 []byte) []byte {
	frame := make([]byte, 14, 14+len(l3))
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	return append(frame, l3...)
}

// ipv4 builds an IPv4 packet carrying payload, with the given protocol.
func ipv4Packet(src, dst string, proto uint8, payload []byte) []byte {
	p := make([]byte, 20, 20+len(payload))
	p[0] = 0x45 // version 4, 5-word header
	binary.BigEndian.PutUint16(p[2:4], uint16(20+len(payload)))
	p[9] = proto
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.ParseIP(dst).To4())

	return append(p, payload...)
}

// tcpSegment builds the first four octets of a TCP or UDP header, which is all that
// carries ports.
func tcpSegment(srcPort, dstPort uint16, extra int) []byte {
	seg := make([]byte, 4+extra)
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)

	return seg
}

// gtpuEncap wraps an inner packet the way the downlink tee sees it: outer IPv4, UDP
// to port 2152, then a GTP-U G-PDU header.
func gtpuEncap(inner []byte, flags byte, optional []byte) []byte {
	g := make([]byte, 8, 8+len(optional)+len(inner))
	g[0] = 0x30 | flags // version 1, protocol type GTP
	g[1] = 0xff         // G-PDU
	binary.BigEndian.PutUint16(g[2:4], uint16(len(optional)+len(inner)))
	binary.BigEndian.PutUint32(g[4:8], 0x1001)
	g = append(g, optional...)
	g = append(g, inner...)

	udp := make([]byte, 8, 8+len(g))
	binary.BigEndian.PutUint16(udp[0:2], 2152)
	binary.BigEndian.PutUint16(udp[2:4], 2152)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(g)))
	udp = append(udp, g...)

	return ethIPv4(ipv4Packet("10.76.0.1", "10.76.0.2", protoUDP, udp))
}

// uplinkCopy is a copy of a packet the target sent from the given port.
func uplinkCopy(port uint16) []byte {
	return ethIPv4(ipv4Packet("10.250.0.9", "1.1.1.1", protoTCP, tcpSegment(port, 80, 16)))
}

// downlinkCopy is a copy of a packet sent to the target's given port, as the
// downlink tee sees it — inside the GTP-U tunnel.
func downlinkCopy(port uint16) []byte {
	return gtpuEncap(ipv4Packet("1.1.1.1", "10.250.0.9", protoTCP, tcpSegment(80, port, 16)), 0, nil)
}

// wildcardSession is the ordinary case: one FAR per direction, and PDRs whose SDF
// filters constrain nothing but the UE address. A port criterion against it can only
// be settled by reading the packet.
func wildcardSession() PFCPSession { return unmarkedSession(100, "10.250.0.9") }

// sharedFARSession has both directions forwarding through one FAR, so enabling
// duplication for a criterion that selects one direction copies the other too.
func sharedFARSession() PFCPSession {
	ue := ip2int(net.ParseIP("10.250.0.9"))

	return PFCPSession{
		localSEID: 100,
		PacketForwardingRules: PacketForwardingRules{
			pdrs: []pdr{
				uplinkPDR(100, 9, 0x1001, ip2int(net.ParseIP("10.76.0.2")), ue),
				downlinkPDR(100, 9, ue),
			},
			fars: []far{{farID: 9, fseID: 100, applyAction: ActionForward}},
		},
	}
}

func taskWith(ids ...types.TargetIdentifier) types.InterceptTask {
	return types.InterceptTask{XID: "W1", Targets: ids, Products: []types.ProductType{types.ProductCC}}
}

// TestFilterDecidesEachCriterion covers every criterion the CC-POI accepts, in both
// directions. What each must do is not obvious from the criterion alone: some cover a
// whole session and need no filtering, some cover one direction and are settled by
// the datapath's tag, and only the transport-port ones require the packet.
func TestFilterDecidesEachCriterion(t *testing.T) {
	niHex := hex.EncodeToString([]byte(testNetInstance()))

	cases := []struct {
		name    string
		session PFCPSession
		ids     []types.TargetIdentifier
		// wantTrivial is whether the filter should decide without reading a packet at
		// all — task 4.3's requirement that the common case costs nothing.
		wantTrivial  bool
		wantUplink   bool
		wantDownlink bool
	}{
		{
			name:        "PFCP session ID covers the whole session",
			session:     wildcardSession(),
			ids:         []types.TargetIdentifier{{Type: types.TargetFSEID, Value: "100"}},
			wantTrivial: true, wantUplink: true, wantDownlink: true,
		},
		{
			name:        "UE address covers the whole session",
			session:     wildcardSession(),
			ids:         []types.TargetIdentifier{ueAddr("10.250.0.9")},
			wantTrivial: true, wantUplink: true, wantDownlink: true,
		},
		{
			name:        "network instance covers the whole session",
			session:     wildcardSession(),
			ids:         []types.TargetIdentifier{{Type: types.TargetNetworkInstance, Value: niHex}},
			wantTrivial: true, wantUplink: true, wantDownlink: true,
		},
		{
			name:        "QER ID covers the whole session, both PDRs being policed",
			session:     wildcardSession(),
			ids:         []types.TargetIdentifier{{Type: types.TargetQERID, Value: "4"}},
			wantTrivial: true, wantUplink: true, wantDownlink: true,
		},
		{
			// The tunnel appears in the uplink PDR's PDI only, so this is one direction —
			// and on a session whose FAR is shared, the downlink copies that arrive must
			// be dropped.
			name:        "F-TEID selects the uplink only",
			session:     sharedFARSession(),
			ids:         []types.TargetIdentifier{{Type: types.TargetFTEID, Value: "4097"}},
			wantTrivial: false, wantUplink: true, wantDownlink: false,
		},
		{
			name:    "inbound direction selects the uplink only",
			session: sharedFARSession(),
			ids: []types.TargetIdentifier{
				{Type: types.TargetGTPTunnelDirection, Value: x1.GTPDirectionInbound},
			},
			wantTrivial: false, wantUplink: true, wantDownlink: false,
		},
		{
			name:    "outbound direction selects the downlink only",
			session: sharedFARSession(),
			ids: []types.TargetIdentifier{
				{Type: types.TargetGTPTunnelDirection, Value: x1.GTPDirectionOutbound},
			},
			wantTrivial: false, wantUplink: false, wantDownlink: true,
		},
		{
			name:        "PDR ID selects the direction of that rule",
			session:     sharedFARSession(),
			ids:         []types.TargetIdentifier{{Type: types.TargetPDRID, Value: "2"}},
			wantTrivial: false, wantUplink: false, wantDownlink: true,
		},
		{
			// The criteria of a task are alternatives, so one covering the session makes
			// the whole filter trivial however narrow the others are.
			name:    "a broad criterion beside a narrow one covers everything",
			session: sharedFARSession(),
			ids: []types.TargetIdentifier{
				{Type: types.TargetPDRID, Value: "2"},
				ueAddr("10.250.0.9"),
			},
			wantTrivial: true, wantUplink: true, wantDownlink: true,
		},
		{
			// Two narrow criteria, one per direction, add up to both.
			name:    "two directions tasked separately",
			session: sharedFARSession(),
			ids: []types.TargetIdentifier{
				{Type: types.TargetGTPTunnelDirection, Value: x1.GTPDirectionInbound},
				{Type: types.TargetGTPTunnelDirection, Value: x1.GTPDirectionOutbound},
			},
			wantTrivial: false, wantUplink: true, wantDownlink: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := filterFor(taskWith(c.ids...), c.session)
			if f.trivial() != c.wantTrivial {
				t.Errorf("trivial() = %v, want %v", f.trivial(), c.wantTrivial)
			}
			if got := f.matches(farForwardUAndDuplicate, uplinkCopy(443)); got != c.wantUplink {
				t.Errorf("uplink copy matched = %v, want %v", got, c.wantUplink)
			}
			if got := f.matches(farForwardDAndDuplicate, downlinkCopy(443)); got != c.wantDownlink {
				t.Errorf("downlink copy matched = %v, want %v", got, c.wantDownlink)
			}
		})
	}
}

// TestFilterOnTransportPort is the one criterion that cannot be answered from the
// tag or the session's rules, since the PDRs here constrain no port. Reading the
// wrong end of the packet would intercept by the far end's port instead of the
// target's, which is a different set of traffic entirely.
func TestFilterOnTransportPort(t *testing.T) {
	f := filterFor(taskWith(types.TargetIdentifier{Type: types.TargetTCPPort, Value: "443"}),
		wildcardSession())
	if f.trivial() {
		t.Fatal("a port criterion on wildcard rules cannot be trivial — nothing would be filtered")
	}

	cases := []struct {
		name   string
		action byte
		frame  []byte
		want   bool
	}{
		{"the target's own port, uplink", farForwardUAndDuplicate, uplinkCopy(443), true},
		{"another of the target's ports, uplink", farForwardUAndDuplicate, uplinkCopy(8080), false},
		{"the target's own port, downlink inside the tunnel", farForwardDAndDuplicate, downlinkCopy(443), true},
		{"another port, downlink", farForwardDAndDuplicate, downlinkCopy(8080), false},
		{
			// The far end's port is 443 and the target's is not: matching this would
			// collect the wrong traffic.
			"the far end's port is the criterion's, uplink",
			farForwardUAndDuplicate,
			ethIPv4(ipv4Packet("10.250.0.9", "1.1.1.1", protoTCP, tcpSegment(8080, 443, 16))),
			false,
		},
		{
			"a UDP packet on the same port number does not match a TCP criterion",
			farForwardUAndDuplicate,
			ethIPv4(ipv4Packet("10.250.0.9", "1.1.1.1", protoUDP, tcpSegment(443, 80, 8))),
			false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := f.matches(c.action, c.frame); got != c.want {
				t.Errorf("matched = %v, want %v", got, c.want)
			}
		})
	}
}

// TestFilterOnMalformedPacket covers the exposure class this filter introduces: it
// is the first place the CC-POI reads bytes the far end chose. Every case must yield
// no match and no panic. A copy that cannot be read is not delivered — delivering on
// a guess would be collection the warrant may not cover.
func TestFilterOnMalformedPacket(t *testing.T) {
	f := filterFor(taskWith(types.TargetIdentifier{Type: types.TargetTCPPort, Value: "443"}),
		wildcardSession())

	full := uplinkCopy(443)
	dl := downlinkCopy(443)

	cases := []struct {
		name   string
		action byte
		frame  []byte
	}{
		{"nothing at all", farForwardUAndDuplicate, nil},
		{"an empty frame", farForwardUAndDuplicate, []byte{}},
		{"an Ethernet header and nothing more", farForwardUAndDuplicate, full[:14]},
		{"an IP header cut short", farForwardUAndDuplicate, full[:14+12]},
		{"a complete IP header and no transport", farForwardUAndDuplicate, full[:14+20]},
		{"a transport header cut mid-port", farForwardUAndDuplicate, full[:14+20+3]},
		{
			// A header length claiming more than the frame holds.
			"an IP header length past the end of the frame", farForwardUAndDuplicate,
			overwrite(full, 14, 0x4f),
		},
		{
			// A header length below the minimum, which would make the transport offset
			// point back into the header.
			"an IP header length below the minimum", farForwardUAndDuplicate,
			overwrite(full, 14, 0x41),
		},
		{"a non-IP ether type", farForwardUAndDuplicate, overwrite(full, 13, 0x35)},
		{"a fragment that is not the first", farForwardUAndDuplicate, overwrite(full, 14+7, 0x10)},
		{"a downlink copy that is not a tunnel", farForwardDAndDuplicate, full},
		{"a downlink tunnel cut before the inner packet", farForwardDAndDuplicate, dl[:14+20+8+8]},
		{
			// A GTP-U message type other than G-PDU carries no user traffic.
			"a GTP-U message that is not a G-PDU", farForwardDAndDuplicate,
			overwrite(dl, 14+20+8+1, 0x01),
		},
		{
			// The extension-header flag set, with no extension headers present.
			"a GTP-U header claiming optional fields it does not have", farForwardDAndDuplicate,
			overwrite(dl, 14+20+8, 0x34),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if f.matches(c.action, c.frame) {
				t.Error("a frame that could not be read was matched")
			}
		})
	}
}

// overwrite returns a copy of frame with one byte replaced.
func overwrite(frame []byte, at int, b byte) []byte {
	out := append([]byte(nil), frame...)
	out[at] = b

	return out
}

// TestFilterWalksGTPUExtensionHeaders checks the tunnel walk on the forms a real
// downlink copy takes, and that a chain designed to spin is refused. The lengths
// driving the walk are the far end's to choose, so an unbounded one is a
// denial-of-service in the interception path.
func TestFilterWalksGTPUExtensionHeaders(t *testing.T) {
	f := filterFor(taskWith(types.TargetIdentifier{Type: types.TargetUDPPort, Value: "5060"}),
		wildcardSession())
	inner := ipv4Packet("1.1.1.1", "10.250.0.9", protoUDP, tcpSegment(5060, 5060, 8))

	// A sequence number present, so the four optional octets are there with no
	// extension header following.
	seq := []byte{0x00, 0x01, 0x00, 0x00}
	if !f.matches(farForwardDAndDuplicate, gtpuEncap(inner, 0x02, seq)) {
		t.Error("a tunnel carrying a sequence number was not read")
	}

	// One extension header: [len=1][2 octets][next=0].
	ext := []byte{0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00}
	if !f.matches(farForwardDAndDuplicate, gtpuEncap(inner, 0x06, ext)) {
		t.Error("a tunnel carrying one extension header was not read")
	}

	// A chain longer than the walk will follow, ending properly and followed by a
	// packet that *would* match. Refusing it is the point: GTP-U in practice carries
	// one or two extension headers, and a frame built to make this element walk a long
	// chain per copy is a frame built to slow the interception path down.
	long := []byte{0x00, 0x01, 0x00, 0x01}
	for range 11 {
		long = append(long, 0x01, 0x00, 0x00, 0x01)
	}
	long = append(long, 0x01, 0x00, 0x00, 0x00) // the last says nothing follows
	if f.matches(farForwardDAndDuplicate, gtpuEncap(inner, 0x06, long)) {
		t.Error("a chain longer than the walk follows was accepted")
	}

	// An unterminated chain: every header says another follows, so the walk runs out
	// of frame. It must give up rather than read past the end.
	var chain []byte
	chain = append(chain, 0x00, 0x01, 0x00, 0x01)
	for range 32 {
		chain = append(chain, 0x01, 0x00, 0x00, 0x01)
	}
	if f.matches(farForwardDAndDuplicate, gtpuEncap(inner, 0x06, chain)) {
		t.Error("an unterminated extension-header chain was accepted")
	}

	// A zero length would leave the walk on the same octet for ever.
	zero := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}
	if f.matches(farForwardDAndDuplicate, gtpuEncap(inner, 0x06, zero)) {
		t.Error("an extension header of zero length was accepted")
	}
}

// TestFilterAllocatesNothingPerCopy checks that deciding a copy allocates nothing
// sized from the packet — the exposure the vendored ASN.1 decoder had, where an
// off-the-wire length drove an allocation. A filter that allocated per copy would
// also put the interception path at the mercy of the offered rate.
func TestFilterAllocatesNothingPerCopy(t *testing.T) {
	f := filterFor(taskWith(types.TargetIdentifier{Type: types.TargetTCPPort, Value: "443"}),
		wildcardSession())
	up, down := uplinkCopy(443), downlinkCopy(443)

	allocs := testing.AllocsPerRun(200, func() {
		f.matches(farForwardUAndDuplicate, up)
		f.matches(farForwardDAndDuplicate, down)
	})
	if allocs != 0 {
		t.Errorf("deciding two copies allocated %v times, want none", allocs)
	}
}

// TestTrivialFilterReadsNoPacket is task 4.3 in the form that can actually be
// asserted: where coverage is exact the frame is never touched, so a filter that
// claims to be trivial must decide a copy it could not possibly parse.
func TestTrivialFilterReadsNoPacket(t *testing.T) {
	f := filterFor(taskWith(ueAddr("10.250.0.9")), wildcardSession())
	if !f.trivial() {
		t.Fatal("a criterion covering the whole session should need no filtering")
	}
	for _, frame := range [][]byte{nil, {}, {0xff}} {
		if !f.matches(farForwardUAndDuplicate, frame) {
			t.Error("a trivial filter read the frame instead of passing the copy")
		}
	}
}

// TestFilterForUncoveredSessionMatchesNothing checks that a task whose criteria
// select nothing in a session decides none of its copies. Such a task should not
// have been offered the copy at all, so this is the backstop: labelling another
// subscriber's traffic with this warrant is the worst outcome available.
func TestFilterForUncoveredSessionMatchesNothing(t *testing.T) {
	f := filterFor(taskWith(ueAddr("10.250.0.99")), wildcardSession())
	if f.trivial() {
		t.Fatal("a filter for a session the criteria do not select claims to cover it")
	}
	if f.matches(farForwardUAndDuplicate, uplinkCopy(443)) ||
		f.matches(farForwardDAndDuplicate, downlinkCopy(443)) {
		t.Error("copies of an unselected session's traffic were matched")
	}
}

// taggedCopy prepends the datapath's tag to a frame: [fseid(8)][action(1)][frame].
func taggedCopy(seid uint64, action byte, frame []byte) []byte {
	out := make([]byte, 0, liTagLen+len(frame))
	out = binary.LittleEndian.AppendUint64(out, seid)
	out = append(out, action)

	return append(out, frame...)
}

// shipperOver builds a shipper over a fixture's tasking and sessions, with reports
// recorded rather than sent.
func shipperOver(f *enablerFixture, rec *recordingReporter) *liShipper {
	return &liShipper{
		tasks:    f.tasks,
		enabler:  f.e,
		reporter: rec,
		senders:  make(map[string]x2x3.Sender),
		ids:      x2x3.NewIdentity("upf-1", upfInterceptionPoint),
	}
}

// TestFilteredCopyIsNotAFault is the distinction group 5 exists for. A copy the
// criteria do not select was never authorised to be taken, so discarding it is
// correct behaviour — not lost content. Reporting it would manufacture delivery
// faults out of every narrow warrant, and would bury the reports that mean
// something: an ADMF told that content is being lost cannot tell which claim to act
// on.
func TestFilteredCopyIsNotAFault(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, sharedFARSession())
	f.activate(t, "W1", types.TargetIdentifier{
		Type: types.TargetGTPTunnelDirection, Value: x1.GTPDirectionInbound,
	})

	rec := &recordingReporter{}
	s := shipperOver(f, rec)

	// The downlink copy arrives because the FAR is shared, and the inbound criterion
	// does not select it.
	s.ship(taggedCopy(100, farForwardDAndDuplicate, downlinkCopy(443)))

	if got := rec.reported(); len(got) != 0 {
		t.Errorf("discarding an unselected copy reported %v, want nothing", got)
	}
	if len(s.senders) != 0 {
		t.Error("an unselected copy was prepared for delivery")
	}
}

// TestUntaskedContentStillReports keeps the report firing for the case it exists
// for: content duplicated for a session no warrant covers at all. That is a real
// disagreement between the two interfaces — the SMF marked a session and no task
// arrived — and only the ADMF can resolve it. Filtering must not have swallowed it.
func TestUntaskedContentStillReports(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, unmarkedSession(100, "10.250.0.9"))
	// A warrant, but for another subscriber, so this session is covered by none.
	f.activate(t, "W1", ueAddr("10.250.0.10"))

	rec := &recordingReporter{}
	s := shipperOver(f, rec)

	s.ship(taggedCopy(100, farForwardUAndDuplicate, uplinkCopy(443)))

	got := rec.reported()
	if len(got) != 1 || got[0] != x1.NEIssueContentUntasked {
		t.Errorf("reported %v, want one %s", got, x1.NEIssueContentUntasked)
	}
}

// TestSelectedCopyIsNotDiscarded is the counterpart: a copy the criteria do select
// must get as far as delivery. Without this, a filter that rejected everything would
// pass both tests above — no faults reported and no over-collection — while
// intercepting nothing at all.
func TestSelectedCopyIsNotDiscarded(t *testing.T) {
	f := newEnablerFixture(t)
	f.putSession(t, sharedFARSession())
	f.activate(t, "W1", types.TargetIdentifier{
		Type: types.TargetGTPTunnelDirection, Value: x1.GTPDirectionInbound,
	})

	rec := &recordingReporter{}
	s := shipperOver(f, rec)

	// The uplink copy is the one the inbound criterion selects. This task carries no
	// X3 destination, so delivery cannot complete — but reaching that complaint is
	// what proves the copy was not filtered out beforehand.
	s.ship(taggedCopy(100, farForwardUAndDuplicate, uplinkCopy(443)))

	got := rec.reported()
	if len(got) != 1 || got[0] != x1.NEIssueInvalidConfig {
		t.Errorf("reported %v, want the selected copy to reach delivery and complain "+
			"about the missing destination (%s)", got, x1.NEIssueInvalidConfig)
	}
}
