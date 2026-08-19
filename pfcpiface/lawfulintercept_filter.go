// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"encoding/binary"

	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x2x3"
)

// Duplication is set per FAR, and a FAR may forward traffic that a task's detection
// criteria do not identify — the traffic of another PDR pointing at it, or of
// another transport port on the same PDR. Enabling duplication therefore collects a
// superset of what the criteria select, and this file drops the difference before
// delivery. Delivering it would be collection beyond the authorisation.
//
// It answers from the datapath's tag and the session's own rules wherever it can,
// and reads the packet only where nothing else can settle the question. The tag and
// the rules are already parsed and trusted; the packet is whatever the far end
// sent, so every read of it is bounds-checked and nothing is allocated from a
// length it carries.
//
// A copy that does not match is not lost content: it is content this element was
// never authorised to take. It is dropped silently, and specifically not reported
// as a delivery fault — see the reporting in lawfulintercept.go.

// copyFilter narrows the copies of one session's traffic to those a task's criteria
// identify. Its arms are the task's criteria, which are alternatives: a copy
// matching any arm belongs to the task.
type copyFilter struct {
	// all short-circuits the whole filter: every copy of the session's traffic
	// belongs to the task, so no copy needs deciding. Explicit rather than implied by
	// the arms, because "no arms" must not silently mean "match nothing" — a filter
	// built without session state to resolve against has to deliver, not discard.
	all  bool
	arms []filterArm
	// frags remembers what the initial fragment of each fragmented datagram was classified
	// as, so the datagram's later fragments — which carry no transport header — are
	// delivered or dropped with it rather than being dropped for not repeating it.
	//
	// A pointer, because a copyFilter is held by value in a coveredTask and copied to every
	// caller: the memo has to be the same one for every worker deciding copies of the same
	// session under the same tasking. Nil for a filter with no inspecting arm, which is
	// every filter that does not have to read the packet — so the ordinary paths allocate
	// nothing.
	frags *fragmentMemo
}

// filterArm is one criterion resolved against one session — enough to decide any
// copy of that session's traffic without resolving it again.
type filterArm struct {
	// uplink and downlink are the directions of the PDRs this criterion selected. A
	// criterion selecting only the uplink PDR of a session whose FAR is shared with
	// the downlink one is the ordinary case, and the tag alone settles it.
	uplink   bool
	downlink bool
	// inspect is set when the criterion is a transport-port criterion whose selected
	// PDRs do not constrain the port — no SDF filter, or a filter covering a range.
	// Nothing but the packet can then say whether a copy is the criterion's.
	inspect bool
	proto   uint8
	port    uint16
}

// filterFor resolves a task's criteria against one session. Copies of that
// session's traffic can then be decided from the result alone.
//
// It parses as it goes, which is right for a caller that has a task and nothing else.
// The shipping path does not: it holds criteria parsed when the tasking changed, and
// calls filterFrom directly — parsing here per copy was half the per-packet cost this
// filter exists to justify.
func filterFor(task types.InterceptTask, sess PFCPSession) copyFilter {
	criteria := make([]criterion, 0, len(task.Targets))
	for _, id := range task.Targets {
		if c, err := parseCriterion(id); err == nil {
			criteria = append(criteria, c)
		}
	}

	return filterFrom(criteria, sess, nil)
}

// filterFrom resolves already-parsed criteria against one session.
//
// onLoss reports a fragment discarded because this element had no classification for its
// datagram — the existing X3 content-loss condition. It is a parameter rather than reached
// through anything, because the only caller that has a reporting channel is the enabler, and
// a filter built without one (a test, or a shipper with no datapath) must still work.
func filterFrom(criteria []criterion, sess PFCPSession, onLoss func()) copyFilter {
	one := []PFCPSession{sess}

	var f copyFilter
	for _, c := range criteria {
		refs := c.resolve(one)
		if len(refs) == 0 {
			// This criterion selects nothing in this session. Another may.
			continue
		}

		arm := filterArm{proto: c.proto, port: c.port}
		for _, r := range refs {
			if r.uplink {
				arm.uplink = true
			} else {
				arm.downlink = true
			}
			// Only a transport-port criterion resolves to broader-than-itself coverage,
			// and only then does the packet have to be read.
			if r.cover == coverBroader {
				arm.inspect = true
			}
		}
		// A criterion covering both directions with nothing left to inspect settles
		// every copy on its own, so the rest cannot narrow anything: the arms are
		// alternatives.
		if arm.uplink && arm.downlink && !arm.inspect {
			return copyFilter{all: true}
		}
		f.arms = append(f.arms, arm)
	}

	// Only where something has to read the packet. A filter whose arms all settle on the
	// datapath's own direction tag never looks at a fragment header, so it needs no memo and
	// pays for none.
	for _, a := range f.arms {
		if a.inspect {
			f.frags = newFragmentMemo(onLoss)

			break
		}
	}

	return f
}

// unfiltered is the filter for a copy this element cannot resolve criteria for,
// which delivers everything. It is the behaviour from before criteria other than
// the session identity were supported, and the session identity covers a whole
// session in both directions in any case.
func unfiltered() copyFilter { return copyFilter{all: true} }

// trivial reports that every copy of the session's traffic belongs to the task, so
// no copy needs deciding. It is the common case — a task keyed by the session
// identity, or by an address, covers the whole session in both directions — and it
// is what keeps interception free of per-packet work where filtering has nothing to
// correct.
func (f copyFilter) trivial() bool { return f.all }

// matches reports whether a copy belongs to the task. frame is the teed Ethernet
// frame, read only when an arm requires it.
func (f copyFilter) matches(action byte, frame []byte) bool {
	if f.trivial() {
		return true
	}

	uplink := action == farForwardUAndDuplicate
	for _, a := range f.arms {
		if uplink && !a.uplink {
			continue
		}
		if !uplink && !a.downlink {
			continue
		}
		if !a.inspect {
			return true
		}
		if f.inspected(frame, uplink, a) {
			return true
		}
	}

	return false
}

// inspected decides one inspecting arm against a copy, reading the packet.
//
// **A fragmented datagram is decided once, from the fragment that carries the transport
// header, and every later fragment follows that decision.** Before this, a later fragment
// simply had no ports to read: the port comparison reported false and the copy was dropped — every
// non-initial fragment of a datagram this element had just decided was authorised. An agency
// received the head of each datagram and nothing else, and downstream that is invisible,
// because the dropped copies never reached framing so the X3 sequence has no gap in it.
func (f copyFilter) inspected(frame []byte, uplink bool, a filterArm) bool {
	l3, ok := ueNetworkLayer(frame, uplink)
	if !ok {
		return false
	}

	key, offset, more, ok := fragmentOf(l3, uplink)
	if !ok {
		// Not a header this element can read. Unchanged: a copy it cannot parse is not one
		// it can confirm belongs to the criterion, and delivering on a guess is collection
		// the warrant may not cover.
		return false
	}

	// The ordinary case, and the one that must stay allocation-free: an unfragmented
	// datagram carries its own transport header and settles on its own.
	if offset == 0 && !more {
		return f.portMatches(l3, uplink, a)
	}

	if offset == 0 {
		// The initial fragment of a fragmented datagram. It carries the transport header, so
		// it is decided normally — and the decision is remembered for the fragments that
		// follow, which carry none.
		matched := f.portMatches(l3, uplink, a)
		f.frags.classify(key, matched)

		return matched
	}

	// A later fragment. Its ports are not in it: the bytes at those offsets are payload,
	// and the offset field is the far end's to choose.
	if matched, known := f.frags.decision(key); known {
		return matched
	}

	// No classification: the fragment arrived before the one carrying the transport header,
	// or the decision expired, or the memo was at its ceiling. The copy is discarded — and
	// **reported**, because this element cannot tell whether it was authorised and a loss it
	// cannot see is the one thing this plane may not produce. A *known* non-match is not
	// reported: dropping those fragments is what the criterion asked for.
	//
	// Holding such a fragment until its first arrives is deliberately not done; see
	// lawfulintercept_fragment.go for why, and x2x3/CONFORMANCE.md, where the limit is
	// declared rather than left to be discovered.
	if f.frags != nil && f.frags.onLoss != nil {
		f.frags.onLoss()
	}

	return false
}

// portMatches reads the transport header of a datagram that carries one and compares it
// against the arm.
func (f copyFilter) portMatches(l3 []byte, uplink bool, a filterArm) bool {
	proto, transport, ok := transportOf(l3)
	if !ok {
		return false
	}

	src, dst, ok := portsOf(proto, transport)
	if !ok {
		return false
	}

	port := dst
	if uplink {
		port = src
	}

	return proto == a.proto && port == a.port
}

// ueNetworkLayer returns the target's own IP header inside a teed copy.
//
// The two directions carry different things, which is the whole reason this is a function:
// the uplink copy is teed after decapsulation, so it *is* the target's packet; the downlink
// copy is teed after GTP-U encapsulation, so the target's packet is inside the tunnel.
//
// Split out from the port comparison because the fragment decision needs the same bytes: reading the
// header twice, once for the ports and once for the fragmentation state, would have walked the
// tunnel twice on the one path in this element whose cost is per packet.
func ueNetworkLayer(frame []byte, uplink bool) ([]byte, bool) {
	l3, format := networkLayerOf(frame)
	if format == x2x3.PayloadFormatEthernet {
		// networkLayerOf reports Ethernet when it found no network layer at all. The
		// bytes it returns are then the frame as given, whose first nibble could still
		// look like an IP version.
		return nil, false
	}

	if !uplink {
		var ok bool
		if l3, ok = gtpuPayloadOf(l3); !ok {
			return nil, false
		}
	}

	return l3, true
}

// transportOf skips an IP header and returns the protocol it carries with the bytes
// following it. IPv6 is refused rather than guessed at: reaching its transport
// header means walking a chain of extension headers, and a UE IPv6 criterion is
// refused at tasking time anyway, so nothing here needs it.
func transportOf(l3 []byte) (uint8, []byte, bool) {
	const (
		minIPv4Header = 20
		protoOffset   = 9
	)

	if len(l3) < minIPv4Header || l3[0]>>4 != 4 {
		return 0, nil, false
	}

	hdrLen := int(l3[0]&0x0f) * 4
	if hdrLen < minIPv4Header || hdrLen > len(l3) {
		return 0, nil, false
	}

	// A fragment other than the first does not carry the transport header, and its
	// offset field is the far end's to choose. Bytes at the expected offsets would
	// be payload read as ports.
	const (
		flagsOffset  = 6
		fragmentMask = 0x1fff
	)
	if binary.BigEndian.Uint16(l3[flagsOffset:flagsOffset+2])&fragmentMask != 0 {
		return 0, nil, false
	}

	return l3[protoOffset], l3[hdrLen:], true
}

// portsOf returns the source and destination ports of a TCP or UDP header.
func portsOf(proto uint8, transport []byte) (uint16, uint16, bool) {
	const minPortHeader = 4

	if proto != protoTCP && proto != protoUDP {
		return 0, 0, false
	}
	if len(transport) < minPortHeader {
		return 0, 0, false
	}

	return binary.BigEndian.Uint16(transport[0:2]), binary.BigEndian.Uint16(transport[2:4]), true
}

// gtpuPayloadOf returns the packet carried inside a GTP-U datagram, given the outer
// network layer. Every length it reads is the far end's to choose, so each is
// checked against what is actually present and the extension-header walk is bounded
// — a length field driving an unbounded loop or a sized allocation is how the
// vendored ASN.1 decoder came to have a denial-of-service defect.
func gtpuPayloadOf(l3 []byte) ([]byte, bool) {
	const (
		gtpuMinHeader = 8
		// The optional sequence number, N-PDU number and next-extension-header type,
		// present together whenever any of E, S or PN is set.
		gtpuOptionalLen = 4
		flagExtension   = 0x04
		flagSequence    = 0x02
		flagNPDU        = 0x01
		// GTP-U carrying a user packet. Signalling messages (echo, error indication)
		// carry no user traffic to attribute.
		msgTypeGPDU = 0xff
		// An extension-header chain longer than this is not a packet worth walking.
		maxExtensions = 8
	)

	proto, udp, ok := transportOf(l3)
	if !ok || proto != protoUDP {
		return nil, false
	}

	const udpHeaderLen = 8
	if len(udp) < udpHeaderLen {
		return nil, false
	}
	if binary.BigEndian.Uint16(udp[2:4]) != tunnelGTPUPort {
		return nil, false
	}

	g := udp[udpHeaderLen:]
	if len(g) < gtpuMinHeader || g[1] != msgTypeGPDU {
		return nil, false
	}

	offset := gtpuMinHeader
	flags := g[0]
	if flags&(flagExtension|flagSequence|flagNPDU) != 0 {
		offset += gtpuOptionalLen
		if offset > len(g) {
			return nil, false
		}
		// The next-extension-header type is the last of the optional bytes.
		next := g[offset-1]
		for n := 0; next != 0; n++ {
			if n == maxExtensions {
				return nil, false
			}
			// Each extension header is [length][content][next], with length counting
			// 4-octet units including its own byte and the next-header byte.
			if offset >= len(g) {
				return nil, false
			}
			extLen := int(g[offset]) * 4
			// A zero length would leave the walk on the same octet reading the same
			// next-header byte for ever. The iteration cap above would stop it anyway —
			// the two guards are deliberately redundant, since either alone is enough to
			// keep this terminating and the failure they prevent is a hang in the
			// interception path.
			if extLen == 0 || offset+extLen > len(g) {
				return nil, false
			}
			next = g[offset+extLen-1]
			offset += extLen
		}
	}

	if offset >= len(g) {
		return nil, false
	}

	return g[offset:], true
}
