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

	return filterFrom(criteria, sess)
}

// filterFrom resolves already-parsed criteria against one session.
func filterFrom(criteria []criterion, sess PFCPSession) copyFilter {
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
		if proto, port, ok := uePortOf(frame, uplink); ok && proto == a.proto && port == a.port {
			return true
		}
	}

	return false
}

// uePortOf returns the target's own transport port in a teed copy, with the
// protocol carrying it. It reports false for anything it cannot read with
// certainty — a truncated frame, a protocol without ports, a tunnel it cannot
// walk — and the caller then treats the copy as not matching. That is the safe
// direction: a copy delivered on a guess is collection the warrant may not cover,
// while one dropped is a copy of traffic this element could not confirm was the
// criterion's.
//
// The two directions carry different things. The uplink copy is teed after
// decapsulation, so it is the target's own IP packet and the target is its source.
// The downlink copy is teed after GTP-U encapsulation, so the target's packet is
// inside the tunnel and the target is its destination.
func uePortOf(frame []byte, uplink bool) (uint8, uint16, bool) {
	l3, format := networkLayerOf(frame)
	if format == x2x3.PayloadFormatEthernet {
		// networkLayerOf reports Ethernet when it found no network layer at all. The
		// bytes it returns are then the frame as given, whose first nibble could still
		// look like an IP version.
		return 0, 0, false
	}

	if !uplink {
		var ok bool
		if l3, ok = gtpuPayloadOf(l3); !ok {
			return 0, 0, false
		}
	}

	proto, transport, ok := transportOf(l3)
	if !ok {
		return 0, 0, false
	}

	src, dst, ok := portsOf(proto, transport)
	if !ok {
		return 0, 0, false
	}

	if uplink {
		return proto, src, true
	}

	return proto, dst, true
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
