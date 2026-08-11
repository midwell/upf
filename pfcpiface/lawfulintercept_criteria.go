// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
)

// This file resolves a Lawful Interception detection criterion (3GPP TS 33.128
// table 6.2.3-7) against the PFCP state this agent already holds: which PDRs, in
// which live sessions, carry traffic the criterion identifies.
//
// It answers only that question. Enabling duplication on the FARs those PDRs
// reference, and dropping copies the enablement over-collected, are separate steps
// — the criterion is resolved once at tasking time, not per packet.

// coverage says how well a PDR's traffic corresponds to a criterion.
type coverage int

const (
	// coverNone: the PDR carries no traffic the criterion identifies.
	coverNone coverage = iota
	// coverExact: every packet the PDR matches is traffic the criterion identifies.
	coverExact
	// coverBroader: the PDR carries the identified traffic and more besides, because
	// its PDI is less specific than the criterion — a criterion naming a transport
	// port against a PDR with no SDF filter, say. Duplicating it collects beyond the
	// criterion, so the copies need filtering before delivery.
	coverBroader
)

func (c coverage) String() string {
	switch c {
	case coverExact:
		return "exact"
	case coverBroader:
		return "broader"
	default:
		return "none"
	}
}

// criterion is a detection criterion parsed into the form the agent compares
// against PFCP state. Parsing happens once, when the task is accepted: the X1
// values arrive as strings, and re-parsing them per PDR — or worse per packet —
// would put string handling on the interception path.
type criterion struct {
	kind types.TargetIdentifierType

	seid uint64 // TargetFSEID
	teid uint32 // TargetFTEID
	// tunnelIP is the F-TEID's address when the criterion carried one. A TEID alone
	// does not identify a tunnel — two nodes may allocate the same value — so the
	// address narrows it where the triggering function supplied it.
	tunnelIP    uint32
	hasTunnelIP bool
	ueIP        uint32 // TargetUEIPv4
	port        uint16 // TargetTCPPort, TargetUDPPort
	proto       uint8  // the transport the port belongs to
	ruleID      uint32 // TargetPDRID, TargetQERID
	netInstance string // TargetNetworkInstance, as the wire octets
	uplink      bool   // TargetGTPTunnelDirection
}

// Transport protocol numbers (IANA), as they appear in an SDF filter's proto field.
const (
	protoTCP uint8 = 6
	protoUDP uint8 = 17
)

// parseCriterion converts an X1 target identifier into a criterion this agent can
// resolve. It returns an error for a criterion the agent cannot evaluate, which
// the caller must report rather than swallow: a criterion silently treated as
// unmatchable would leave an acknowledged interception collecting nothing.
func parseCriterion(t types.TargetIdentifier) (criterion, error) {
	c := criterion{kind: t.Type}

	switch t.Type {
	case types.TargetFSEID:
		seid, err := strconv.ParseUint(t.Value, 10, 64)
		if err != nil {
			return criterion{}, fmt.Errorf("li: invalid PFCP session ID %q", t.Value)
		}
		c.seid = seid

	case types.TargetFTEID:
		// "TEID" or "TEID@address" — the form x1 produces for both the plain
		// gtpuTunnelId identifier and the extension's FTEID.
		val, addr, hasAddr := strings.Cut(t.Value, "@")
		teid, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return criterion{}, fmt.Errorf("li: invalid GTP tunnel ID %q", t.Value)
		}
		c.teid = uint32(teid)
		if hasAddr {
			ip, err := parseIPv4(addr)
			if err != nil {
				return criterion{}, fmt.Errorf("li: invalid GTP tunnel address %q: %w", addr, err)
			}
			c.tunnelIP, c.hasTunnelIP = ip, true
		}

	case types.TargetUEIPv4:
		ip, err := parseIPv4(t.Value)
		if err != nil {
			return criterion{}, fmt.Errorf("li: invalid UE IPv4 address %q: %w", t.Value, err)
		}
		c.ueIP = ip

	case types.TargetTCPPort, types.TargetUDPPort:
		port, err := strconv.ParseUint(t.Value, 10, 16)
		if err != nil || port == 0 {
			return criterion{}, fmt.Errorf("li: invalid port %q", t.Value)
		}
		c.port = uint16(port)
		c.proto = protoTCP
		if t.Type == types.TargetUDPPort {
			c.proto = protoUDP
		}

	case types.TargetPDRID, types.TargetQERID:
		id, err := strconv.ParseUint(t.Value, 10, 32)
		if err != nil {
			return criterion{}, fmt.Errorf("li: invalid rule ID %q", t.Value)
		}
		c.ruleID = uint32(id)

	case types.TargetNetworkInstance:
		// xs:hexBinary on the wire; compared against the octets the PDI carried.
		raw, err := hex.DecodeString(t.Value)
		if err != nil || len(raw) == 0 {
			return criterion{}, fmt.Errorf("li: invalid network instance %q", t.Value)
		}
		c.netInstance = string(raw)

	case types.TargetGTPTunnelDirection:
		// Read relative to this network element, which is the only reading that makes
		// the enumeration usable here: the UPF *receives* uplink GTP packets, so an
		// inbound tunnel is the uplink one, and it *sends* downlink GTP packets, so an
		// outbound tunnel is the downlink one. A PDR's srcIface says which of the two
		// it matches on.
		//
		// The enumeration is two values with no definition attached, so the reading
		// is an interpretation and the cost of having it backwards is intercepting
		// the opposite direction to the one authorised. It is asserted against real
		// traffic end to end rather than left to this comment.
		switch t.Value {
		case x1.GTPDirectionInbound:
			c.uplink = true
		case x1.GTPDirectionOutbound:
			c.uplink = false
		default:
			return criterion{}, fmt.Errorf("li: unknown GTP tunnel direction %q", t.Value)
		}

	case types.TargetUEIPv6:
		// This datapath holds a UE address as a uint32 and installs IPv4 rules only,
		// so no session it can describe has an IPv6 UE address to match. Refused
		// rather than accepted-and-never-matched, which is an interception that
		// produces nothing while reporting success.
		return criterion{}, fmt.Errorf("li: UE IPv6 addresses are not supported by this datapath")

	case types.TargetPDR:
		// An encoded TS 29.244 rule. Comparing one to the rules a session holds needs
		// canonicalisation semantics this agent does not have, and a wrong comparison
		// intercepts the wrong traffic rather than failing visibly.
		return criterion{}, fmt.Errorf("li: PDR criteria are not supported")

	default:
		// Subscriber identities (SUPI, GPSI, PEI) reach the UPF only by mistake: it
		// holds no subscriber identity to match them against.
		return criterion{}, fmt.Errorf("li: %s is not a packet detection criterion", t.Type)
	}

	return c, nil
}

// parseIPv4 converts a dotted-quad address to the datapath's uint32 form.
func parseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}

	return ip2int(ip), nil
}

// pdrRef identifies one PDR of one session, with the FAR it forwards through. The
// FAR is what carries the duplication flag, so it is the thing enablement acts on;
// the PDR is what filtering has to reason about.
type pdrRef struct {
	seid  uint64
	pdrID uint32
	farID uint32
	cover coverage
	// uplink is the direction of the PDR's traffic, which is what lets a copy be
	// attributed without inspecting it: the datapath's tag says which direction each
	// copy came from.
	uplink bool
}

func (r pdrRef) String() string {
	return fmt.Sprintf("pdr(seid=%d, id=%d, far=%d, %s)", r.seid, r.pdrID, r.farID, r.cover)
}

// resolve returns every PDR, across all live sessions, that carries traffic the
// criterion identifies, each with how closely it corresponds. It walks all
// sessions rather than one because most criteria do not name a session: a network
// instance spans many, and an address or tunnel identifies one without saying
// which.
//
// An empty result means the criterion selects nothing *at present*. That is not
// the same as unevaluable — a criterion may name a subscriber that has not yet
// attached — so the caller must distinguish "no session matches yet" from the
// error parseCriterion returns.
func (c criterion) resolve(sessions []PFCPSession) []pdrRef {
	var out []pdrRef

	for i := range sessions {
		for j := range sessions[i].pdrs {
			p := sessions[i].pdrs[j]
			if cov := c.matchPDR(p); cov != coverNone {
				out = append(out, pdrRef{
					seid: p.fseID, pdrID: p.pdrID, farID: p.farID,
					cover: cov, uplink: p.IsUplink(),
				})
			}
		}
	}

	return out
}

// matchPDR reports how a PDR's traffic corresponds to the criterion.
func (c criterion) matchPDR(p pdr) coverage {
	switch c.kind {
	case types.TargetFSEID:
		// Every PDR of the session carries its traffic, and the criterion is the
		// session, so nothing broader is included.
		return exactIf(p.fseID == c.seid)

	case types.TargetFTEID:
		// A tunnel endpoint appears in the PDI of the PDR that matches on it, which is
		// the uplink one: the downlink PDR of the same session matches on the UE
		// address instead and its traffic leaves through a tunnel the PDI does not
		// name. So this selects one direction, exactly.
		if p.tunnelTEID != c.teid || p.tunnelTEIDMask == 0 {
			return coverNone
		}
		if c.hasTunnelIP && p.tunnelIP4Dst != c.tunnelIP {
			return coverNone
		}

		return coverExact

	case types.TargetUEIPv4:
		return exactIf(p.ueAddress == c.ueIP && p.ueAddress != 0)

	case types.TargetTCPPort, types.TargetUDPPort:
		return c.matchPort(p)

	case types.TargetPDRID:
		return exactIf(p.pdrID == c.ruleID)

	case types.TargetQERID:
		// A QER is shared by the PDRs it polices, so this selects each of them, and
		// each exactly: the criterion is the QER's traffic, not a subset of it.
		for _, q := range p.qerIDList {
			if q == c.ruleID {
				return coverExact
			}
		}

		return coverNone

	case types.TargetNetworkInstance:
		return exactIf(p.networkInstance != "" && p.networkInstance == c.netInstance)

	case types.TargetGTPTunnelDirection:
		return exactIf(p.IsUplink() == c.uplink)

	default:
		// parseCriterion refuses everything else, so reaching here means a criterion
		// was constructed without going through it.
		return coverNone
	}
}

// matchPort resolves a transport-port criterion against a PDR's SDF filter. The
// UE is the source of uplink traffic and the destination of downlink traffic, so
// which port range describes the UE's port depends on the PDR's direction.
//
// A PDR whose filter does not constrain the port still carries the port's traffic,
// so it is selected as broader rather than rejected: refusing it would mean an
// interception ordered by port produces nothing on a session whose rules happen to
// be wildcard, which is the common case.
func (c criterion) matchPort(p pdr) coverage {
	if p.appFilter.protoMask != 0 && p.appFilter.proto != c.proto {
		return coverNone
	}

	r := p.appFilter.dstPortRange
	if p.IsUplink() {
		r = p.appFilter.srcPortRange
	}

	switch {
	case r.isWildcardMatch():
		// No port constraint: the traffic is in there, along with every other port.
		return coverBroader
	case c.port < r.low || c.port > r.high:
		return coverNone
	case r.isExactMatch():
		return coverExact
	default:
		// A range containing the port, so the PDR also carries the rest of the range,
		// and the proto may be unconstrained too.
		return coverBroader
	}
}

func exactIf(ok bool) coverage {
	if ok {
		return coverExact
	}

	return coverNone
}

// resolution is what resolving one criterion produced: the PDRs it selects, and
// whether duplicating them collects exactly that traffic or more. Filtering is
// needed only when it is not exact, so this is what lets the common case cost
// nothing per packet.
type resolution struct {
	pdrs []pdrRef
	// exact is true when every selected PDR corresponds exactly to the criterion
	// *and* no FAR it forwards through is shared with a PDR the criterion does not
	// select. Either kind of over-coverage means copies arrive that the criterion
	// does not identify.
	exact bool
	// fars are the FARs to enable duplication on, deduplicated. A FAR is listed once
	// however many selected PDRs reference it.
	fars []farRef
}

// farRef identifies one FAR of one session.
type farRef struct {
	seid  uint64
	farID uint32
}

// resolveOn resolves the criterion against the given sessions and reports what
// duplicating the result would cover. A FAR shared with PDRs the criterion does
// not select makes the coverage approximate even when every selected PDR matched
// exactly — duplication is set per FAR, so the unselected PDRs' traffic is copied
// too.
func (c criterion) resolveOn(sessions []PFCPSession) resolution {
	refs := c.resolve(sessions)
	if len(refs) == 0 {
		return resolution{exact: true}
	}

	selected := make(map[farRef]struct{}, len(refs))
	res := resolution{pdrs: refs, exact: true}
	for _, r := range refs {
		if r.cover != coverExact {
			res.exact = false
		}
		fr := farRef{seid: r.seid, farID: r.farID}
		if _, seen := selected[fr]; !seen {
			selected[fr] = struct{}{}
			res.fars = append(res.fars, fr)
		}
	}

	// A FAR is shared when some PDR referencing it was not selected. Only the
	// sessions holding a selected FAR need looking at.
	chosen := make(map[uint64]struct{}, len(res.fars))
	for _, r := range refs {
		chosen[r.seid] = struct{}{}
	}
	for i := range sessions {
		if _, ok := chosen[sessions[i].localSEID]; !ok {
			continue
		}
		for j := range sessions[i].pdrs {
			p := sessions[i].pdrs[j]
			if _, ok := selected[farRef{seid: p.fseID, farID: p.farID}]; !ok {
				continue
			}
			if c.matchPDR(p) == coverNone {
				res.exact = false

				return res
			}
		}
	}

	return res
}
