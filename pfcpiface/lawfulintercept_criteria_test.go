// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"encoding/hex"
	"math"
	"net"
	"testing"

	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
)

// The sessions these tests resolve against, chosen so that each criterion has
// something it must select and something it must not:
//
//	seid 100 — the target: UE 10.250.0.9, uplink TEID 0x1001 on 10.76.0.2, DNN
//	           "internet". Its two PDRs reference separate FARs, so a criterion
//	           selecting one direction covers exactly that direction.
//	seid 200 — another subscriber on the same DNN, so a network-instance criterion
//	           must select it too and an address criterion must not.
//	seid 300 — a session whose uplink and downlink PDRs share one FAR, which is how
//	           duplication comes to over-collect: enabling it on that FAR copies the
//	           direction the criterion did not select.
const (
	targetSEID = uint64(100)
	otherSEID  = uint64(200)
	sharedSEID = uint64(300)
)

func testNetInstance() string { return "internet" }

func criteriaSessions() []PFCPSession {
	ue := ip2int(net.ParseIP("10.250.0.9"))
	n3 := ip2int(net.ParseIP("10.76.0.2"))

	return []PFCPSession{
		{
			localSEID: targetSEID,
			PacketForwardingRules: PacketForwardingRules{
				pdrs: []pdr{
					uplinkPDR(targetSEID, 1, 0x1001, n3, ue),
					downlinkPDR(targetSEID, 2, ue),
				},
				fars: []far{{farID: 1, fseID: targetSEID}, {farID: 2, fseID: targetSEID}},
			},
		},
		{
			localSEID: otherSEID,
			PacketForwardingRules: PacketForwardingRules{
				pdrs: []pdr{
					uplinkPDR(otherSEID, 1, 0x2001, n3, ip2int(net.ParseIP("10.250.0.10"))),
				},
				fars: []far{{farID: 1, fseID: otherSEID}},
			},
		},
		{
			localSEID: sharedSEID,
			PacketForwardingRules: PacketForwardingRules{
				pdrs: []pdr{
					uplinkPDR(sharedSEID, 9, 0x3001, n3, ip2int(net.ParseIP("10.250.0.11"))),
					downlinkPDR(sharedSEID, 9, ip2int(net.ParseIP("10.250.0.11"))),
				},
				fars: []far{{farID: 9, fseID: sharedSEID}},
			},
		},
	}
}

// uplinkPDR builds the uplink rule of a session. Its PDR ID is always 1: the
// downlink rule takes 2, matching how the SMF numbers them.
func uplinkPDR(seid uint64, farID, teid, n3, ue uint32) pdr {
	return pdr{
		pdrID: 1, fseID: seid, farID: farID,
		srcIface: access, srcIfaceMask: 0xff,
		tunnelTEID: teid, tunnelTEIDMask: math.MaxUint32,
		tunnelIP4Dst: n3, tunnelIP4DstMask: math.MaxUint32,
		ueAddress:       ue,
		qerIDList:       []uint32{4},
		networkInstance: testNetInstance(),
		appFilter: applicationFilter{
			srcIP: ue, srcIPMask: math.MaxUint32,
			srcPortRange: newWildcardPortRange(), dstPortRange: newWildcardPortRange(),
		},
	}
}

// downlinkPDR builds the downlink rule of a session, PDR ID 2 to the uplink's 1.
func downlinkPDR(seid uint64, farID, ue uint32) pdr {
	return pdr{
		pdrID: 2, fseID: seid, farID: farID,
		srcIface: core, srcIfaceMask: 0xff,
		ueAddress:       ue,
		qerIDList:       []uint32{4},
		networkInstance: testNetInstance(),
		appFilter: applicationFilter{
			dstIP: ue, dstIPMask: math.MaxUint32,
			srcPortRange: newWildcardPortRange(), dstPortRange: newWildcardPortRange(),
		},
	}
}

// sel is one expected selection: a PDR of a session, and how closely it
// corresponds to the criterion.
type sel struct {
	seid  uint64
	pdrID uint32
	cover coverage
}

// TestResolveCriteria checks which PDRs each detection criterion of TS 33.128
// table 6.2.3-7 selects across every live session, including the criteria that
// select nothing. Selecting the wrong PDRs is not a visible failure at runtime —
// it silently intercepts another subscriber's traffic, or none — so each case
// pins the exact set.
func TestResolveCriteria(t *testing.T) {
	sessions := criteriaSessions()
	niHex := hex.EncodeToString([]byte(testNetInstance()))

	cases := []struct {
		name string
		id   types.TargetIdentifier
		want []sel
	}{
		{
			name: "PFCP session ID selects both directions of one session",
			id:   types.TargetIdentifier{Type: types.TargetFSEID, Value: "100"},
			want: []sel{{targetSEID, 1, coverExact}, {targetSEID, 2, coverExact}},
		},
		{
			name: "PFCP session ID of no live session selects nothing",
			id:   types.TargetIdentifier{Type: types.TargetFSEID, Value: "999"},
			want: nil,
		},
		{
			name: "F-TEID selects the uplink PDR that matches on the tunnel",
			id:   types.TargetIdentifier{Type: types.TargetFTEID, Value: "4097"}, // 0x1001
			want: []sel{{targetSEID, 1, coverExact}},
		},
		{
			name: "F-TEID with the wrong node address selects nothing",
			id:   types.TargetIdentifier{Type: types.TargetFTEID, Value: "4097@10.76.0.99"},
			want: nil,
		},
		{
			name: "F-TEID with the right node address still selects it",
			id:   types.TargetIdentifier{Type: types.TargetFTEID, Value: "4097@10.76.0.2"},
			want: []sel{{targetSEID, 1, coverExact}},
		},
		{
			name: "UE address selects both directions, and only that subscriber",
			id:   types.TargetIdentifier{Type: types.TargetUEIPv4, Value: "10.250.0.9"},
			want: []sel{{targetSEID, 1, coverExact}, {targetSEID, 2, coverExact}},
		},
		{
			name: "an unattached UE address selects nothing",
			id:   types.TargetIdentifier{Type: types.TargetUEIPv4, Value: "10.250.0.99"},
			want: nil,
		},
		{
			name: "PDR ID selects that rule in every session holding it",
			id:   types.TargetIdentifier{Type: types.TargetPDRID, Value: "2"},
			want: []sel{{targetSEID, 2, coverExact}, {sharedSEID, 2, coverExact}},
		},
		{
			name: "QER ID selects every PDR the QER polices",
			id:   types.TargetIdentifier{Type: types.TargetQERID, Value: "4"},
			want: []sel{
				{targetSEID, 1, coverExact},
				{targetSEID, 2, coverExact},
				{otherSEID, 1, coverExact},
				{sharedSEID, 1, coverExact},
				{sharedSEID, 2, coverExact},
			},
		},
		{
			name: "QER ID no session uses selects nothing",
			id:   types.TargetIdentifier{Type: types.TargetQERID, Value: "77"},
			want: nil,
		},
		{
			name: "network instance spans every session on the DNN",
			id:   types.TargetIdentifier{Type: types.TargetNetworkInstance, Value: niHex},
			want: []sel{
				{targetSEID, 1, coverExact},
				{targetSEID, 2, coverExact},
				{otherSEID, 1, coverExact},
				{sharedSEID, 1, coverExact},
				{sharedSEID, 2, coverExact},
			},
		},
		{
			name: "another network instance selects nothing",
			id: types.TargetIdentifier{
				Type: types.TargetNetworkInstance, Value: hex.EncodeToString([]byte("ims")),
			},
			want: nil,
		},
		{
			name: "inbound direction selects the uplink PDRs only",
			id:   types.TargetIdentifier{Type: types.TargetGTPTunnelDirection, Value: x1.GTPDirectionInbound},
			want: []sel{{targetSEID, 1, coverExact}, {otherSEID, 1, coverExact}, {sharedSEID, 1, coverExact}},
		},
		{
			name: "outbound direction selects the downlink PDRs only",
			id:   types.TargetIdentifier{Type: types.TargetGTPTunnelDirection, Value: x1.GTPDirectionOutbound},
			want: []sel{{targetSEID, 2, coverExact}, {sharedSEID, 2, coverExact}},
		},
		{
			name: "a port on wildcard rules selects them as broader than the criterion",
			id:   types.TargetIdentifier{Type: types.TargetTCPPort, Value: "443"},
			want: []sel{
				{targetSEID, 1, coverBroader},
				{targetSEID, 2, coverBroader},
				{otherSEID, 1, coverBroader},
				{sharedSEID, 1, coverBroader},
				{sharedSEID, 2, coverBroader},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cr, err := parseCriterion(c.id)
			if err != nil {
				t.Fatalf("parseCriterion(%+v): %v", c.id, err)
			}
			got := cr.resolve(sessions)
			if len(got) != len(c.want) {
				t.Fatalf("selected %v, want %v", got, c.want)
			}
			for i, w := range c.want {
				if got[i].seid != w.seid || got[i].pdrID != w.pdrID || got[i].cover != w.cover {
					t.Errorf("selection %d = %v, want pdr(seid=%d, id=%d, %s)",
						i, got[i], w.seid, w.pdrID, w.cover)
				}
			}
		})
	}
}

// TestResolvePortCriterionAgainstSDFFilter covers the port cases the wildcard
// sessions above cannot: a PDR whose SDF filter does constrain the port, and one
// whose filter constrains it to something else.
func TestResolvePortCriterionAgainstSDFFilter(t *testing.T) {
	ue := ip2int(net.ParseIP("10.250.0.9"))
	withFilter := func(direction uint8, proto uint8, low, high uint16) pdr {
		p := pdr{
			pdrID: 1, fseID: targetSEID, farID: 1,
			srcIface: direction, srcIfaceMask: 0xff, ueAddress: ue,
			appFilter: applicationFilter{proto: proto, protoMask: 0xff},
		}
		r := portRange{low: low, high: high}
		if direction == access {
			p.appFilter.srcPortRange, p.appFilter.dstPortRange = r, newWildcardPortRange()
		} else {
			p.appFilter.srcPortRange, p.appFilter.dstPortRange = newWildcardPortRange(), r
		}

		return p
	}

	cases := []struct {
		name string
		p    pdr
		id   types.TargetIdentifier
		want coverage
	}{
		{
			// The UE is the source uplink, so the criterion's port is the source port.
			name: "uplink exact match on the UE's port",
			p:    withFilter(access, protoTCP, 443, 443),
			id:   types.TargetIdentifier{Type: types.TargetTCPPort, Value: "443"},
			want: coverExact,
		},
		{
			name: "uplink filter on another port",
			p:    withFilter(access, protoTCP, 80, 80),
			id:   types.TargetIdentifier{Type: types.TargetTCPPort, Value: "443"},
			want: coverNone,
		},
		{
			// The UE is the destination downlink, so it is the destination port that
			// describes the UE's port — reading the source port here would intercept
			// on the far end's port instead.
			name: "downlink exact match on the UE's port",
			p:    withFilter(core, protoTCP, 443, 443),
			id:   types.TargetIdentifier{Type: types.TargetTCPPort, Value: "443"},
			want: coverExact,
		},
		{
			name: "a range containing the port is broader",
			p:    withFilter(access, protoTCP, 400, 500),
			id:   types.TargetIdentifier{Type: types.TargetTCPPort, Value: "443"},
			want: coverBroader,
		},
		{
			name: "a UDP criterion does not match a TCP filter",
			p:    withFilter(access, protoTCP, 443, 443),
			id:   types.TargetIdentifier{Type: types.TargetUDPPort, Value: "443"},
			want: coverNone,
		},
		{
			name: "a UDP criterion matches a UDP filter",
			p:    withFilter(access, protoUDP, 2152, 2152),
			id:   types.TargetIdentifier{Type: types.TargetUDPPort, Value: "2152"},
			want: coverExact,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cr, err := parseCriterion(c.id)
			if err != nil {
				t.Fatalf("parseCriterion: %v", err)
			}
			if got := cr.matchPDR(c.p); got != c.want {
				t.Errorf("coverage = %s, want %s", got, c.want)
			}
		})
	}
}

// TestResolveReportsCoverage checks task 2.3's question: would duplicating the
// selected PDRs collect exactly the criterion's traffic, or more? It decides
// whether the copies have to be filtered, so a wrong "exact" here means
// over-collection reaching a mediation function.
func TestResolveReportsCoverage(t *testing.T) {
	sessions := criteriaSessions()

	cases := []struct {
		name      string
		id        types.TargetIdentifier
		wantExact bool
		wantFARs  []farRef
	}{
		{
			// Both PDRs selected, and both of the session's FARs, so nothing else
			// forwards through them.
			name:      "a session's own FARs cover it exactly",
			id:        types.TargetIdentifier{Type: types.TargetFSEID, Value: "100"},
			wantExact: true,
			wantFARs:  []farRef{{targetSEID, 1}, {targetSEID, 2}},
		},
		{
			// FAR 1 is the uplink FAR of that session alone.
			name:      "one direction of a session with separate FARs is exact",
			id:        types.TargetIdentifier{Type: types.TargetFTEID, Value: "4097"},
			wantExact: true,
			wantFARs:  []farRef{{targetSEID, 1}},
		},
		{
			// Session 300's two PDRs share FAR 9, so enabling duplication for the
			// uplink one copies the downlink too.
			name:      "a shared FAR makes one direction approximate",
			id:        types.TargetIdentifier{Type: types.TargetPDRID, Value: "1"},
			wantExact: false,
			wantFARs:  []farRef{{targetSEID, 1}, {otherSEID, 1}, {sharedSEID, 9}},
		},
		{
			// Wildcard rules carry the port along with every other, so the copies must
			// be filtered whatever the FAR structure.
			name:      "a port on wildcard rules is approximate",
			id:        types.TargetIdentifier{Type: types.TargetTCPPort, Value: "443"},
			wantExact: false,
			wantFARs:  []farRef{{targetSEID, 1}, {targetSEID, 2}, {otherSEID, 1}, {sharedSEID, 9}},
		},
		{
			// Nothing selected is trivially exact: there is nothing to over-collect.
			name:      "selecting nothing needs no filtering",
			id:        types.TargetIdentifier{Type: types.TargetUEIPv4, Value: "10.250.0.99"},
			wantExact: true,
			wantFARs:  nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cr, err := parseCriterion(c.id)
			if err != nil {
				t.Fatalf("parseCriterion: %v", err)
			}
			res := cr.resolveOn(sessions)
			if res.exact != c.wantExact {
				t.Errorf("exact = %v, want %v (selected %v)", res.exact, c.wantExact, res.pdrs)
			}
			if len(res.fars) != len(c.wantFARs) {
				t.Fatalf("FARs = %v, want %v", res.fars, c.wantFARs)
			}
			for i, w := range c.wantFARs {
				if res.fars[i] != w {
					t.Errorf("FAR %d = %+v, want %+v", i, res.fars[i], w)
				}
			}
		})
	}
}

// TestParseCriterionRefusals checks that the criteria this agent cannot resolve
// are refused here rather than resolving to an empty selection. The two are very
// different: an empty selection is a task waiting for a session to appear, while a
// criterion that can never be evaluated is an interception that will never produce
// anything, and the triggering function has to be told.
func TestParseCriterionRefusals(t *testing.T) {
	cases := []struct {
		name string
		id   types.TargetIdentifier
	}{
		{
			name: "UE IPv6, which this datapath has no state for",
			id:   types.TargetIdentifier{Type: types.TargetUEIPv6, Value: "2001:db8::9"},
		},
		{
			name: "an encoded PDR, which needs comparison semantics we do not have",
			id:   types.TargetIdentifier{Type: types.TargetPDR, Value: "0a01"},
		},
		{
			name: "a subscriber identity, which the UPF holds none of",
			id:   types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"},
		},
		{
			name: "a malformed session ID",
			id:   types.TargetIdentifier{Type: types.TargetFSEID, Value: "not-a-number"},
		},
		{
			name: "a malformed UE address",
			id:   types.TargetIdentifier{Type: types.TargetUEIPv4, Value: "10.250.0"},
		},
		{
			name: "an IPv6 literal in the IPv4 arm",
			id:   types.TargetIdentifier{Type: types.TargetUEIPv4, Value: "2001:db8::9"},
		},
		{
			name: "a port of zero",
			id:   types.TargetIdentifier{Type: types.TargetTCPPort, Value: "0"},
		},
		{
			name: "a port beyond the range",
			id:   types.TargetIdentifier{Type: types.TargetUDPPort, Value: "65536"},
		},
		{
			name: "an odd-length network instance, which is not hexBinary",
			id:   types.TargetIdentifier{Type: types.TargetNetworkInstance, Value: "abc"},
		},
		{
			name: "a direction outside the enumeration",
			id:   types.TargetIdentifier{Type: types.TargetGTPTunnelDirection, Value: "sideways"},
		},
		{
			name: "a tunnel address that is not an address",
			id:   types.TargetIdentifier{Type: types.TargetFTEID, Value: "4097@nowhere"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseCriterion(c.id); err == nil {
				t.Errorf("parseCriterion(%+v) accepted a criterion it cannot resolve", c.id)
			}
		})
	}
}
