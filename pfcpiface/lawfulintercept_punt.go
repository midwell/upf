// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"time"

	"github.com/omec-project/li/x1"
	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"google.golang.org/grpc"
)

// Content of communication leaves the datapath through a userspace socket, and a
// socket can fill. When it does, the datapath's write fails and the copy is
// discarded before any Go code sees it — so the shipper cannot report a loss it
// never witnessed, and neither can the delivery layer.
//
// That is the whole problem: a throughput ceiling is a capacity fact and design
// documents one, but *silent* loss means a mediation function receives part of the
// ordered content believing it complete, and an agency has no way to know. Decision
// D11 exists so that LI-plane faults reach the ADMF rather than failing invisibly.
//
// The only vantage point that can see the loss is the datapath's own accounting:
// the merge module counts what it handed to the egress port, the port counts what
// it managed to send, and the difference is what was dropped on the way out. The
// PFCP agent already holds a bessd channel for programming the pipeline, so it can
// read both and report the gap.

const (
	// liPuntPollInterval is how often the egress accounting is compared. Loss
	// matters in aggregate rather than per packet — the ADMF needs to know that an
	// interception is under-delivering, not which packet went missing — so this is
	// deliberately slow enough to cost nothing on a busy datapath.
	liPuntPollInterval = 30 * time.Second

	// liX3Port is the port the duplicated copies leave through.
	liX3Port = "liX3"
)

// bessCounters is the slice of the bessd API this monitor needs: two counter
// reads. Narrowed to those so the comparison logic can be tested without a
// datapath, since the logic — what counts as new loss, and what counts as a
// restart rather than a recovery — is where the mistakes would be.
type bessCounters interface {
	GetModuleInfo(ctx context.Context, in *pb.GetModuleInfoRequest, opts ...grpc.CallOption) (*pb.GetModuleInfoResponse, error)
	GetPortStats(ctx context.Context, in *pb.GetPortStatsRequest, opts ...grpc.CallOption) (*pb.GetPortStatsResponse, error)
}

// liEgressModules are the modules that may sit immediately upstream of the egress
// port, in preference order.
//
// Whichever is *adjacent* to the port is the right one to compare against: packets
// between it and the port are either sent or discarded, never in flight. A
// pipeline that buffers copies has the queue there; one that does not has the
// merge. Accepting both means the accounting keeps working when the datapath
// configuration and this binary are not upgraded in lockstep — which is not
// hypothetical, since they ship in different images.
var liEgressModules = []string{"liQueue", "liMerge"}

// liPuntMonitor watches for content discarded between the datapath and the
// shipper.
type liPuntMonitor struct {
	client   bessCounters
	reporter neIssueReporter
	// blind records that the egress accounting could not be read, so the ADMF is
	// told once rather than on every poll.
	blind bool
	// lost is the cumulative gap observed so far. Only growth is reported: the
	// absolute figure includes anything lost before this monitor started, and a
	// steady gap is one fault, not a fault per poll.
	lost uint64
}

// startLIPuntMonitor begins comparing the LI egress accounting. It is silent when
// no reporting channel is configured, because the finding it produces has nowhere
// else it may legitimately go — a general log is exactly where it must not appear.
func startLIPuntMonitor(client bessCounters, reporter neIssueReporter) {
	if client == nil || reporter == nil {
		return
	}

	m := &liPuntMonitor{client: client, reporter: reporter}
	go m.run()
}

func (m *liPuntMonitor) run() {
	ticker := time.NewTicker(liPuntPollInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.check()
	}
}

// check reads both counters once and reports any new shortfall.
func (m *liPuntMonitor) check() {
	handed, ok := m.handedToPort()
	if !ok {
		return
	}

	sent, ok := m.sentPackets()
	if !ok {
		return
	}

	// The port cannot have sent more than it was given; if it appears to have, the
	// counters were read across a datapath restart and the comparison is
	// meaningless rather than reassuring.
	if sent > handed {
		m.lost = 0

		return
	}

	lost := handed - sent
	if lost <= m.lost {
		// No new loss since the last poll. A gap that stops growing has already
		// been reported.
		m.lost = lost

		return
	}

	m.lost = lost
	// NE-level only: how much content was lost, never whose. The ADMF can act on
	// this — reduce the tasking, provision more capacity, or accept the gap — but
	// only if it is told.
	m.reporter.Notify(x1.NEIssueX3PuntLost,
		"content copies discarded at the datapath egress socket")
}

// handedToPort returns the number of duplicated packets the datapath passed to the
// egress port. Anything the port did not then send was discarded on the write.
func (m *liPuntMonitor) handedToPort() (uint64, bool) {
	for _, name := range liEgressModules {
		if n, ok := m.modulePackets(name); ok {
			return n, true
		}
	}

	// Neither module is present, so this element cannot tell whether content is
	// being discarded on its way in. That is not "no loss" — it is no longer
	// knowing, which the ADMF should hear about once rather than never.
	if !m.blind {
		m.blind = true
		m.reporter.Notify(x1.NEIssueInvalidConfig,
			"content egress accounting unavailable; loss at the datapath egress cannot be detected")
	}

	return 0, false
}

// modulePackets returns the packets a module has passed out, and whether it could
// be read at all.
func (m *liPuntMonitor) modulePackets(name string) (uint64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	res, err := m.client.GetModuleInfo(ctx, &pb.GetModuleInfoRequest{Name: name})
	if err != nil || res.GetError() != nil {
		return 0, false
	}

	gates := res.GetOgates()
	if len(gates) == 0 {
		// Gate accounting is only present when the pipeline enables tracking on
		// that gate; without it there is nothing to compare and a silent zero
		// would read as "no loss".
		return 0, false
	}

	// Summing stays correct if the pipeline ever fans out.
	var total uint64
	for _, g := range gates {
		total += g.GetPkts()
	}

	return total, true
}

// sentPackets returns the number of duplicated packets the egress port managed to
// write to the shipper.
func (m *liPuntMonitor) sentPackets() (uint64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	// Unlike getPortStats, no "Fast" suffix: the LI egress is a plain
	// UnixSocketPort named exactly as the pipeline declares it.
	res, err := m.client.GetPortStats(ctx, &pb.GetPortStatsRequest{Name: liX3Port})
	if err != nil || res.GetError() != nil {
		return 0, false
	}

	return res.GetOut().GetPackets(), true
}
