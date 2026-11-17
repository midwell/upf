// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"time"

	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"github.com/omec-project/util/li/x1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
)

// Content of communication leaves the datapath through a userspace socket, and a
// socket can fill. When it does, the datapath's write fails and the copy is
// discarded before any Go code sees it — so the shipper cannot report a loss it
// never witnessed, and neither can the delivery layer.
//
// That is the whole problem: a throughput ceiling is a capacity fact and can be
// documented, but *silent* loss means a mediation function receives part of the
// ordered content believing it complete, and an agency has no way to know. LI-plane
// faults are reported so that they reach the ADMF rather than failing invisibly.
//
// The only vantage point that can see the loss is the datapath's own accounting.
// Copies are lost in two places on the way out: the egress queue discards on
// enqueue when it is full, and the egress port discards what its write did not
// take. Each keeps its own cumulative discard count. The PFCP agent already holds a
// bessd channel for programming the pipeline, so it can read both and report growth.

const (
	// liPuntPollInterval is how often the egress accounting is read. Loss
	// matters in aggregate rather than per packet — the ADMF needs to know that an
	// interception is under-delivering, not which packet went missing — so this is
	// deliberately slow enough to cost nothing on a busy datapath.
	liPuntPollInterval = 30 * time.Second

	// liX3Port is the port the duplicated copies leave through.
	liX3Port = "liX3"
)

// bessCounters is the slice of the bessd API this monitor needs: two counter
// reads. Narrowed to those so the reporting logic can be tested without a
// datapath, since the logic — what counts as new loss, and what counts as a
// restart rather than a recovery — is where the mistakes would be.
type bessCounters interface {
	// GetPortStats is how the egress port's discards are read.
	GetPortStats(ctx context.Context, in *pb.GetPortStatsRequest, opts ...grpc.CallOption) (*pb.GetPortStatsResponse, error)
	// ModuleCommand is how a module's own accounting is read — Queue.get_status here,
	// which is the only counter that sees a discard on enqueue.
	ModuleCommand(ctx context.Context, in *pb.CommandRequest, opts ...grpc.CallOption) (*pb.CommandResponse, error)
}

// liQueueModule is the buffering stage in front of the egress port.
const liQueueModule = "liQueue"

// liPuntMonitor watches for content discarded between the datapath and the
// shipper.
type liPuntMonitor struct {
	client   bessCounters
	reporter neIssueReporter
	// lost is the egress port's cumulative discard count as last read. Only growth is
	// reported, because a steady figure is one fault, not a fault per poll. It starts at
	// zero, so the first poll reports any discards already counted as growth -- including
	// ones from before this agent started, when the agent restarted and bessd did not.
	lost uint64
	// dropped is the buffering stage's own cumulative discard count, tracked the same way
	// and for the same reason. It is a separate figure rather than added to lost, because
	// the two are different losses at different points and a datapath restart resets them
	// independently.
	dropped uint64
}

// startLIPuntMonitor begins watching the LI egress accounting. It is silent when
// no reporting channel is configured, because what it detects has nowhere
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

// check reads both discard counters once and reports any new loss.
//
// Each counter is cumulative and read on its own, so traffic passing between the two reads
// changes neither: a discard count grows only when a copy is discarded. That is why the
// port's own count is read rather than inferred from what was handed to the port against
// what it sent — two separate reads of moving packet counters differ by whatever passed
// between them, which on lossless traffic reads as loss.
func (m *liPuntMonitor) check() {
	m.checkQueueDrops()
	m.checkPortDrops()
}

// checkPortDrops reports growth in the egress port's own discard count.
//
// BESS's PortOut counts a batch's unsent packets as the port's output drops — a full socket,
// no shipper connected, or a port administratively down — so this is the loss on the
// datapath's write, counted where it happens.
//
// Silent when the port cannot be read: the shipper notices its socket has gone and reports
// x3EgressDown, and a second report of the same fact from here would add nothing.
func (m *liPuntMonitor) checkPortDrops() {
	dropped, ok := m.portDropped()
	if !ok {
		return
	}

	if dropped <= m.lost {
		// Either steady — already reported — or reset by a datapath restart, which is a
		// new baseline rather than a recovery.
		m.lost = dropped

		return
	}

	m.lost = dropped
	// NE-level only: how much content was lost, never whose. The ADMF can act on
	// this — reduce the tasking, provision more capacity, or accept the gap — but
	// only if it is told.
	m.reporter.Notify(x1.NEIssueX3PuntLost,
		"content copies discarded at the datapath egress socket")
}

// checkQueueDrops reports growth in the buffering stage's own discard count.
//
// The port's count cannot see this loss: a Queue discards on enqueue, when it is full, and
// those copies never reach the port at all.
//
// Silent where the stage is not a queue, or where its status cannot be read: a pipeline
// whose egress stage is the merge has nothing to ask.
func (m *liPuntMonitor) checkQueueDrops() {
	dropped, ok := m.queueDropped()
	if !ok {
		return
	}

	if dropped <= m.dropped {
		// Either steady — already reported — or reset by a datapath restart, which is a
		// new baseline rather than a recovery.
		m.dropped = dropped

		return
	}

	m.dropped = dropped
	m.reporter.Notify(x1.NEIssueX3PuntLost,
		"content copies discarded by the datapath egress queue")
}

// queueDropped reads the egress queue's cumulative discard count, and reports whether
// there was one to read.
func (m *liPuntMonitor) queueDropped() (uint64, bool) {
	arg, err := anypb.New(&pb.QueueCommandGetStatusArg{})
	if err != nil {
		return 0, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	res, err := m.client.ModuleCommand(ctx, &pb.CommandRequest{
		Name: liQueueModule,
		Cmd:  "get_status",
		Arg:  arg,
	})
	if err != nil || res.GetError() != nil {
		// No queue in this pipeline, or a datapath that will not answer. Neither is a
		// statement about loss.
		return 0, false
	}

	var status pb.QueueCommandGetStatusResponse
	if err := res.GetData().UnmarshalTo(&status); err != nil {
		return 0, false
	}

	return status.GetDropped(), true
}

// portDropped reads the egress port's cumulative discard count, and reports whether
// there was one to read.
func (m *liPuntMonitor) portDropped() (uint64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	// Unlike getPortStats, no "Fast" suffix: the LI egress is a plain
	// UnixSocketPort named exactly as the pipeline declares it.
	res, err := m.client.GetPortStats(ctx, &pb.GetPortStatsRequest{Name: liX3Port})
	if err != nil || res.GetError() != nil {
		return 0, false
	}

	return res.GetOut().GetDropped(), true
}
