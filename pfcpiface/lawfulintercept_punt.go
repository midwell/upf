// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

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
	// ModuleCommand is how a module's own accounting is read — Queue.get_status here,
	// which is the only counter that sees a discard on enqueue.
	ModuleCommand(ctx context.Context, in *pb.CommandRequest, opts ...grpc.CallOption) (*pb.CommandResponse, error)
}

// liEgressModules are the modules that may sit immediately upstream of the egress
// port, in preference order.
//
// Whichever is *adjacent* to the port is the right one to compare against. A pipeline that
// buffers copies has the queue there; one that does not has the merge. Accepting both means
// the accounting keeps working when the datapath configuration and this binary are not
// upgraded in lockstep — which is not hypothetical, since they ship in different images.
//
// **The comparison is sound for a merge and structurally blind for a queue**, and the
// preference order puts the queue first, so it was blind in the configuration this element
// actually runs. The reasoning it rested on — packets between the stage and the port "are
// either sent or discarded, never in flight" — is true of a merge and false of a queue: a
// queue discards on *enqueue*, and its output-gate accounting counts packets *dequeued*
// toward the port. So during sustained overflow the two counters agree exactly and the
// difference is zero: the one condition this monitor exists to detect is the one condition
// the comparison cannot see.
//
// A queue therefore has its own dropped counter read as well (see queueDropped). The
// comparison is kept for what it does handle — loss on the port's write, which is the
// merge case and is real either way.
var liEgressModules = []string{"liQueue", "liMerge"}

// liQueueModule is the buffering stage, named separately because it is the one whose
// discards the comparison cannot see.
const liQueueModule = "liQueue"

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
	// dropped is the buffering stage's own cumulative discard count, tracked the same way
	// and for the same reason. It is a separate figure rather than added to lost, because
	// the two are different losses at different points and a datapath restart resets them
	// independently.
	dropped uint64
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
	// **The buffering stage's own discards, which the comparison below cannot see.** A queue
	// drops on enqueue and counts its output gate on dequeue, so both sides of the
	// comparison exclude the dropped packets equally and the difference stays zero while
	// content is being lost.
	m.checkQueueDrops()

	// **Downstream first.** The two reads are not atomic, so traffic passing between them
	// lands on whichever side is read second. Reading the port last made a busy egress
	// legitimately report sent > handed, which the branch below then took for a datapath
	// restart and used to clear the loss baseline — turning ordinary traffic into a reason to
	// forget a real gap. Read in this order the same traffic makes the comparison
	// conservative: `handed` is at least as current as `sent`, so the difference errs toward
	// under-reporting rather than toward a false restart.
	sent, ok := m.sentPackets()
	if !ok {
		return
	}

	handed, ok := m.handedToPort()
	if !ok {
		return
	}

	// The port cannot have sent more than it was given; if it appears to have, the
	// counters were read across a datapath restart and the comparison is
	// meaningless rather than reassuring. With the reads in the order above, ordinary
	// traffic no longer produces this.
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

// checkQueueDrops reports growth in the buffering stage's own discard count.
//
// This is the counter that sees the loss the module-out-versus-port-sent comparison is
// structurally blind to: a Queue discards on enqueue, when it is full, and those packets
// never reach the output gate the comparison reads. So the comparison agrees exactly while
// copies are being dropped — the condition the monitor was built for is the one it could not
// detect.
//
// Silent where the stage is not a queue, or where its status cannot be read: a pipeline
// using the merge has nothing to ask, and an unreadable module is already reported once by
// handedToPort's blind branch rather than twice from here.
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
		// statement about loss, and handedToPort already reports the unreadable case.
		return 0, false
	}

	var status pb.QueueCommandGetStatusResponse
	if err := res.GetData().UnmarshalTo(&status); err != nil {
		return 0, false
	}

	return status.GetDropped(), true
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
