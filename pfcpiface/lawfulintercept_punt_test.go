// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"slices"
	"testing"

	"github.com/omec-project/li/x1"
	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
)

// fakeCounters serves whatever the test wants the datapath's accounting to say.
type fakeCounters struct {
	handed, sent uint64
	// dropped is the buffering stage's own discard count — the counter the
	// module-out-versus-port-sent comparison is structurally blind to, because a queue drops
	// on enqueue and counts its output gate on dequeue.
	dropped uint64
	// noQueue reproduces a pipeline whose egress stage is the merge, which has no status
	// command to ask.
	noQueue bool
	// noGates reproduces a pipeline whose gate tracking is off, where the merge
	// module reports no gate accounting at all.
	noGates bool
	// moduleErr and portErr reproduce an unreachable or renamed target.
	moduleErr, portErr bool
	// advance runs between the two counter reads, so a test can put traffic through the
	// datapath at the one instant the ordering of those reads decides the answer.
	advance func(*fakeCounters)
	// reads counts the counter reads, which is how the ordering itself is asserted.
	reads []string
}

func (f *fakeCounters) ModuleCommand(_ context.Context, in *pb.CommandRequest, _ ...grpc.CallOption) (*pb.CommandResponse, error) {
	if f.noQueue || in.GetName() != liQueueModule || in.GetCmd() != "get_status" {
		return &pb.CommandResponse{Error: &pb.Error{Errmsg: "no such module"}}, nil
	}

	data, err := anypb.New(&pb.QueueCommandGetStatusResponse{Dropped: f.dropped})
	if err != nil {
		return nil, err
	}

	return &pb.CommandResponse{Data: data}, nil
}

func (f *fakeCounters) GetModuleInfo(_ context.Context, _ *pb.GetModuleInfoRequest, _ ...grpc.CallOption) (*pb.GetModuleInfoResponse, error) {
	f.reads = append(f.reads, "module")
	if f.moduleErr {
		return &pb.GetModuleInfoResponse{Error: &pb.Error{Errmsg: "no such module"}}, nil
	}

	res := &pb.GetModuleInfoResponse{}
	if !f.noGates {
		res.Ogates = []*pb.GetModuleInfoResponse_OGate{{Pkts: f.handed}}
	}

	return res, nil
}

func (f *fakeCounters) GetPortStats(_ context.Context, _ *pb.GetPortStatsRequest, _ ...grpc.CallOption) (*pb.GetPortStatsResponse, error) {
	f.reads = append(f.reads, "port")
	// Traffic passing between the two reads, which is what the read order decides the
	// meaning of.
	if f.advance != nil {
		f.advance(f)
	}
	if f.portErr {
		return &pb.GetPortStatsResponse{Error: &pb.Error{Errmsg: "no such port"}}, nil
	}

	return &pb.GetPortStatsResponse{Out: &pb.GetPortStatsResponse_Stat{Packets: f.sent}}, nil
}

// TestPuntMonitorReportsNewLossOnly covers the reporting logic: content discarded
// on the way out of the datapath has to reach the ADMF, and has to do so without
// re-reporting a gap that has stopped growing.
func TestPuntMonitorReportsNewLossOnly(t *testing.T) {
	c := &fakeCounters{handed: 1000, sent: 1000}
	rec := &recordingReporter{}
	m := &liPuntMonitor{client: c, reporter: rec}

	// Counters agree: nothing lost, nothing to say.
	m.check()

	if len(rec.issues) != 0 {
		t.Fatalf("reported %v with no loss", rec.issues)
	}

	// A gap opens.
	c.handed, c.sent = 2000, 1900
	m.check()

	if len(rec.issues) != 1 || rec.issues[0] != x1.NEIssueX3PuntLost {
		t.Fatalf("reported %v, want one %s", rec.issues, x1.NEIssueX3PuntLost)
	}

	// Traffic continues with the same gap: already reported, so silent. Re-reporting
	// a static gap on every poll would bury the report that matters in noise.
	c.handed, c.sent = 3000, 2900
	m.check()

	if len(rec.issues) != 1 {
		t.Errorf("reported %v; a gap that stopped growing was reported again", rec.issues)
	}

	// The gap widens: that is new loss and must be reported again.
	c.handed, c.sent = 4000, 3800
	m.check()

	if len(rec.issues) != 2 {
		t.Errorf("reported %v, want a second report when the loss grew", rec.issues)
	}
}

// TestPuntMonitorHandlesRestartAndUnknowns checks the readings that must not be
// mistaken for good news. Reporting nothing because a counter was unreadable is
// acceptable; reporting nothing because loss was misread as recovery is not.
func TestPuntMonitorHandlesRestartAndUnknowns(t *testing.T) {
	t.Run("counters read backwards across a restart", func(t *testing.T) {
		c := &fakeCounters{handed: 5000, sent: 4000}
		rec := &recordingReporter{}
		m := &liPuntMonitor{client: c, reporter: rec}

		m.check() // establishes a 1000 gap and reports it

		// The datapath restarted: the port's counter now exceeds the module's,
		// which is impossible within one lifetime, so the comparison is meaningless
		// rather than a recovery.
		c.handed, c.sent = 10, 500
		m.check()

		// The baseline must have been dropped, so the next genuine gap is reported
		// rather than being hidden under the pre-restart figure.
		c.handed, c.sent = 1000, 950
		m.check()

		if len(rec.issues) != 2 {
			t.Errorf("reported %v, want the pre-restart report and the new one", rec.issues)
		}
	})

	// Losing the ability to read the accounting is not the same as reading zero
	// loss, and it must not pass for it. The ADMF hears once — repeating on every
	// poll would bury it — and the two ways of losing that ability are equivalent:
	// no such module, or a module whose gate accounting is off.
	for name, c := range map[string]*fakeCounters{
		"module unreachable or renamed": {moduleErr: true},
		"gate tracking disabled":        {noGates: true, sent: 100},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recordingReporter{}
			m := &liPuntMonitor{client: c, reporter: rec}

			m.check()
			m.check()

			if len(rec.issues) != 1 || rec.issues[0] != x1.NEIssueInvalidConfig {
				t.Errorf("reported %v, want exactly one %s", rec.issues, x1.NEIssueInvalidConfig)
			}
		})
	}

	// An unreadable *port* is left to the shipper, which notices its socket has gone
	// and reports x3EgressDown — a second report of the same fact from here would
	// add nothing.
	t.Run("port unreachable or renamed", func(t *testing.T) {
		rec := &recordingReporter{}
		m := &liPuntMonitor{client: &fakeCounters{handed: 100, portErr: true}, reporter: rec}

		m.check()

		if len(rec.issues) != 0 {
			t.Errorf("reported %v; an unreadable port is the shipper's to report", rec.issues)
		}
	})
}

// TestPuntMonitorNeedsAReportingChannel covers the deployment where no ADMF is
// configured. The finding has nowhere legitimate to go — a general log is exactly
// where interception must not appear — so the monitor does not run at all.
func TestPuntMonitorNeedsAReportingChannel(t *testing.T) {
	startLIPuntMonitor(&fakeCounters{}, nil)
	startLIPuntMonitor(nil, &recordingReporter{})
}

// TestPuntMonitorSeesTheQueuesOwnDiscards is the finding: the monitor was blind to the one
// condition it exists to detect.
//
// It compared what the module upstream of the egress port handed on against what the port
// sent, and where that module is `liQueue` — which it prefers — the comparison is
// structurally incapable of seeing the loss: a queue discards on *enqueue*, when it is full,
// and its output-gate accounting counts packets *dequeued* toward the port. So during
// sustained overflow both sides of the comparison exclude the dropped packets equally and the
// difference stays exactly zero while content is being lost.
//
// The module's own comment reasoned that packets between it and the port "are either sent or
// discarded, never in flight", which is true of a merge and false of a queue.
func TestPuntMonitorSeesTheQueuesOwnDiscards(t *testing.T) {
	// The overflow case, stated exactly: everything the queue dequeued reached the port, so
	// the comparison sees nothing, and the queue's own counter says content was dropped.
	c := &fakeCounters{handed: 1000, sent: 1000, dropped: 0}
	rec := &recordingReporter{}
	m := &liPuntMonitor{client: c, reporter: rec}

	m.check()
	if n := len(rec.reported()); n != 0 {
		t.Fatalf("reported %d faults before any loss", n)
	}

	// A burst overflows the queue. Both comparison counters advance together, because the
	// dropped copies never reached the output gate.
	c.handed, c.sent, c.dropped = 2000, 2000, 500

	m.check()

	if !slices.Contains(rec.reported(), x1.NEIssueX3PuntLost) {
		t.Errorf("content was discarded by the egress queue and reported as %v: the comparison "+
			"agrees exactly while copies are being dropped, so the condition the monitor exists "+
			"for is the one it could not detect", rec.reported())
	}

	// A steady figure is one fault, not a fault per poll.
	before := len(rec.reported())
	m.check()
	if now := len(rec.reported()); now != before {
		t.Errorf("a discard count that stopped growing was reported again (%d → %d)", before, now)
	}
}

// TestPuntMonitorDoesNotMistakeTrafficForARestart is the sampling-order half.
//
// The two reads are not atomic. Read upstream-first, traffic passing between them landed on
// the *downstream* side, so a busy egress legitimately reported sent > handed — which the
// monitor took for a datapath restart and used to clear its loss baseline, turning ordinary
// traffic into a reason to forget a real gap. Read downstream-first the same traffic makes
// the comparison conservative instead.
func TestPuntMonitorDoesNotMistakeTrafficForARestart(t *testing.T) {
	// A real gap of 100, and traffic flowing while the counters are read.
	c := &fakeCounters{handed: 1000, sent: 900, noQueue: true}
	c.advance = func(f *fakeCounters) {
		// Between the two reads, 200 more packets go through. Whichever counter is read
		// second sees them.
		f.handed += 200
		f.sent += 200
	}

	rec := &recordingReporter{}
	m := &liPuntMonitor{client: c, reporter: rec}

	m.check()

	// The port must be read first, so `handed` is the fresher of the two.
	if len(c.reads) < 2 || c.reads[0] != "port" {
		t.Errorf("counters were read in order %v, want the port first: read last, ordinary "+
			"traffic makes the port appear to have sent more than it was given", c.reads)
	}
	// And the gap is still seen rather than being cleared as a restart.
	if !slices.Contains(rec.reported(), x1.NEIssueX3PuntLost) {
		t.Error("a real gap was not reported: traffic passing between the two reads was taken " +
			"for a datapath restart, which cleared the loss baseline")
	}
	if m.lost == 0 {
		t.Error("the loss baseline was cleared, so the next poll re-reports the same gap")
	}
}
