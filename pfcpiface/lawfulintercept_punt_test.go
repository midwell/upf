// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"slices"
	"testing"

	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"github.com/omec-project/util/li/x1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
)

// fakeCounters serves whatever the test wants the datapath's accounting to say.
type fakeCounters struct {
	// sent and portDropped are the egress port's output counters: copies written to the
	// shipper, and copies its write did not take.
	sent, portDropped uint64
	// dropped is the buffering stage's own discard count — loss the port never sees,
	// because a queue drops on enqueue and those copies never reach the port.
	dropped uint64
	// noQueue reproduces a pipeline whose egress stage is the merge, which has no status
	// command to ask.
	noQueue bool
	// portErr reproduces an unreachable or renamed port.
	portErr bool
	// traffic is how many copies the datapath sends, losslessly, before each counter read
	// is answered — traffic passing between two reads that are not atomic.
	traffic uint64
}

func (f *fakeCounters) ModuleCommand(_ context.Context, in *pb.CommandRequest, _ ...grpc.CallOption) (*pb.CommandResponse, error) {
	f.sent += f.traffic
	if f.noQueue || in.GetName() != liQueueModule || in.GetCmd() != "get_status" {
		return &pb.CommandResponse{Error: &pb.Error{Errmsg: "no such module"}}, nil
	}

	data, err := anypb.New(&pb.QueueCommandGetStatusResponse{Dropped: f.dropped})
	if err != nil {
		return nil, err
	}

	return &pb.CommandResponse{Data: data}, nil
}

func (f *fakeCounters) GetPortStats(_ context.Context, _ *pb.GetPortStatsRequest, _ ...grpc.CallOption) (*pb.GetPortStatsResponse, error) {
	f.sent += f.traffic
	if f.portErr {
		return &pb.GetPortStatsResponse{Error: &pb.Error{Errmsg: "no such port"}}, nil
	}

	return &pb.GetPortStatsResponse{Out: &pb.GetPortStatsResponse_Stat{
		Packets: f.sent,
		Dropped: f.portDropped,
	}}, nil
}

// TestPuntMonitorReportsNewLossOnly covers the reporting logic: content discarded
// on the way out of the datapath has to reach the ADMF, and has to do so without
// re-reporting a loss that has stopped growing.
func TestPuntMonitorReportsNewLossOnly(t *testing.T) {
	c := &fakeCounters{sent: 1000, noQueue: true}
	rec := &recordingReporter{}
	m := &liPuntMonitor{client: c, reporter: rec}

	// Nothing discarded: nothing to say.
	m.check()

	if len(rec.issues) != 0 {
		t.Fatalf("reported %v with no loss", rec.issues)
	}

	// The port's write starts failing.
	c.sent, c.portDropped = 1900, 100
	m.check()

	if len(rec.issues) != 1 || rec.issues[0] != x1.NEIssueX3PuntLost {
		t.Fatalf("reported %v, want one %s", rec.issues, x1.NEIssueX3PuntLost)
	}

	// Traffic continues with no further discards: already reported, so silent.
	// Re-reporting a static figure on every poll would bury the report that matters in noise.
	c.sent = 2900
	m.check()

	if len(rec.issues) != 1 {
		t.Errorf("reported %v; a discard count that stopped growing was reported again", rec.issues)
	}

	// More copies are discarded: that is new loss and must be reported again.
	c.sent, c.portDropped = 3800, 200
	m.check()

	if len(rec.issues) != 2 {
		t.Errorf("reported %v, want a second report when the loss grew", rec.issues)
	}
}

// TestPuntMonitorHandlesRestartAndUnknowns checks the readings that must not be
// mistaken for good news. Reporting nothing because a counter was unreadable is
// acceptable; reporting nothing because loss was misread as recovery is not.
func TestPuntMonitorHandlesRestartAndUnknowns(t *testing.T) {
	t.Run("the discard count goes down across a restart", func(t *testing.T) {
		c := &fakeCounters{sent: 4000, portDropped: 1000, noQueue: true}
		rec := &recordingReporter{}
		m := &liPuntMonitor{client: c, reporter: rec}

		m.check() // establishes a baseline of 1000 and reports it

		// The datapath restarted: a cumulative count went down, which is impossible within
		// one lifetime, so this is a new baseline rather than a recovery — and not new loss.
		c.sent, c.portDropped = 500, 10
		m.check()

		if len(rec.issues) != 1 {
			t.Fatalf("reported %v after a restart, want only the pre-restart report", rec.issues)
		}

		// The baseline must have been dropped, so the next genuine loss is reported rather
		// than being hidden under the pre-restart figure.
		c.sent, c.portDropped = 950, 60
		m.check()

		if len(rec.issues) != 2 {
			t.Errorf("reported %v, want the pre-restart report and the new one", rec.issues)
		}
	})

	// An unreadable *port* is left to the shipper, which notices its socket has gone
	// and reports x3EgressDown — a second report of the same fact from here would
	// add nothing. And it is not a reading: the baseline stands, so loss that grew
	// across the gap is still reported once the port answers again.
	t.Run("port unreachable or renamed", func(t *testing.T) {
		c := &fakeCounters{sent: 100, portDropped: 50, noQueue: true}
		rec := &recordingReporter{}
		m := &liPuntMonitor{client: c, reporter: rec}

		m.check() // reports the 50

		c.portErr = true
		m.check()

		if len(rec.issues) != 1 {
			t.Fatalf("reported %v; an unreadable port is the shipper's to report", rec.issues)
		}

		c.portErr, c.portDropped = false, 80
		m.check()

		if len(rec.issues) != 2 {
			t.Errorf("reported %v; loss that grew while the port was unreadable was not reported",
				rec.issues)
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

// TestPuntMonitorSeesTheQueuesOwnDiscards: the port's discard count is blind to the queue in
// front of it.
//
// A queue discards on *enqueue*, when it is full, so the copies it drops never reach the port
// and the port's counters say nothing about them: during sustained overflow the port sends
// everything it is given and its discard count stays exactly zero while content is being lost.
// The queue's own counter is the one that sees it.
func TestPuntMonitorSeesTheQueuesOwnDiscards(t *testing.T) {
	c := &fakeCounters{sent: 1000}
	rec := &recordingReporter{}
	m := &liPuntMonitor{client: c, reporter: rec}

	m.check()
	if n := len(rec.reported()); n != 0 {
		t.Fatalf("reported %d faults before any loss", n)
	}

	// A burst overflows the queue. The port sends everything the queue dequeued, so its
	// discard count does not move.
	c.sent, c.dropped = 2000, 500

	m.check()

	if !slices.Contains(rec.reported(), x1.NEIssueX3PuntLost) {
		t.Errorf("content was discarded by the egress queue and reported as %v: the port's "+
			"discard count cannot see copies that never reached it", rec.reported())
	}

	// A steady figure is one fault, not a fault per poll.
	before := len(rec.reported())
	m.check()
	if now := len(rec.reported()); now != before {
		t.Errorf("a discard count that stopped growing was reported again (%d → %d)", before, now)
	}
}

// TestPuntMonitorDoesNotMistakeTrafficForLoss is the sampling half.
//
// The counter reads are not atomic, and live interception keeps copies moving between them.
// Inferring loss from two reads of moving packet counters — what was handed to the port
// against what it sent — makes that traffic look like loss on every poll it straddles, so a
// lossless egress would report X3 content loss to the ADMF. A cumulative discard count does
// not move with traffic, only with discards.
func TestPuntMonitorDoesNotMistakeTrafficForLoss(t *testing.T) {
	// Lossless traffic: 200 copies sent before each read is answered, none discarded.
	c := &fakeCounters{sent: 1000, traffic: 200}
	rec := &recordingReporter{}
	m := &liPuntMonitor{client: c, reporter: rec}

	for range 5 {
		m.check()
	}

	if len(rec.issues) != 0 {
		t.Errorf("lossless traffic was reported as %v: copies passing between two counter reads "+
			"are not copies discarded", rec.issues)
	}

	// And real loss in the middle of the same traffic is still seen.
	c.portDropped = 7
	m.check()

	if len(rec.issues) != 1 || rec.issues[0] != x1.NEIssueX3PuntLost {
		t.Errorf("reported %v, want one %s once copies were discarded", rec.issues, x1.NEIssueX3PuntLost)
	}
}
