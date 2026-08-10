// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"testing"

	"github.com/omec-project/li/x1"
	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"google.golang.org/grpc"
)

// fakeCounters serves whatever the test wants the datapath's accounting to say.
type fakeCounters struct {
	handed, sent uint64
	// noGates reproduces a pipeline whose gate tracking is off, where the merge
	// module reports no gate accounting at all.
	noGates bool
	// moduleErr and portErr reproduce an unreachable or renamed target.
	moduleErr, portErr bool
}

func (f *fakeCounters) GetModuleInfo(_ context.Context, _ *pb.GetModuleInfoRequest, _ ...grpc.CallOption) (*pb.GetModuleInfoResponse, error) {
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
