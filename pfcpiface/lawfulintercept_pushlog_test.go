// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"errors"
	"testing"

	"github.com/omec-project/upf-epc/logger"
	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// A write the interception plane makes on its own, outside any PFCP procedure, writes nothing to
// the general log, whether the datapath takes it, refuses it, fails the RPC or does not answer in
// time. Each rule of a batch is logged with its session's F-SEID and tunnel, and a failure with
// the module it failed in, so a push logged like a modification would show an operator which
// session a tasking had just reached, with no PFCP Session Modification before it. Path
// monitoring is on, so the registration a FAR's tunnel brings is covered too.
func TestAnInterceptionPushWritesNothingToTheGeneralLog(t *testing.T) {
	shortTimeout(t)

	saved := enableGtpuPathMonitoring
	enableGtpuPathMonitoring = true
	t.Cleanup(func() { enableGtpuPathMonitoring = saved })

	core, logs := observer.New(zapcore.DebugLevel)
	savedLog := logger.BessLog
	logger.BessLog = zap.New(core).Sugar()
	t.Cleanup(func() { logger.BessLog = savedLog })

	// Never released: a worker let go after the join gave up would go on to log and to read the
	// path-monitoring flag while the cleanups above put them back.
	blocked := &bess{client: blockingModuleStub{release: make(chan struct{})}}
	blocked.readQciQosMap(&Conf{})

	rules := PacketForwardingRules{fars: []far{{
		farID: 1, fseID: 0x2632898145f4d191, applyAction: ActionForward, liDuplicate: true,
		tunnelType: 1, tunnelIP4Dst: 0x0ac800c9, tunnelTEID: 0x1001, tunnelPort: 2152,
	}}}

	for _, tc := range []struct {
		name string
		b    *bess
	}{
		{"accepted", answeringBess(&pb.CommandResponse{}, nil)},
		{"table full", answeringBess(&pb.CommandResponse{Error: &pb.Error{Code: errnoNoSpace, Errmsg: msgTableFull}}, nil)},
		{"rpc failed", answeringBess(nil, errors.New("connection refused"))},
		{"timed out", blocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs.TakeAll()
			u := &upf{datapath: tc.b}

			u.sendDuplicationPush(PacketForwardingRules{}, rules)

			if n := logs.Len(); n != 0 {
				t.Errorf("the interception push wrote %d general-log entries, want 0: %v", n, logs.TakeAll())
			}

			// The same write made by a PFCP Session Modification is logged, so the zero above
			// can only be because the push was kept out.
			u.sendDuplicationWrite(upfMsgTypeMod, PacketForwardingRules{}, rules)

			if logs.Len() == 0 {
				t.Error("a modification's write logged nothing, so the zero above shows nothing")
			}
		})
	}
}
