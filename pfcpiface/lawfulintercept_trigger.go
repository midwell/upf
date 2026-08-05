// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"

	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
)

// The UPF is a triggered CC-POI: it does not learn about warrants from the ADMF.
// The CC Triggering Function in the SMF tasks it over LI_T3, which TS 33.128
// clause 5.2.6 realises as ETSI TS 103 221-1 with the CC-TF in the role of the
// "ADMF" and this CC-POI in the role of the "NE". Each trigger names the PFCP
// session to intercept and carries what the datapath cannot know: the warrant XID
// to label content with, the correlation identifier that joins it to the SMF's
// signalling, and where to deliver it.
//
// The PFCP DUPL apply-action remains the mechanism that replicates packets
// (design D14); this interface supplies the identity of what is replicated. The
// two therefore arrive over different interfaces and can disagree — content whose
// session has no trigger must not be delivered, since it could only be labelled
// with an XID no mediation function can attribute.

// startTriggerListener binds the LI_T3 triggering interface and returns the task
// store the shipper matches duplicated content against.
//
// The bind is synchronous so a failure reaches the caller: a CC-POI that looks
// enabled but can never be tasked performs no interception, and the whole point
// of failing closed here is that this is not discoverable from the outside.
// Nothing is logged — that this NE can be tasked at all must not appear in a
// general operator log (review R25/R27).
func startTriggerListener(cfg *LiConfig, serverTLS *tls.Config, reporter neIssueReporter) (*store.Store, error) {
	tasks := store.New()
	// RequireResolvableDIDs is what lets the triggering function find out that this
	// POI has lost the destination it provisioned — after a restart, say. Accepting
	// such a trigger would mean duplicating a subject's traffic and discarding every
	// copy while the triggering function is told interception is running, which is
	// exactly what happened before review R37.
	// The purge hook is what keeps the fail-safe from being silent: interception
	// stopping is the safe outcome, but only if somebody is told it happened.
	// Reports are throttled per type, so a purge of many tasks yields one.
	srv := x1.NewServer(tasks, cfg.NEID,
		x1.WithADMF(cfg.TFID),
		x1.RequireResolvableDIDs(),
		x1.OnDeactivate(func(types.InterceptTask) {
			if reporter != nil {
				_ = reporter.ReportNEIssue(x1.NEIssueTaskingPurged,
					"content interception tasking removed; the triggering function went quiet")
			}
		}))

	ln, err := net.Listen("tcp", cfg.X1Listen)
	if err != nil {
		if reporter != nil {
			_ = reporter.ReportNEIssue(x1.NEIssueX1ListenFailed, "X1 listener bind failed")
		}

		return nil, fmt.Errorf("li: X1 listen on %s: %w", cfg.X1Listen, err)
	}

	// Mutual TLS with the identity binding checked per message by x1.Server: the
	// certificate proves the peer is in the LI domain, the binding proves it is the
	// triggering function we were told to accept (review R26).
	httpSrv := &http.Server{
		Handler:   srv,
		TLSConfig: serverTLS,
		// net/http writes handshake failures to the default logger, i.e. this
		// process's stderr: "http: TLS handshake error from <addr>: remote error:
		// tls: bad certificate". On an LI interface that is a disclosure — it puts
		// the LI domain's address in the general operator log and marks this NE as
		// running a mutually-authenticated listener nothing else explains. Discard
		// it; genuine faults on this interface are reported to the ADMF over X1
		// (design D11), which is the only channel allowed to know (review R35).
		ErrorLog: log.New(io.Discard, "", 0),
	}
	// Certificates come from TLSConfig, so the file arguments are empty.
	go func() { _ = httpSrv.ServeTLS(ln, "", "") }()

	// The keepalive fail-safe (TS 103 221-1), applied to the triggering interface
	// for the reason it exists: a triggering function that goes away must not leave
	// interception running behind it. The same mechanism already guards the ADMF
	// path on the AMF and SMF (design D11 Part B).
	if cfg.TriggerKeepalive != "" {
		timeout, err := time.ParseDuration(cfg.TriggerKeepalive)
		if err != nil || timeout <= 0 {
			return nil, fmt.Errorf("li: invalid trigger_keepalive %q", cfg.TriggerKeepalive)
		}

		go srv.WatchKeepalive(timeout)
	}

	return tasks, nil
}

// lookupTrigger returns the LI_T3 task covering the PFCP session identified by
// seid, and reports whether one exists. The F-SEID is the detection criterion the
// CC-TF sends (TS 33.128 table 6.2.3-7, "PFCP Session ID") and the value the
// datapath tags onto every duplicated packet, so it is what ties a copy on the
// wire back to the warrant that authorised taking it.
//
// When several warrants cover one session the first task is returned; delivering
// one copy per warrant is multi-agency work this does not attempt.
func lookupTrigger(tasks *store.Store, seid uint64) (types.InterceptTask, bool) {
	if tasks == nil || seid == 0 {
		return types.InterceptTask{}, false
	}

	matched := tasks.Match(types.TargetIdentifier{
		Type:  types.TargetFSEID,
		Value: strconv.FormatUint(seid, 10),
	})
	if len(matched) == 0 {
		return types.InterceptTask{}, false
	}

	return matched[0], true
}
