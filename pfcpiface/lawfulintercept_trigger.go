// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
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
// The PFCP DUPL apply-action remains the mechanism that replicates packets;
// this interface supplies the identity of what is replicated. The
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
// general operator log.
func startTriggerListener(cfg *LiConfig, serverTLS *tls.Config, reporter neIssueReporter, enabler *ccEnabler) (*store.Store, error) {
	// Parse the fail-safe window before anything is bound. Doing it afterwards left
	// a listener accepting and applying tasking into a store this function had
	// already abandoned by returning an error — an element that looks un-tasked to
	// its operator while quietly holding warrants.
	keepalive, err := triggerKeepalive(cfg.TriggerKeepalive)
	if err != nil {
		return nil, err
	}

	tasks := store.New()
	if enabler != nil {
		enabler.tasks = tasks
	}
	// RequireResolvableDIDs is what lets the triggering function find out that this
	// POI has lost the destination it provisioned — after a restart, say. Accepting
	// such a trigger would mean duplicating a subject's traffic and discarding every
	// copy while the triggering function is told interception is running, which is
	// exactly what used to happen. The purge hook is what keeps the fail-safe from
	// being silent: interception stopping is the safe outcome, but only if somebody
	// is told it happened.
	// Reports are throttled per type, so a purge of many tasks yields one.
	//
	// Deliberately *without* x1.WithConfiguredDestinations, which the AMF and SMF do wire.
	// A triggered POI takes its destinations from the function that triggered it and from
	// nowhere else: the capability requires that a network function "SHALL NOT synthesise a
	// missing task attribute from local state or configuration", and letting an operator
	// declare a destination here would give the UPF an X3 endpoint the CC-TF never
	// provisioned. Adding it for symmetry with the other two POIs would be a regression, not
	// a tidy-up.
	srv := x1.NewServer(tasks, cfg.NEID,
		x1.WithADMF(cfg.TFID),
		x1.RequireResolvableDIDs(),
		x1.OnDeactivate(func(types.InterceptTask) {
			// Whatever duplication this task required and no remaining task does is
			// withdrawn, before the report: interception stopping is the outcome being
			// reported, so it must actually have stopped.
			enabler.retask()
			if reporter != nil {
				reporter.Notify(x1.NEIssueTaskingPurged,
					"content interception tasking removed; the triggering function went quiet")
			}
		}),
		// A task is refused unless every detection criterion is one this datapath can
		// resolve. Acknowledging one it cannot leaves the triggering function believing
		// an interception is running that can never produce anything — and nothing
		// outside this element could discover that.
		x1.CanApply(enabler.canApply),
		// The traffic a criterion identifies may be traffic the SMF never marked, so
		// accepting the task is not enough: duplication has to be enabled for it here.
		// Modifications reach this too, since x1 treats a retarget as an activation.
		x1.OnActivate(func(types.InterceptTask) { enabler.retask() }),
		// Someone in the LI trust domain trying to trigger this CC-POI as a triggering
		// function it is not would be aiming a subject's traffic at a destination of
		// their choosing. It is refused, but this element logs nothing by design, so
		// without this the attempt leaves no trace at all.
		x1.OnAuthFailure(func(code int) {
			if reporter != nil {
				reporter.Notify(x1.NEIssueX1AuthFailed,
					fmt.Sprintf("LI_T3 triggering refused: peer failed authentication (error %d)", code))
			}
		}))

	// ListenConfig.Listen rather than net.Listen so the listen carries a context
	// (the linter's noctx rule); the bind is otherwise unchanged.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", cfg.X1Listen)
	if err != nil {
		if reporter != nil {
			reporter.Notify(x1.NEIssueX1ListenFailed, "X1 listener bind failed")
		}

		return nil, fmt.Errorf("li: X1 listen on %s: %w", cfg.X1Listen, err)
	}

	// Mutual TLS with the identity binding checked per message by x1.Server: the
	// certificate proves the peer is in the LI domain, the binding proves it is the
	// triggering function we were told to accept.
	// NewListener supplies the properties every X1 endpoint needs and none of the
	// three network functions should be trusted to remember separately: a discarded
	// error log and per-phase timeouts, without which an unauthenticated peer can
	// hold connections open until this element can no longer be untasked.
	httpSrv := x1.NewListener(srv, serverTLS)
	// Certificates come from TLSConfig, so the file arguments are empty. ServeTLS
	// blocks until the listener is closed and then returns; the bind already
	// succeeded above, so its return is not actionable here.
	//nolint:errcheck // serve-until-close; a bind failure already surfaced above
	go func() { _ = httpSrv.ServeTLS(ln, "", "") }()

	// The keepalive fail-safe (TS 103 221-1), applied to the triggering interface
	// for the reason it exists: a triggering function that goes away must not leave
	// interception running behind it. The same mechanism already guards the ADMF
	// path on the AMF and SMF. A nil stop channel means it runs for as long as this
	// element can hold tasking, which is the whole point.
	if keepalive > 0 {
		go srv.WatchKeepalive(keepalive, nil)
	}

	return tasks, nil
}

// triggerKeepalive validates the configured fail-safe window. An empty value
// leaves the fail-safe off and yields zero; anything unparseable or non-positive
// is an error rather than a silent "off", since a deployment that asked for the
// fail-safe and did not get it holds tasking nothing will ever reclaim.
func triggerKeepalive(v string) (time.Duration, error) {
	if v == "" {
		return 0, nil
	}

	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("li: invalid trigger_keepalive %q", v)
	}

	return d, nil
}

// lookupTrigger returns the LI_T3 task covering the PFCP session identified by
// seid, how many tasks cover it in all, and whether any does. The F-SEID is the
// detection criterion the CC-TF sends (TS 33.128 table 6.2.3-7, "PFCP Session
// ID") and the value the datapath tags onto every duplicated packet, so it is
// what ties a copy on the wire back to the warrant that authorised taking it.
//
// Delivering one copy per warrant is multi-agency work this does not attempt, so
// when several warrants cover one session the first is chosen. What matters is
// that "first" is the same on every packet: store.Match orders by XID precisely
// so this choice is stable. Picking from a map's iteration order instead — as this
// did — scattered one session's packets across the covering warrants at random,
// leaving every agency with a partial stream and none with a usable one. The count
// is returned so the caller can tell the ADMF that a warrant is being served
// nothing, which is the part of this compromise that must not stay quiet.
func lookupTrigger(tasks *store.Store, enabler *ccEnabler, seid uint64) (types.InterceptTask, copyFilter, int, bool) {
	if tasks == nil || seid == 0 {
		return types.InterceptTask{}, copyFilter{}, 0, false
	}

	// A task may be keyed by any of the detection criteria of table 6.2.3-7, most of
	// which name something other than a session — an address, a tunnel, a network
	// instance. Only the duplication control can say whether such a criterion selects
	// traffic in this session, since answering needs the session's own rules.
	matched := enabler.tasksCovering(seid)
	if len(matched) == 0 {
		// Without duplication control there is no session state to resolve against, so
		// the only criterion that can be answered is the session identity itself, which
		// covers a whole session and so needs no filtering. This is the path a shipper
		// built without a datapath takes.
		for _, task := range tasks.Match(types.TargetIdentifier{
			Type:  types.TargetFSEID,
			Value: strconv.FormatUint(seid, 10),
		}) {
			matched = append(matched, coveredTask{task: task, filter: unfiltered()})
		}
	}
	if len(matched) == 0 {
		return types.InterceptTask{}, copyFilter{}, 0, false
	}

	return matched[0].task, matched[0].filter, len(matched), true
}
