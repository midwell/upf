// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
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
// probes are the conditions this element can be asked about — the shipper's, since the
// knowledge is the shipper's. They are passed in rather than built here because this
// function owns the interface and not the delivery.
func startTriggerListener(cfg *LiConfig, serverTLS *tls.Config, reporter neIssueReporter,
	enabler *ccEnabler, ids *x2x3.Identity, onTasking func(), probes ...x1.FaultProbe,
) (*store.Store, error) {
	// Parse the fail-safe window before anything is bound. Doing it afterwards left
	// a listener accepting and applying tasking into a store this function had
	// already abandoned by returning an error — an element that looks un-tasked to
	// its operator while quietly holding warrants.
	keepalive, err := triggerKeepalive(cfg.TriggerKeepalive)
	if err != nil {
		return nil, err
	}

	tasks := store.New()
	// setTasks rather than an assignment: it also parses what the store holds, so the
	// shipping path is not left falling back to the one criterion a bare store lookup
	// can answer until the first tasking change happens to rebuild it.
	enabler.setTasks(tasks)
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
	opts := []x1.Option{
		x1.WithADMF(cfg.TFID),
		x1.RequireResolvableDIDs(),
		// What this element can observe about itself, for the triggering function that asks
		// for its status. A triggered CC-POI is the one element whose product loss is
		// invisible everywhere else: a dropped copy produces no record for anybody to miss.
		x1.WithFaultProbes(probes...),
		// One hook for the whole lifecycle: an activation, a modification and a
		// removal all change what this datapath must duplicate, and all of them are
		// answered the same way — by re-deriving duplication from the tasking that
		// remains. The triggering function may also change a task's products or its
		// criteria without touching its targets, which the previous pair of hooks
		// could not express and so did not report at all.
		x1.OnTaskChange(func(prev, next *types.InterceptTask) {
			// Whatever duplication the tasking requires now, and only that.
			//
			// onTasking is the shipper's: which destinations are in use is a function of the
			// tasking, so this is the one event that can make a delivery client
			// unreferenced. Called on every branch, including the removal below.
			if onTasking != nil {
				defer onTasking()
			}
			if next != nil {
				enabler.retask()

				// A modification keeps the *task's* XID, and leaving the numbering alone
				// is right for every modification but one: the numbering is keyed by the
				// **delivery** XID, which here is the warrant's ProductID, and a relabel
				// moves it. The context under the superseded label is then stranded —
				// every copy from this point carries the new label, so nothing will
				// number under the old one again.
				//
				// Released per context, not per XID, and this is the case that shows why:
				// the triggering function relabels a warrant's triggers one at a time, so
				// while this one is being modified its sibling sessions are still
				// delivering under the old label. Forget would take their numbering with
				// it, which is the defect this granularity exists to avoid, reached from
				// the modification path instead of the removal path.
				if prev != nil && prev.DeliveryXID() != next.DeliveryXID() {
					var corr [x2x3.CorrelationIDLength]byte
					binary.BigEndian.PutUint64(corr[:], prev.CorrelationID)
					ids.ForgetContext(prev.DeliveryXID().Bytes(), corr)
				}

				return
			}
			// A removal runs before the purge report below, and interception stopping
			// is the outcome being reported — so it must actually have stopped.
			// Re-derivation happens on the enabler's worker now, so asking is not
			// stopping: this waits for the pass it asked for, or the report would be a
			// lie in exactly the window it matters.
			enabler.retaskAndWait()
			// The numbering state goes with the tasking — **this task's context, not the
			// delivery XID's.**
			//
			// The granularity is the whole point here and it is not the same as at an
			// IRI-POI. The triggering function allocates one task per (warrant, session,
			// UPF) and gives them all the warrant's ProductID, which is what travels on
			// the wire as the XID, so several live tasks share it. Releasing by XID when
			// one PDU session ends therefore restarts the numbering of every other
			// session that warrant is still intercepting at this element — measured as a
			// sibling session's next xCC numbered 0 where it should have been 3.
			//
			// That is worse than the leak it was written to prevent. A sequence number is
			// how a mediation function detects loss, so numbering that resets under a
			// live context makes this element emit a sequence the receiver must read as
			// duplication or as a gap: the loss signal forged by the state that governs
			// it. Releasing one context leaves at worst an entry per ended session,
			// bounded by live tasking and visible through Identity.Contexts().
			//
			// Done on every removal — an ordinary withdrawal, a bulk deactivation, a
			// fail-safe purge — because the state belongs to the tasking and not to the
			// circumstances of its removal.
			var corr [x2x3.CorrelationIDLength]byte
			binary.BigEndian.PutUint64(corr[:], prev.CorrelationID)
			ids.ForgetContext(prev.DeliveryXID().Bytes(), corr)
		}),
		// A purge is reported only when nobody asked for it. An explicit
		// DeactivateTask, a retarget and a bulk deactivation are all expected ends of
		// an interception; reporting them as fail-safe purges — which this element did,
		// 179 times in one captured run — trains an operator to ignore the one channel
		// that says the triggering function has stopped answering.
		x1.OnPurge(func(_ types.InterceptTask, reason x1.PurgeReason) {
			if reason != x1.PurgeKeepaliveLapse || reporter == nil {
				return
			}
			// Off the caller's goroutine, for OnAuthFailure's reason and one more: a
			// purge reaches here from the X1 request goroutine (DeactivateAllTasks) as
			// well as from the fail-safe watchdog, and the transition lock this
			// callback now runs under serialises every other X1 operation behind it.
			// A blocking POST here would make one provisioning request wait on the
			// ADMF's own reachability and hold the rest of the interface behind it.
			reporter.NotifyAsync(x1.NEIssueTaskingPurged,
				"content interception tasking removed; the triggering function went quiet")
		}),
		// A task is refused unless every detection criterion is one this datapath can
		// resolve. Acknowledging one it cannot leaves the triggering function believing
		// an interception is running that can never produce anything — and nothing
		// outside this element could discover that.
		x1.CanApply(enabler.canApply),
		// Someone in the LI trust domain trying to trigger this CC-POI as a triggering
		// function it is not would be aiming a subject's traffic at a destination of
		// their choosing. It is refused, but this element logs nothing by design, so
		// without this the attempt leaves no trace at all.
		//
		// Reported off the X1 request goroutine. OnAuthFailure documents that it runs
		// synchronously on that goroutine and must not block, and a report is an mTLS
		// round trip to the ADMF bounded only by its own 10s timeout — so reporting a
		// refusal by holding the triggering interface open for the duration of a POST
		// to a peer that may itself be unreachable turns a refused request into a
		// stalled X1 channel, and makes this element's response time depend on whether
		// the ADMF is up. The AMF and SMF have honoured this contract since it was
		// written; this element did not, which is what NotifyAsync now settles in one
		// place for all three.
		x1.OnAuthFailure(func(code int) {
			if reporter != nil {
				reporter.NotifyAsync(x1.NEIssueX1AuthFailed,
					fmt.Sprintf("LI_T3 triggering refused: peer failed authentication (error %d)", code))
			}
		}),
	}
	// This element acts on a provisioned correlation value: it stamps task.CorrelationID
	// on every X3 PDU it delivers, and an LI_T3 trigger carries one mandatorily. So a
	// task carrying the field is accepted here, where an IRI-POI refuses it — the
	// correlation joining *its* records to a session is the session's, and one
	// provisioned value across the many sessions a task covers would collapse them at
	// the mediation function.
	opts = append(opts, x1.HonoursCorrelationID())

	// The two bulk operations the standard settles by advance agreement rather than by
	// what the element is. Unset leaves its defaults; li/x1 owns what unset means.
	opts = append(opts, x1.BulkOptions(cfg.DeactivateAllTasks, cfg.RemoveAllDestinations)...)

	srv := x1.NewServer(tasks, cfg.NEID, opts...)

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
// ccTFKeepaliveCadence is how often a CC triggering function tells this element it
// is still there. It is not configurable at the triggering function, so it is the
// fixed quantity this element's fail-safe window has to be expressed against.
const ccTFKeepaliveCadence = 60 * time.Second

// minTriggerKeepalive is the shortest fail-safe window that can distinguish a
// triggering function that has gone away from one that is merely between
// keepalives. Two cadences plus a margin: at one cadence any jitter, retransmit or
// scheduling delay reads as absence.
//
// Below it the fail-safe stops being a backstop and becomes a fault. It purges
// live tasking that a healthy triggering function is still answering for, and the
// element then reports taskingPurged — which names the triggering function as the
// thing that went silent, sending an operator to investigate an element that was
// behaving correctly, while interception the agency believes is running has in
// fact stopped.
const minTriggerKeepalive = 2*ccTFKeepaliveCadence + 30*time.Second

// tooShortTriggerKeepalive reports whether a configured window is short enough to
// purge tasking a healthy triggering function is still answering for.
//
// Separate from triggerKeepalive, and checked only where operator configuration is
// validated, because the two answer different questions. triggerKeepalive asks
// whether a window is usable at all, and the shipper is built directly with short
// windows in tests that have to observe a purge without waiting minutes for one.
// This asks whether a window an operator wrote is one the deployment can live
// with, which is a question only configuration can be wrong about.
func tooShortTriggerKeepalive(d time.Duration) bool {
	return d > 0 && d < minTriggerKeepalive
}

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
// Where several warrants cover one session the first is chosen. That is a declared
// scope boundary rather than an unfinished piece of work, and it is declared in
// `li/CONFORMANCE.md` and its X1 disposition — what is not implemented, what it
// would cost, and what would make it worth revisiting are stated there and are
// deliberately not restated here, so the two cannot drift apart.
//
// What belongs here is why the code looks like this: "first" must be the same on
// every packet, and store.Match orders by XID precisely so this choice is stable.
// Picking from a map's iteration order instead — as this did — scattered one
// session's packets across the covering warrants at random, leaving every agency
// with a partial stream and none with a usable one. The count is returned so the
// caller can tell the ADMF that a warrant is being served nothing, which is the
// part of this compromise that must not stay quiet.
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
			// The same filter tasksCovering applies, and it matters here for the reason
			// stated there: the caller takes the first task, so a task that requires no
			// content — and therefore has no X3 destination to deliver it to — would
			// take attribution of the copy away from the warrant that does, and swallow
			// the whole stream. Applying it on one path and not the other means the
			// answer depends on whether a datapath happened to be attached.
			if !producesCC(task) {
				continue
			}
			matched = append(matched, coveredTask{task: task, filter: unfiltered()})
		}
	}
	if len(matched) == 0 {
		return types.InterceptTask{}, copyFilter{}, 0, false
	}

	return matched[0].task, matched[0].filter, len(matched), true
}
