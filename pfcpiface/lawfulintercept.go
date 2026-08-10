// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
)

// The BESS liEncap (GenericEncap) prepends a fixed tag to every duplicated
// packet before it reaches the X3 egress socket: an 8-byte F-SEID (used as the
// X3 correlation id) followed by a 1-byte FAR action (the forward-and-duplicate
// action, which encodes the direction). Layout: [fseid(8)][action(1)][packet].
const (
	fseidTagLen = 8
	liTagLen    = fseidTagLen + 1 // + 1-byte FAR action
)

// liShipper is the UPF's Lawful Interception CC-POI. It reads the content-of-
// communication copies the BESS datapath tees to a userspace socket (for a FAR
// carrying the DUPL apply-action) and delivers each one to the MDF3 as an ETSI
// TS 103 221-2 X3 PDU over mutual TLS. Opt-in: created only when LI is
// configured, and it logs nothing that reveals which subscriber is intercepted.
// reconnect backoff bounds for the X3 egress socket.
const (
	minReconnectDelay = 100 * time.Millisecond
	maxReconnectDelay = 5 * time.Second
)

// Punting copies to userspace has a ceiling, and the socket that carries them
// holds only as many datagrams as net.unix.max_dgram_qlen allows — 10 by default,
// which a burst fills instantly. Everything the read loop does before returning to
// Read is time that queue spends filling, so the loop does nothing but read and
// hand off; parsing, task lookup and PDU framing happen on workers.
const (
	// liFrameQueueDepth absorbs a burst that arrives faster than it can be framed.
	liFrameQueueDepth = 4096
	// liFrameWorkers frame concurrently. Delivery itself is already asynchronous;
	// this covers the per-packet work in front of it.
	liFrameWorkers = 4
	// liMaxPunted bounds a single copy read from the socket.
	liMaxPunted = 1 << 16
)

type liShipper struct {
	sockAddr string
	sock     net.Conn
	reporter neIssueReporter // nil when NE-initiated reporting is not configured
	// tasks holds the LI_T3 triggers installed by the CC-TF, indexed by the
	// F-SEID the datapath tags onto duplicated packets. It is what supplies the
	// warrant XID and correlation identifier for each copy.
	tasks *store.Store
	// tlsConfig is the client side of the LI PKI, used to dial each MDF3.
	tlsConfig *tls.Config

	mu      sync.Mutex
	senders map[string]x2x3.Sender // per MDF3 address, created on first use

	// punted carries copies from the socket read to the framing workers, and free
	// recycles the buffers so the hot path does not allocate per packet.
	punted chan []byte
	free   chan []byte
}

// errNoDeliveryCredentials means X3 delivery was attempted with no LI client
// credentials loaded, which can only happen in a test that built a shipper
// directly. Delivering intercept product over an unauthenticated connection is
// never an acceptable fallback.
var errNoDeliveryCredentials = errors.New("li: no X3 delivery credentials")

// neIssueReporter surfaces LI-plane faults to the ADMF over X1. An interface (like
// the x2x3.Sender above) so tests can assert what a fault reports without an ADMF.
// It exposes the fire-and-forget form (*x1.Reporter.Notify): reporting is
// best-effort by design and a failed report has nowhere to go, so the outcome is
// not returned.
type neIssueReporter interface {
	Notify(issueType, description string)
}

// startLIShipper dials the datapath's X3 egress socket, prepares X3 delivery to
// the MDF3 (mutual TLS), and starts the shipping loop.
func startLIShipper(cfg *LiConfig, client pb.BESSControlClient) (*liShipper, error) {
	mat, err := mtls.Load(cfg.Cert, cfg.Key, cfg.CACert)
	if err != nil {
		return nil, err
	}

	var d net.Dialer
	sock, err := d.DialContext(context.Background(), "unixpacket", cfg.X3SockAddr)
	if err != nil {
		return nil, err
	}

	setPuntReadBuffer(sock, cfg.X3RcvBuf)

	var reporter *x1.Reporter
	if cfg.AdmfURL != "" {
		reporter = x1.NewReporter(cfg.AdmfURL, cfg.AdmfID, cfg.NEID, mat.ClientTLS())
	}

	// Bring up the LI_T3 triggering interface before the shipping loop: without it
	// no content can be attributed to a warrant, so there is nothing worth shipping.
	// A typed-nil reporter would defeat the nil checks inside, so pass the
	// interface only when one is configured.
	var issueReporter neIssueReporter
	if reporter != nil {
		issueReporter = reporter
	}

	tasks, err := startTriggerListener(cfg, mat.ServerTLS(), issueReporter)
	if err != nil {
		_ = sock.Close()

		return nil, err
	}
	// X3 destinations arrive per task over LI_T3 (CreateDestination + the task's
	// ListOfDIDs), so no delivery client can be built here — one is created per
	// MDF3 address on first use. Delivery is asynchronous either way: shipLoop must
	// keep draining the datapath socket and cannot block on an MDF3, or the unread
	// socket would make BESS drop every subsequent copy.
	s := &liShipper{
		sockAddr:  cfg.X3SockAddr,
		sock:      sock,
		tasks:     tasks,
		tlsConfig: mat.ClientTLS(),
		senders:   make(map[string]x2x3.Sender),
		punted:    make(chan []byte, liFrameQueueDepth),
		free:      make(chan []byte, liFrameQueueDepth),
	}
	// Only assign when configured: a typed-nil *x1.Reporter in the interface field
	// would pass the nil check in report() and then panic on use.
	if reporter != nil {
		s.reporter = reporter
	}
	for range liFrameWorkers {
		go s.frameLoop()
	}

	go s.shipLoop()
	// Loss between the datapath and this shipper is invisible from here — a copy
	// discarded on the socket write never arrives — so it is watched from the only
	// vantage point that can see it, the datapath's own accounting.
	startLIPuntMonitor(client, issueReporter)

	return s, nil
}

// setPuntReadBuffer asks the kernel for a deeper receive buffer on the egress
// socket, so a burst of duplicated packets is absorbed rather than discarded on
// the datapath's write.
//
// On its own this achieves little, and it is worth being explicit about why: an
// AF_UNIX SEQPACKET socket refuses a write once its receive queue holds
// net.unix.max_dgram_qlen *datagrams*, which defaults to 10 and is not affected by
// the buffer size at all. The byte budget only starts to bind after that queue
// limit is raised, which is a deployment matter — the sysctl is per network
// namespace, so the pod needs it set before this socket is created. Measured
// effect of raising it from 10 to 4096: egress loss under burst fell by about half.
func setPuntReadBuffer(sock net.Conn, size int) {
	if size <= 0 {
		return
	}

	if c, ok := sock.(*net.UnixConn); ok {
		// Best-effort: the kernel caps the request at net.core.rmem_max, and a
		// smaller-than-requested buffer is still better than the default. Nothing is
		// logged either way — a failure here degrades capacity, and capacity
		// problems are reported by the egress monitor rather than announced.
		//nolint:errcheck // best-effort tuning; degraded capacity is reported by the egress monitor
		_ = c.SetReadBuffer(size)
	}
}

// report surfaces an LI-plane fault to the ADMF over X1 (throttled, NE-level, no
// target id), never to general logs. No-op when reporting is not configured.
func (s *liShipper) report(issueType, description string) {
	if s.reporter != nil {
		s.reporter.Notify(issueType, description)
	}
}

// shipLoop reads each teed packet — an 8-byte F-SEID tag (prepended by the BESS
// GenericEncap) followed by the subscriber's inner IP packet — and hands it to
// ship, which resolves the F-SEID to the LI_T3 task covering that session and
// delivers the content labelled with that task's warrant XID and correlation
// identifier.
func (s *liShipper) shipLoop() {
	buf := make([]byte, liMaxPunted)

	for {
		n, err := s.sock.Read(buf)
		if err != nil {
			// The datapath X3 socket dropped (BESS restart / transient error). Do
			// not die — that would silently disable interception for the life of
			// the process. Report it to the ADMF, then reconnect (with backoff) so
			// interception resumes when the datapath returns.
			s.report(x1.NEIssueX3EgressDown, "X3 egress socket unavailable")
			s.reconnect()

			continue
		}

		if n <= liTagLen {
			continue // tag only, no user-plane payload
		}

		// Copy out of the read buffer and hand off. The read buffer is reused, so
		// the copy is necessary; doing anything more here — parsing, a task lookup,
		// framing a PDU — is time the socket queue spends filling behind us, and
		// what it overflows with is intercept product nobody can recover.
		out := append(s.buffer()[:0], buf[:n]...)

		select {
		case s.punted <- out:
		default:
			// Framing cannot keep up. This is lost content like any other, so it is
			// reported rather than left to be inferred from a counter nobody reads.
			s.recycle(out)
			s.report(x1.NEIssueX3FramingLost, "content copies dropped before framing")
		}
	}
}

// frameLoop turns punted copies into X3 PDUs and hands them to delivery.
func (s *liShipper) frameLoop() {
	for b := range s.punted {
		s.checkTag(b)
		s.ship(b)
		s.recycle(b)
	}
}

// buffer takes a recycled buffer, or allocates when the pool is empty.
func (s *liShipper) buffer() []byte {
	select {
	case b := <-s.free:
		return b
	default:
		return make([]byte, 0, liMaxPunted)
	}
}

// recycle returns a buffer for reuse, dropping it if the pool is full.
func (s *liShipper) recycle(b []byte) {
	select {
	case s.free <- b:
	default:
	}
}

// ship delivers one duplicated packet, if the session it came from is covered by
// an LI_T3 task.
//
// Duplication and tasking reach this UPF over different interfaces — the DUPL
// apply-action over PFCP, the warrant over X1 — so they can disagree.
// Content whose session has no task is **dropped and reported**, never delivered:
// the only label available for it would be a zero XID, and a mediation function
// attributes product by XID alone and discards what it cannot attribute without
// complaint. Shipping it would look like working interception while delivering
// nothing usable.
func (s *liShipper) ship(tagged []byte) {
	fseid := binary.LittleEndian.Uint64(tagged[:fseidTagLen])

	task, covering, ok := lookupTrigger(s.tasks, fseid)
	if !ok {
		s.report(x1.NEIssueContentUntasked, "duplicated content for a session with no interception task")

		return
	}

	if covering > 1 {
		// Every copy of this session goes to one warrant, so the others are
		// authorised and receiving nothing. Only the ADMF can reconcile that, and it
		// cannot do so from an absence of product.
		s.report(x1.NEIssueContentTaskOverlap,
			"several interception tasks cover one session; content is delivered under one of them")
	}

	dest, ok := x3Destination(task)
	if !ok {
		s.report(x1.NEIssueInvalidConfig, "interception task carries no X3 delivery destination")

		return
	}

	sender, err := s.senderFor(dest)
	if err != nil {
		s.report(x1.NEIssueMDFUnreachable, "X3 delivery destination could not be prepared")

		return
	}

	// Enqueue for asynchronous delivery and keep reading: Send never blocks, so
	// a slow/unreachable MDF3 cannot stall the socket read (which would make
	// BESS drop subsequent copies). Delivery failures are reported from the
	// worker via the onError hook set in senderFor.
	//nolint:errcheck // async enqueue never blocks; delivery failures report via onError
	_ = sender.Send(shipperPDU(tagged, task))
}

// x3Destination returns the task's X3 delivery endpoint. A destination
// provisioned as X2Only is not one: delivering content to a signalling endpoint
// would be a disclosure to the wrong place.
func x3Destination(task types.InterceptTask) (string, bool) {
	for _, d := range task.Deliveries {
		if d.Type == types.DeliveryX3 && d.Address != "" {
			return d.Address, true
		}
	}

	return "", false
}

// senderFor returns the delivery client for an MDF3 address, creating it on first
// use. Destinations arrive per task over X1, so they are not known at startup, and
// several agencies' destinations may be in use at once — hence one sender per
// address rather than one for the process.
func (s *liShipper) senderFor(addr string) (x2x3.Sender, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sender, ok := s.senders[addr]; ok {
		return sender, nil
	}

	if s.tlsConfig == nil {
		return nil, errNoDeliveryCredentials
	}

	sender := x2x3.NewAsyncSender(
		x2x3.NewClient(addr, s.tlsConfig), 0,
		func(error) { s.report(x1.NEIssueMDFUnreachable, "MDF3 X3 delivery failed") },
		// A full queue is lost content, and it is not covered by the delivery-failure
		// report above: that fires when the MDF is unreachable, whereas the queue
		// overflows when the MDF is reachable but slower than the offered rate. Left
		// unreported, the product is silently incomplete.
		func() { s.report(x1.NEIssueX3DeliveryLost, "content copies dropped from the delivery queue") },
	)
	s.senders[addr] = sender

	return sender, nil
}

// checkTag reports an unusable LI tag to the ADMF. The tag's fields reach liEncap
// as BESS per-packet metadata, whose offsets are assigned from the pipeline graph;
// a wiring in which they do not reach the encap is accepted at load time with only
// a printed note, and every copy then carries a zero correlation id or an unknown
// action. Interception would be running but its product would not be correlatable
// by the MDF, so surface it over X1 — never to general logs.
func (s *liShipper) checkTag(tagged []byte) {
	switch tagged[fseidTagLen] {
	case farForwardDAndDuplicate, farForwardUAndDuplicate:
	default:
		s.report(x1.NEIssueX3TagInvalid, "content tag carries an unknown forwarding action")

		return
	}

	if binary.LittleEndian.Uint64(tagged[:fseidTagLen]) == 0 {
		s.report(x1.NEIssueX3TagInvalid, "content tag carries no session correlation")
	}
}

// reconnect closes the dead X3 egress socket and redials it with capped
// exponential backoff, blocking until the datapath socket is available again.
func (s *liShipper) reconnect() {
	_ = s.sock.Close()

	delay := minReconnectDelay
	for {
		time.Sleep(delay)

		var d net.Dialer
		sock, err := d.DialContext(context.Background(), "unixpacket", s.sockAddr)
		if err == nil {
			s.sock = sock
			return
		}

		if delay < maxReconnectDelay {
			delay *= 2
		}
	}
}

// shipperPDU frames one teed datapath packet as an X3 content-of-communication
// PDU, labelled with the identity the CC-TF supplied for that session's task. The
// datapath prepends the F-SEID (which selects the task) and the FAR action; the
// action distinguishes the downlink copy — teed after GTP-U encap, so a GTP-U
// packet toward the target — from the uplink copy — decapsulated inner IP from
// the target — which sets both the X3 payload format and the direction. Getting
// this wrong would ship the downlink copy mislabeled as decapsulated inner IP.
func shipperPDU(tagged []byte, task types.InterceptTask) *x2x3.PDU {
	action := tagged[fseidTagLen]
	inner := tagged[liTagLen:]
	pdu := &x2x3.PDU{Type: x2x3.PDUTypeX3}
	// Both identity fields come from the LI_T3 task and neither is derived here:
	// the XID is the warrant's (the task's ProductID, per TS 103 221-1 clause
	// 6.2.1.2, which is what makes the content attributable at all), and the
	// correlation identifier is the value the SMF also put on that session's xIRI,
	// which is what lets the MDF join content to signalling. Deriving either
	// locally is how the two streams came to disagree.
	pdu.XID = task.DeliveryXID().Bytes()
	binary.BigEndian.PutUint64(pdu.CorrelationID[:], task.CorrelationID)

	l3, format := networkLayerOf(inner)
	pdu.Payload = append([]byte(nil), l3...)
	pdu.Direction = directionOf(action)
	pdu.PayloadFormat = format

	// The downlink copy is teed after GTP-U encapsulation, so its network layer is
	// the outer packet carrying the tunnel toward the target.
	if action == farForwardDAndDuplicate && format != x2x3.PayloadFormatEthernet {
		pdu.PayloadFormat = x2x3.PayloadFormatGTPU
	}

	return pdu
}

// networkLayerOf returns the packet to carry on X3 and its payload format. The
// BESS pipeline tees a full Ethernet frame — its GTP-U decap leaves the link layer
// intact — whereas X3 carries the network-layer packet, so an L2 header is stripped
// when one is present. A payload that is already a bare IP packet is shipped
// unchanged, and anything unrecognised is shipped whole and labelled Ethernet
// rather than mislabelled as IP.
func networkLayerOf(pkt []byte) ([]byte, x2x3.PayloadFormat) {
	if l3, ok := stripEthernet(pkt); ok {
		return l3, payloadFormatOf(l3)
	}

	if len(pkt) > 0 && (pkt[0]>>4 == 4 || pkt[0]>>4 == 6) {
		return pkt, payloadFormatOf(pkt)
	}

	return pkt, x2x3.PayloadFormatEthernet
}

// directionOf maps the datapath forward-and-duplicate action to the X3 direction.
func directionOf(action byte) x2x3.PayloadDirection {
	switch action {
	case farForwardDAndDuplicate:
		return x2x3.DirectionToTarget
	case farForwardUAndDuplicate:
		return x2x3.DirectionFromTarget
	default:
		return x2x3.DirectionUnknown
	}
}

// stripEthernet removes the Ethernet (and any 802.1Q) header from a teed frame,
// returning the network-layer packet. It reports false when the frame does not
// carry IPv4/IPv6, in which case the caller must not claim an IP payload format.
func stripEthernet(frame []byte) ([]byte, bool) {
	const (
		ethHeaderLen  = 14
		vlanTagLen    = 4
		etherTypeIPv4 = 0x0800
		etherTypeIPv6 = 0x86DD
		etherTypeVLAN = 0x8100
		etherTypeQinQ = 0x88A8
	)

	offset := ethHeaderLen
	for len(frame) > offset {
		etherType := binary.BigEndian.Uint16(frame[offset-2 : offset])
		switch etherType {
		case etherTypeIPv4, etherTypeIPv6:
			return frame[offset:], true
		case etherTypeVLAN, etherTypeQinQ:
			offset += vlanTagLen
		default:
			return frame, false
		}
	}

	return frame, false
}

// payloadFormatOf classifies an inner user-plane packet by IP version.
func payloadFormatOf(pkt []byte) x2x3.PayloadFormat {
	if len(pkt) > 0 && pkt[0]>>4 == 6 {
		return x2x3.PayloadFormatIPv6
	}

	return x2x3.PayloadFormatIPv4
}
