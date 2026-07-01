// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"net"
	"time"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/x2x3"
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

type liShipper struct {
	sockAddr string
	sock     net.Conn
	client   *x2x3.Client
}

// startLIShipper dials the datapath's X3 egress socket, prepares X3 delivery to
// the MDF3 (mutual TLS), and starts the shipping loop.
func startLIShipper(cfg *LiConfig) (*liShipper, error) {
	mat, err := mtls.Load(cfg.Cert, cfg.Key, cfg.CACert)
	if err != nil {
		return nil, err
	}

	var d net.Dialer
	sock, err := d.DialContext(context.Background(), "unixpacket", cfg.X3SockAddr)
	if err != nil {
		return nil, err
	}

	s := &liShipper{
		sockAddr: cfg.X3SockAddr,
		sock:     sock,
		client:   x2x3.NewClient(cfg.MDF3, mat.ClientTLS()),
	}
	go s.shipLoop()

	return s, nil
}

// shipLoop reads each teed packet — an 8-byte F-SEID tag (prepended by the BESS
// GenericEncap) followed by the subscriber's inner IP packet — and ships it to
// the MDF3 as an X3 PDU. The F-SEID is carried as the X3 correlation ID so the
// MDF can correlate the content to the SMF's session xIRI. The warrant XID is
// left zero: the SMF triggers duplication over PFCP, which carries no LI XID, so
// correlation is by session (F-SEID); passing the XID to the UPF is a follow-up.
func (s *liShipper) shipLoop() {
	buf := make([]byte, 1<<16)

	for {
		n, err := s.sock.Read(buf)
		if err != nil {
			// The datapath X3 socket dropped (BESS restart / transient error). Do
			// not die — that would silently disable interception for the life of
			// the process. Reconnect (with backoff) so interception resumes when
			// the datapath returns.
			s.reconnect()
			continue
		}

		if n <= liTagLen {
			continue // tag only, no user-plane payload
		}

		_ = s.client.Send(shipperPDU(buf[:n]))
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
// PDU. The datapath prepends the F-SEID (correlation) and the FAR action; the
// action distinguishes the downlink copy — teed after GTP-U encap, so a GTP-U
// packet toward the target — from the uplink copy — decapsulated inner IP from
// the target — which sets both the X3 payload format and the direction. Getting
// this wrong would ship the downlink copy mislabeled as decapsulated inner IP.
func shipperPDU(tagged []byte) *x2x3.PDU {
	action := tagged[fseidTagLen]
	inner := tagged[liTagLen:]
	pdu := &x2x3.PDU{
		Type:    x2x3.PDUTypeX3,
		Payload: append([]byte(nil), inner...),
	}
	copy(pdu.CorrelationID[:], tagged[:fseidTagLen])

	switch action {
	case farForwardDAndDuplicate: // downlink: GTP-U packet toward the target
		pdu.PayloadFormat = x2x3.PayloadFormatGTPU
		pdu.Direction = x2x3.DirectionToTarget
	case farForwardUAndDuplicate: // uplink: decapsulated inner IP from the target
		pdu.PayloadFormat = payloadFormatOf(inner)
		pdu.Direction = x2x3.DirectionFromTarget
	default:
		pdu.PayloadFormat = payloadFormatOf(inner)
		pdu.Direction = x2x3.DirectionUnknown
	}

	return pdu
}

// payloadFormatOf classifies an inner user-plane packet by IP version.
func payloadFormatOf(pkt []byte) x2x3.PayloadFormat {
	if len(pkt) > 0 && pkt[0]>>4 == 6 {
		return x2x3.PayloadFormatIPv6
	}

	return x2x3.PayloadFormatIPv4
}
