// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"net"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/x2x3"
)

// fseidTagLen is the width of the F-SEID tag the BESS liEncap (GenericEncap)
// prepends to every duplicated packet before it reaches the X3 egress socket.
const fseidTagLen = 8

// liShipper is the UPF's Lawful Interception CC-POI. It reads the content-of-
// communication copies the BESS datapath tees to a userspace socket (for a FAR
// carrying the DUPL apply-action) and delivers each one to the MDF3 as an ETSI
// TS 103 221-2 X3 PDU over mutual TLS. Opt-in: created only when LI is
// configured, and it logs nothing that reveals which subscriber is intercepted.
type liShipper struct {
	sock   net.Conn
	client *x2x3.Client
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
		sock:   sock,
		client: x2x3.NewClient(cfg.MDF3, mat.ClientTLS()),
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
			return
		}

		if n <= fseidTagLen {
			continue // tag only, no user-plane payload
		}

		_ = s.client.Send(shipperPDU(buf[:n]))
	}
}

// shipperPDU frames one teed datapath packet (an fseidTagLen F-SEID tag followed
// by the inner IP packet) as an X3 content-of-communication PDU.
func shipperPDU(tagged []byte) *x2x3.PDU {
	inner := tagged[fseidTagLen:]
	pdu := &x2x3.PDU{
		Type:          x2x3.PDUTypeX3,
		PayloadFormat: payloadFormatOf(inner),
		Payload:       append([]byte(nil), inner...),
	}
	copy(pdu.CorrelationID[:], tagged[:fseidTagLen])

	return pdu
}

// payloadFormatOf classifies an inner user-plane packet by IP version.
func payloadFormatOf(pkt []byte) x2x3.PayloadFormat {
	if len(pkt) > 0 && pkt[0]>>4 == 6 {
		return x2x3.PayloadFormatIPv6
	}

	return x2x3.PayloadFormatIPv4
}
