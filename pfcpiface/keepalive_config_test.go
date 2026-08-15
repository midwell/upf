// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Forsway Scandinavia AB

package pfcpiface

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/x2x3"
)

// TestX2X3KeepaliveConfigIsRefusedWhenUnusable. This network function validates its
// whole configuration before anything starts, so an unusable keepalive setting is
// refused here rather than defaulted — the loudest outcome available in a process that
// has no ADMF to report to yet.
//
// The pair worth the test is TIME_P2 below TIME_P1: both parse, both look reasonable in
// a file, and together they disconnect every X3 connection before the keepalive that
// would keep it is sent.
func TestX2X3KeepaliveConfigIsRefusedWhenUnusable(t *testing.T) {
	base := func() *LiConfig {
		return &LiConfig{
			X3SockAddr: "/tmp/x3.sock", Cert: "c", Key: "k", CACert: "ca",
			X1Listen: ":8443", TFID: "smf-1", NEID: "upf-1",
		}
	}

	for _, tc := range []struct {
		name    string
		p1, p2  string
		wantErr bool
	}{
		{name: "nothing configured takes the specification's defaults"},
		{name: "a usable pair", p1: "10s", p2: "30s"},
		{name: "only TIME_P1, with TIME_P2 defaulting above it", p1: "30s"},
		{name: "an unparseable TIME_P1", p1: "sixty", wantErr: true},
		{name: "an unparseable TIME_P2", p2: "three minutes", wantErr: true},
		{name: "TIME_P2 equal to TIME_P1", p1: "60s", p2: "60s", wantErr: true},
		{name: "TIME_P2 below TIME_P1", p1: "60s", p2: "30s", wantErr: true},
		// Only TIME_P2, set below the default TIME_P1 of 60s: the file reads as though
		// one timer was tightened, and the mechanism becomes a disconnect loop.
		{name: "only TIME_P2, below the default TIME_P1", p2: "30s", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			li := base()
			li.X2X3KeepaliveTimeP1, li.X2X3KeepaliveTimeP2 = tc.p1, tc.p2

			err := validateConf(Conf{Mode: "sim", RespTimeout: "2s", ReadTimeout: 15, MaxReqRetries: 5, Li: li})
			if (err != nil) != tc.wantErr {
				t.Errorf("validateConf() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestX2X3KeepaliveConfigCarriesTheOperatorsIntent: what config.go accepts must be what
// the shipper runs, including the tri-state switch.
func TestX2X3KeepaliveConfigCarriesTheOperatorsIntent(t *testing.T) {
	enabled, disabled := true, false

	for _, tc := range []struct {
		name         string
		cfg          LiConfig
		wantDisabled bool
		wantP1       time.Duration
	}{
		{name: "unset runs the mechanism"},
		{name: "explicitly enabled", cfg: LiConfig{X2X3KeepaliveEnabled: &enabled}},
		{name: "explicitly disabled", cfg: LiConfig{X2X3KeepaliveEnabled: &disabled}, wantDisabled: true},
		{name: "a configured timer", cfg: LiConfig{X2X3KeepaliveTimeP1: "5s"}, wantP1: 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := keepaliveConfig(tc.cfg)
			if got.Disabled != tc.wantDisabled {
				t.Errorf("Disabled = %v, want %v", got.Disabled, tc.wantDisabled)
			}
			if got.TimeP1 != tc.wantP1 {
				t.Errorf("TimeP1 = %s, want %s", got.TimeP1, tc.wantP1)
			}
		})
	}
}

// TestX2X3KeepaliveReachesTheShippersClients closes the gap between "the settings were
// parsed" and "the settings are what the connection runs".
//
// This POI is the one that does not use x2x3.Pool — it builds its clients in senderFor —
// so nothing else covers the path from configuration to connection. Without this, senderFor
// could be changed to pass a zero KeepaliveConfig and every other test would still pass
// while the UPF silently stopped keepaliving X3.
//
// Asserted through the wire rather than through the struct: what matters is that keepalives
// arrive at the mediation function at the configured period, not that a field was copied.
func TestX2X3KeepaliveReachesTheShippersClients(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := liCA(t, dir)
	mdfCert, mdfKey := liLeaf(t, dir, caCert, caKey, "MDF", "mdf3-1")
	upfCert, upfKey := liLeaf(t, dir, caCert, caKey, "NE", "upf-1")

	mdfMat, err := mtls.Load(mdfCert, mdfKey, caPath)
	if err != nil {
		t.Fatalf("load mdf material: %v", err)
	}
	upfMat, err := mtls.Load(upfCert, upfKey, caPath)
	if err != nil {
		t.Fatalf("load upf material: %v", err)
	}

	// A mediation function that does nothing but count what it is sent.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", mdfMat.ServerTLS())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var (
		mu         sync.Mutex
		keepalives int
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					var head [12]byte
					if _, err := io.ReadFull(c, head[:]); err != nil {
						return
					}
					headerLen := binary.BigEndian.Uint32(head[4:8])
					payloadLen := binary.BigEndian.Uint32(head[8:12])
					rest := make([]byte, int(headerLen)+int(payloadLen)-len(head))
					if _, err := io.ReadFull(c, rest); err != nil {
						return
					}
					if binary.BigEndian.Uint16(head[2:4]) == uint16(x2x3.PDUTypeKeepalive) {
						mu.Lock()
						keepalives++
						mu.Unlock()
					}
				}
			}(conn)
		}
	}()

	// The shipper as senderFor needs it: credentials, the operator's keepalive settings,
	// and somewhere to keep the clients it builds. TIME_P2 is long because this test is
	// about the send, and this mediation function acknowledges nothing.
	s := &liShipper{
		tlsConfig: upfMat.ClientTLS(),
		keepalive: keepaliveConfig(LiConfig{X2X3KeepaliveTimeP1: "25ms", X2X3KeepaliveTimeP2: "1h"}),
		senders:   make(map[string]x2x3.Sender),
	}

	sender, err := s.senderFor(ln.Addr().String())
	if err != nil {
		t.Fatalf("senderFor: %v", err)
	}
	defer sender.Close()

	// A keepalive never dials, so an xCC is what opens the connection it runs on.
	if err := sender.Send(&x2x3.PDU{
		Type:          x2x3.PDUTypeX3,
		PayloadFormat: x2x3.PayloadFormatIPv4,
		Payload:       []byte{0x45, 0x00},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := keepalives
		mu.Unlock()

		if n >= 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	n := keepalives
	mu.Unlock()
	t.Errorf("the mediation function received %d keepalives in 5s at TIME_P1=25ms; "+
		"the shipper's clients are not running the configured mechanism", n)
}
