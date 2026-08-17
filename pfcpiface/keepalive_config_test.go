// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Forsway Scandinavia AB

package pfcpiface

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/x2x3"
)

// TestX2X3KeepaliveConfigDefaultsWhenUnusable.
//
// **This asserted the opposite until 2026-08-17**, and the policy it pinned was the
// defect. An unusable timer was refused by validateConf, whose error reaches
// logger.InitLog.Fatalln in cmd/pfcpiface/main.go: the UPF exited over a keepalive
// timer, taking the user plane with it, and printed the LI field name into the general
// operator log on the way out. Two things an LI value may not do.
//
// The specification supplies both defaults normatively (60s and 180s), so there is
// something correct to fall back to — which is what the AMF and SMF have always done
// with the same two settings. An unusable value is now reported to the ADMF and the
// defaults are used.
//
// The pair worth the test is TIME_P2 below TIME_P1: both parse, both look reasonable in
// a file, and together they disconnect every X3 connection before the keepalive that
// would keep it is sent — so falling back to the defaults has to discard *both*, not
// keep the half that parsed.
func TestX2X3KeepaliveConfigDefaultsWhenUnusable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		p1, p2     string
		wantReport bool
		wantP1     time.Duration
		wantP2     time.Duration
	}{
		{name: "nothing configured takes the specification's defaults"},
		{name: "a usable pair", p1: "10s", p2: "30s", wantP1: 10 * time.Second, wantP2: 30 * time.Second},
		{name: "only TIME_P1, with TIME_P2 defaulting above it", p1: "30s", wantP1: 30 * time.Second},
		{name: "an unparseable TIME_P1", p1: "sixty", wantReport: true},
		{name: "an unparseable TIME_P2", p2: "three minutes", wantReport: true},
		{name: "TIME_P2 equal to TIME_P1", p1: "60s", p2: "60s", wantReport: true},
		{name: "TIME_P2 below TIME_P1", p1: "60s", p2: "30s", wantReport: true},
		// Only TIME_P2, set below the default TIME_P1 of 60s: the file reads as though
		// one timer was tightened, and the mechanism becomes a disconnect loop.
		{name: "only TIME_P2, below the default TIME_P1", p2: "30s", wantReport: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			li := &LiConfig{
				X3SockAddr: "/tmp/x3.sock", Cert: "c", Key: "k", CACert: "ca",
				X1Listen: ":8443", TFID: "smf-1", NEID: "upf-1",
				X2X3KeepaliveTimeP1: tc.p1, X2X3KeepaliveTimeP2: tc.p2,
			}

			// Whatever the timers say, the configuration must not stop the process:
			// validateConf no longer looks at the li block at all.
			if err := validateConf(Conf{Mode: "sim", RespTimeout: "2s", ReadTimeout: 15, MaxReqRetries: 5, Li: li}); err != nil {
				t.Errorf("validateConf() error = %v; an LI timer must not stop the user plane", err)
			}

			reporter := &recordingReporter{}
			got := keepaliveConfig(*li, reporter)

			if got := reporter.reported(); (len(got) > 0) != tc.wantReport {
				t.Errorf("reported = %v, want %v (%v)", len(got) > 0, tc.wantReport, got)
			}
			// Zero means "the specification's own value", which x2x3 resolves.
			if got.TimeP1 != tc.wantP1 || got.TimeP2 != tc.wantP2 {
				t.Errorf("timers = (%s, %s), want (%s, %s)", got.TimeP1, got.TimeP2, tc.wantP1, tc.wantP2)
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
			got := keepaliveConfig(tc.cfg, nil)
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
		keepalive: keepaliveConfig(LiConfig{X2X3KeepaliveTimeP1: "25ms", X2X3KeepaliveTimeP2: "1h"}, nil),
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

// TestAnUnusableLIBlockDoesNotStopTheUserPlane is B1 on this element.
//
// validateConf used to refuse every unusable `li` field, and its error reaches
// logger.InitLog.Fatalln in cmd/pfcpiface/main.go — so a mistyped optional LI value
// exited the process, taking the **user plane** with it, after printing
// `invalid argument 'li.trigger_keepalive'=30 (…)` into the general operator log. An LI
// typo causing a network outage, and an LI-attributable line in a log far more widely
// readable than the config file it describes. bess.go's own handling of a shipper
// failure is deliberately vague for exactly that reason, so this contradicted it.
//
// Loading must now succeed for every one of these, and the shipper must refuse them.
func TestAnUnusableLIBlockDoesNotStopTheUserPlane(t *testing.T) {
	complete := func() *LiConfig {
		return &LiConfig{
			X3SockAddr: "/pod-share/x3", Cert: "c", Key: "k", CACert: "ca",
			X1Listen: ":8443", TFID: "smf-1", NEID: "upf-1",
		}
	}

	for _, tc := range []struct {
		name  string
		spoil func(*LiConfig)
	}{
		{"no ne_id", func(c *LiConfig) { c.NEID = "" }},
		{"no tf_id", func(c *LiConfig) { c.TFID = "" }},
		{"no x1_listen", func(c *LiConfig) { c.X1Listen = "" }},
		{"no x3_sockaddr", func(c *LiConfig) { c.X3SockAddr = "" }},
		{"no credentials", func(c *LiConfig) { c.Cert = "" }},
		{"an unparseable trigger_keepalive", func(c *LiConfig) { c.TriggerKeepalive = "5min" }},
		{"a trigger_keepalive below the floor", func(c *LiConfig) { c.TriggerKeepalive = "30s" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			li := complete()
			tc.spoil(li)

			conf := Conf{Mode: "sim", RespTimeout: "2s", ReadTimeout: 15, MaxReqRetries: 5, Li: li}
			if err := validateConf(conf); err != nil {
				t.Errorf("validateConf refused the configuration (%v). That reaches Fatalln "+
					"in main and stops the user plane over a Lawful Interception value.", err)
			}
			if err := validateLiConfig(li); err == nil {
				t.Error("the shipper accepted a configuration it cannot carry out; interception " +
					"would look enabled and produce nothing")
			}
		})
	}
}

// TestAnUnusableLIBlockNamesNoFieldInTheGeneralLog is the disclosure half. The refusal
// travels as an error to startLIShipper's caller, which logs it non-attributably; what
// must not happen is the field name reaching a general sink, as the Fatalln path did.
func TestAnUnusableLIBlockNamesNoFieldInTheGeneralLog(t *testing.T) {
	var logged bytes.Buffer

	restore := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(restore) })

	li := &LiConfig{
		X3SockAddr: "/pod-share/x3", Cert: "c", Key: "k", CACert: "ca",
		X1Listen: ":8443", TFID: "smf-1", // ne_id missing
	}

	if err := validateConf(Conf{Mode: "sim", RespTimeout: "2s", ReadTimeout: 15, MaxReqRetries: 5, Li: li}); err != nil {
		t.Fatalf("validateConf refused the configuration: %v", err)
	}
	if err := validateLiConfig(li); err == nil {
		t.Fatal("the shipper accepted an li block with no ne_id")
	}

	if strings.Contains(logged.String(), "li.") || strings.Contains(logged.String(), "ne_id") {
		t.Errorf("an LI field name reached the general log:\n%s", logged.String())
	}
}
