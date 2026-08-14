// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Forsway Scandinavia AB

package pfcpiface

import (
	"testing"
	"time"
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
