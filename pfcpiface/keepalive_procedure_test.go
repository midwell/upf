// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/util/li/x1"
)

// TestTheKeepaliveProcedureIsTheOperatorsOwn: the procedure of TS 103 221-1 clause 6.6.2
// runs by default on the clause's timers, keepalive_timeout is TIME_P2, and only
// keepalive_disabled turns it off. trigger_keepalive, the key's former name, still sets
// TIME_P2.
func TestTheKeepaliveProcedureIsTheOperatorsOwn(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  LiConfig
		want *x1.KeepaliveProcedure
	}{
		{"unset runs the clause defaults", LiConfig{}, &x1.KeepaliveProcedure{}},
		{"disabled runs nothing", LiConfig{KeepaliveDisabled: true, KeepaliveTimeout: "5m"}, nil},
		{
			"keepalive_timeout is TIME_P2",
			LiConfig{KeepaliveTimeout: "5m"},
			&x1.KeepaliveProcedure{TimeP2: 5 * time.Minute},
		},
		{"every timer and the retain switch", LiConfig{
			KeepaliveTimeout: "30m", KeepaliveTimeP1: "2m", KeepaliveTimeP3: "4h",
			KeepaliveRetainTasking: true,
		}, &x1.KeepaliveProcedure{
			TimeP2: 30 * time.Minute, TimeP1: 2 * time.Minute, TimeP3: 4 * time.Hour,
			RetainTasking: true,
		}},
		{
			"trigger_keepalive is still TIME_P2",
			LiConfig{TriggerKeepalive: "5m"},
			&x1.KeepaliveProcedure{TimeP2: 5 * time.Minute},
		},
		{
			"both names agreeing",
			LiConfig{KeepaliveTimeout: "5m", TriggerKeepalive: "5m"},
			&x1.KeepaliveProcedure{TimeP2: 5 * time.Minute},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := keepaliveProcedure(&tc.cfg)
			if err != nil {
				t.Fatalf("keepaliveProcedure: %v", err)
			}
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Errorf("keepaliveProcedure = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestTwoNamesForOneTimerMustAgree: keepalive_timeout and its deprecated name
// trigger_keepalive both set to different values is refused, naming both, because the
// element cannot know which the operator meant.
func TestTwoNamesForOneTimerMustAgree(t *testing.T) {
	_, err := keepaliveProcedure(&LiConfig{KeepaliveTimeout: "5m", TriggerKeepalive: "10m"})
	if err == nil {
		t.Fatal("two different values for TIME_P2 were accepted")
	}
	for _, name := range []string{"keepalive_timeout", "trigger_keepalive"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name %s: %v", name, err)
		}
	}
}

// recordingADMF is an ADMF that records every report body it is sent and answers each with
// an empty 200 — not a bound X1 answer, so a report it receives counts as unanswered, which
// is the clause 6.6.2 case that deactivates tasking once TIME_P1 has passed. onReport, when
// set, is called with each body as it arrives.
type recordingADMF struct {
	url      string
	mu       sync.Mutex
	bodies   []string
	onReport func(body string)
}

func newRecordingADMF(t *testing.T, onReport func(body string)) *recordingADMF {
	t.Helper()

	a := &recordingADMF{onReport: onReport}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test handler
		a.mu.Lock()
		a.bodies = append(a.bodies, string(body))
		a.mu.Unlock()
		if a.onReport != nil {
			a.onReport(string(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	a.url = srv.URL

	return a
}

// reporter is an X1 reporter sending to this ADMF, without TLS.
func (a *recordingADMF) reporter() *x1.Reporter {
	return x1.NewReporter(a.url, "admf", testNEID, nil)
}

// received reports whether any body sent so far contains want.
func (a *recordingADMF) received(want string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, b := range a.bodies {
		if strings.Contains(b, want) {
			return true
		}
	}

	return false
}
