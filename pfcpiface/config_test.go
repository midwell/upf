// SPDX-License-Identifier: Apache-2.0
// Copyright 2022-present Open Networking Foundation

package pfcpiface

import (
	"os"
	"testing"

	"go.uber.org/zap"
)

func mustWriteStringToDisk(s string, path string) {
	err := os.WriteFile(path, []byte(s), 0o600)
	if err != nil {
		panic(err)
	}
}

func TestLoadConfigFile(t *testing.T) {
	t.Run("sample config is valid", func(t *testing.T) {
		s := `{
			"mode": "dpdk",
			"log_level": "info",
			"workers": 1,
			"max_sessions": 50000,
			"table_sizes": {
				"pdrLookup": 50000,
				"appQERLookup": 200000,
				"sessionQERLookup": 100000,
				"farLookup": 150000
			},
			"access": {
				"ifname": "access"
			},
			"core": {
				"ifname": "core"
			},
			"measure_upf": true,
			"measure_flow": true,
			"enable_notify_bess": true,
			"notify_sockaddr": "/pod-share/notifycp",
			"cpiface": {
				"dnn": "internet",
				"hostname": "upf",
				"http_port": "8080"
			},
			"n6_bps": 1000000000,
			"n6_burst_bytes": 12500000,
			"n3_bps": 1000000000,
			"n3_burst_bytes": 12500000,
			"qci_qos_config": [{
				"qci": 0,
				"cbs": 50000,
				"ebs": 50000,
				"pbs": 50000,
				"burst_duration_ms": 10,
				"priority": 7
			}]
		}`
		confPath := t.TempDir() + "/conf.jsonc"
		mustWriteStringToDisk(s, confPath)

		_, err := LoadConfigFile(confPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty config has log level info", func(t *testing.T) {
		s := `{
			"mode": "dpdk"
		}`
		confPath := t.TempDir() + "/conf.jsonc"
		mustWriteStringToDisk(s, confPath)

		conf, err := LoadConfigFile(confPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf.LogLevel != zap.InfoLevel {
			t.Fatalf("expected log level %v, got %v", zap.InfoLevel, conf.LogLevel)
		}
	})

	t.Run("all sample configs must be valid", func(t *testing.T) {
		paths := []string{
			"../conf/upf.jsonc",
			"../ptf/config/upf.jsonc",
		}

		for _, path := range paths {
			_, err := LoadConfigFile(path)
			if err != nil {
				t.Errorf("config %v is not valid: %v", path, err)
			}
		}
	})
}

// TestRemoveCommentsKeepsStringContents pins the defect that a URL-valued setting
// used to destroy the configuration: the comment stripper matched the "//" inside
// "https://…" and, because the rendered config is a single line, deleted the rest
// of the file. The parse then failed as "unexpected end of JSON input", pointing
// nowhere near the URL that caused it.
func TestRemoveCommentsKeepsStringContents(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "url in a string is not a comment",
			in:   `{"admf_url":"https://admf.example:9443/X1/ADMF","ne_id":"upf-1"}`,
			want: `{"admf_url":"https://admf.example:9443/X1/ADMF","ne_id":"upf-1"}`,
		},
		{
			name: "line comment outside a string is removed",
			in:   "{\"a\":1} // trailing\n{\"b\":2}",
			want: "{\"a\":1} \n{\"b\":2}",
		},
		{
			name: "block comment outside a string is removed",
			in:   `{"a":/* note */1}`,
			want: `{"a":1}`,
		},
		{
			name: "comment markers inside a string survive",
			in:   `{"a":"/* not a comment */","b":"// nor this"}`,
			want: `{"a":"/* not a comment */","b":"// nor this"}`,
		},
		{
			name: "escaped quote does not end the string",
			in:   `{"a":"say \"https://x\" ok"}`,
			want: `{"a":"say \"https://x\" ok"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := removeComments(tc.in); got != tc.want {
				t.Errorf("removeComments()\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestLoadConfigFileWithURL is the end-to-end form: a config carrying a URL must
// parse. This is what the deployed UPF failed on.
func TestLoadConfigFileWithURL(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/upf.jsonc"
	body := `{"mode":"af_packet","log_level":"info","max_req_retries":5,"resp_timeout":"2s","read_timeout":15,` +
		`"li":{"x3_sockaddr":"/pod-share/li_x3","cert":"/c","key":"/k","ca_cert":"/ca",` +
		`"ne_id":"upf-1","admf_url":"https://10.0.0.1:9443/X1/ADMF","admf_id":"admf-id",` +
		`"x1_listen":"0.0.0.0:8443","tf_id":"smf-1"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	conf, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if conf.Li == nil || conf.Li.AdmfURL != "https://10.0.0.1:9443/X1/ADMF" {
		t.Errorf("admf_url not parsed: %+v", conf.Li)
	}
}
