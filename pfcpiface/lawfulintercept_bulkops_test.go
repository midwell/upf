// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
)

// TestBulkDeactivationFollowsConfiguration drives the LI_T3 triggering interface the way its
// peer does — over mutual TLS, with a certificate the CC-TF's identity is bound into — and
// checks that the agreement stated in this UPF's JSON configuration is the one the element
// enforces.
//
// It goes through startTriggerListener rather than building an x1 server of its own,
// because a configured policy that never reaches the constructor is the failure this is for,
// and a second copy of the wiring in a test would not notice it.
//
// The message is hand-built: x1.Requester implements no bulk request, since no triggering
// function this project ships sends one. That is also what makes disabling both operations
// on a UPF free — see li/README.md.
func TestBulkDeactivationFollowsConfiguration(t *testing.T) {
	no := false

	cases := []struct {
		name        string
		configured  *bool
		wantRefusal bool
	}{
		{name: "agreed disabled", configured: &no, wantRefusal: true},
		{name: "no agreement in advance", configured: nil, wantRefusal: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			caPath, caCert, caKey := liCA(t, dir)
			upfCert, upfKey := liLeaf(t, dir, caCert, caKey, "NE", "upf-1")
			tfCert, tfKey := liLeaf(t, dir, caCert, caKey, "ADMF", "smf-1")

			upfMat, err := mtls.Load(upfCert, upfKey, caPath)
			if err != nil {
				t.Fatalf("load upf material: %v", err)
			}
			tfMat, err := mtls.Load(tfCert, tfKey, caPath)
			if err != nil {
				t.Fatalf("load tf material: %v", err)
			}

			cfg := &LiConfig{
				NEID:               "upf-1",
				TFID:               "smf-1",
				X1Listen:           freePort(t),
				DeactivateAllTasks: c.configured,
			}

			tasks, err := startTriggerListener(cfg, upfMat.ServerTLS(), nil, nil, x2x3.NewIdentity("upf-1", upfInterceptionPoint))
			if err != nil {
				t.Fatalf("startTriggerListener: %v", err)
			}

			// Tasking for the bulk request to act on, installed the way the CC-TF installs
			// it. Without it "the store is empty afterwards" would hold either way.
			req := x1.NewRequester("https://"+cfg.X1Listen, "smf-1", "upf-1", tfMat.ClientTLS())
			const did = "33333333-3333-4333-8333-333333333333"
			if err := req.CreateDestination(x1.Destination{
				DID: did, DeliveryType: "X3Only", Address: "192.0.2.1", Port: 42069,
			}); err != nil {
				t.Fatalf("CreateDestination: %v", err)
			}
			if err := req.ActivateTask(x1.Trigger{
				XID:           "11111111-1111-4111-8111-111111111111",
				ProductID:     "22222222-2222-4222-8222-222222222222",
				CorrelationID: 0x2632898145f4d191,
				SEID:          14426627323429955319,
				SEIDAddress:   "127.0.0.1",
				DIDs:          []string{did},
			}); err != nil {
				t.Fatalf("ActivateTask: %v", err)
			}

			body := postX1(t, cfg.X1Listen, tfMat, bulkRequest("DeactivateAllTasksRequest", "smf-1", "upf-1"))

			if !c.wantRefusal {
				if strings.Contains(body, "errorCode") {
					t.Fatalf("want the standard's default — bulk deactivation performed — got %s", body)
				}
				if tasks.Len() != 0 {
					t.Error("bulk deactivation was acknowledged and did not take effect")
				}

				return
			}

			if !strings.Contains(body, "<ns1:errorCode>5010</ns1:errorCode>") {
				t.Errorf("want the specification's 5010 for a disabled DeactivateAllTasks, got %s", body)
			}
			if want := "DeactivateAllTasks message is not enabled"; !strings.Contains(body, want) {
				t.Errorf("want the specification's own %q, got %s", want, body)
			}
			if tasks.Len() != 1 {
				t.Error("tasking was removed despite the refusal")
			}
		})
	}
}

// TestBulkRemovalFollowsConfiguration is the same assertion for the other switch, and it
// exists because without it the second of the two configuration fields is never observed
// to reach the element at all.
//
// The two are carried by one call taking both, and their conditions are inverted with
// respect to each other. So an element wired with the same field twice — the mistake that
// call is shaped to invite — behaves correctly for bulk deactivation and ignores the
// operator entirely for bulk removal, and every other test here passes.
func TestBulkRemovalFollowsConfiguration(t *testing.T) {
	yes := true

	cases := []struct {
		name        string
		configured  *bool
		wantRefusal bool
	}{
		{name: "agreed permitted", configured: &yes, wantRefusal: false},
		{name: "no agreement in advance", configured: nil, wantRefusal: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			caPath, caCert, caKey := liCA(t, dir)
			upfCert, upfKey := liLeaf(t, dir, caCert, caKey, "NE", "upf-1")
			tfCert, tfKey := liLeaf(t, dir, caCert, caKey, "ADMF", "smf-1")

			upfMat, err := mtls.Load(upfCert, upfKey, caPath)
			if err != nil {
				t.Fatalf("load upf material: %v", err)
			}
			tfMat, err := mtls.Load(tfCert, tfKey, caPath)
			if err != nil {
				t.Fatalf("load tf material: %v", err)
			}

			cfg := &LiConfig{
				NEID:                  "upf-1",
				TFID:                  "smf-1",
				X1Listen:              freePort(t),
				RemoveAllDestinations: c.configured,
			}

			if _, err := startTriggerListener(cfg, upfMat.ServerTLS(), nil, nil, x2x3.NewIdentity("upf-1", upfInterceptionPoint)); err != nil {
				t.Fatalf("startTriggerListener: %v", err)
			}

			// A destination for the request to remove, provisioned the way the CC-TF
			// provisions one. The specification refuses the removal while a task still
			// references a destination, so no task is installed here.
			req := x1.NewRequester("https://"+cfg.X1Listen, "smf-1", "upf-1", tfMat.ClientTLS())
			if err := req.CreateDestination(x1.Destination{
				DID: "33333333-3333-4333-8333-333333333333", DeliveryType: "X3Only",
				Address: "192.0.2.1", Port: 42069,
			}); err != nil {
				t.Fatalf("CreateDestination: %v", err)
			}

			body := postX1(t, cfg.X1Listen, tfMat, bulkRequest("RemoveAllDestinationsRequest", "smf-1", "upf-1"))

			if !c.wantRefusal {
				if strings.Contains(body, "errorCode") {
					t.Fatalf("the configured permission did not reach the element: %s", body)
				}

				return
			}

			if !strings.Contains(body, "<ns1:errorCode>8020</ns1:errorCode>") {
				t.Errorf("want the standard's default — bulk removal refused with 8020 — got %s", body)
			}
		})
	}
}

// TestBulkSwitchesInTheJSONConfig covers what the configuration layer does with the two
// keys, which is where an operator's `false` is at risk of quietly becoming nothing.
//
// The last two cases are the ones worth having. A key mistyped as a *value* must be
// refused rather than defaulted — the rule this config already applies to the fail-safe
// window, and for the same reason: defaulting here answers the permissive way. And the
// other fields of an `li` block are still mandatory, since these two are optional
// additions to a block that is not allowed to fail open.
func TestBulkSwitchesInTheJSONConfig(t *testing.T) {
	// The mandatory fields of an li block, with a placeholder for whatever the case adds.
	li := func(extra string) string {
		return `{
			"mode": "dpdk",
			"li": {
				"x3_sockaddr": "/pod-share/x3",
				"cert": "/li/upf.crt",
				"key": "/li/upf.key",
				"ca_cert": "/li/ca.crt",
				"x1_listen": ":8443",
				"tf_id": "smf-1",
				"ne_id": "upf-1"` + extra + `
			}
		}`
	}

	t.Run("both switches carry through", func(t *testing.T) {
		path := t.TempDir() + "/conf.jsonc"
		mustWriteStringToDisk(li(`,
				"deactivate_all_tasks": false,
				"remove_all_destinations": true`), path)

		conf, err := LoadConfigFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf.Li.DeactivateAllTasks == nil || *conf.Li.DeactivateAllTasks {
			t.Errorf("deactivate_all_tasks = %v, want a stated false — a dropped restriction "+
				"leaves the element performing the operation the operator withheld",
				conf.Li.DeactivateAllTasks)
		}
		if conf.Li.RemoveAllDestinations == nil || !*conf.Li.RemoveAllDestinations {
			t.Errorf("remove_all_destinations = %v, want a stated true", conf.Li.RemoveAllDestinations)
		}
	})

	t.Run("saying nothing is not saying false", func(t *testing.T) {
		path := t.TempDir() + "/conf.jsonc"
		mustWriteStringToDisk(li(""), path)

		conf, err := LoadConfigFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf.Li.DeactivateAllTasks != nil || conf.Li.RemoveAllDestinations != nil {
			t.Error("an li block that states no agreement must leave both unset, so the " +
				"standard's own defaults apply")
		}
	})

	t.Run("a value that is not a boolean is refused", func(t *testing.T) {
		path := t.TempDir() + "/conf.jsonc"
		mustWriteStringToDisk(li(`,
				"deactivate_all_tasks": "false"`), path)

		if _, err := LoadConfigFile(path); err == nil {
			t.Error("a quoted \"false\" was accepted; an unparseable value must be refused " +
				"rather than read as unset, which is the permissive answer")
		}
	})

	t.Run("the mandatory fields are still mandatory", func(t *testing.T) {
		path := t.TempDir() + "/conf.jsonc"
		mustWriteStringToDisk(`{
			"mode": "dpdk",
			"li": {
				"x3_sockaddr": "/pod-share/x3",
				"cert": "/li/upf.crt",
				"key": "/li/upf.key",
				"ca_cert": "/li/ca.crt",
				"x1_listen": ":8443",
				"tf_id": "smf-1",
				"deactivate_all_tasks": false
			}
		}`, path)

		if _, err := LoadConfigFile(path); err == nil {
			t.Error("an li block with no ne_id was accepted; the optional switches must not " +
				"have made the rest of the block optional")
		}
	})
}

// postX1 sends one X1 request to addr as the CC-TF and returns the response body.
func postX1(t *testing.T, addr string, mat *mtls.Material, body []byte) string {
	t.Helper()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: mat.ClientTLS()}}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+addr+"/X1/NE", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post X1: %v", err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	return string(out)
}

// bulkRequest builds one of the two bulk X1 messages: the one that stops every
// interception on this element, or the one that removes every destination it holds.
func bulkRequest(msgType, tfID, neID string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:` + msgType + `">
    <ns1:admfIdentifier>` + tfID + `</ns1:admfIdentifier>
    <ns1:neIdentifier>` + neID + `</ns1:neIdentifier>
    <ns1:messageTimestamp>2026-01-01T00:00:00.000000Z</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa</ns1:x1TransactionId>
  </ns1:x1RequestMessage>
</ns1:X1Request>`)
}
