// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"strings"
	"testing"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
)

// TestTheTriggeringFunctionIsToldWhenX3DeliveryIsDown asserts the wiring, not the mechanism.
//
// li/x1 renders deliveryFault when it is given a reachability answer, and that is tested there.
// What this element has to get right is supplying it — and a CC-POI is where answering
// activeAndWorking wrongly costs the most, because a dropped content copy leaves no record
// anywhere else. The triggering function's interrogation is the only thing that can reveal it,
// and it was hard-coded to say everything was fine.
//
// It goes through startTriggerListener, which is what Init calls, so the assertion covers the
// option actually being passed rather than the option existing.
func TestTheTriggeringFunctionIsToldWhenX3DeliveryIsDown(t *testing.T) {
	const (
		did  = "33333333-3333-4333-8333-333333333333"
		addr = "192.0.2.1:42069"
	)

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

	cfg := &LiConfig{NEID: "upf-1", TFID: "smf-1", X1Listen: freePort(t)}

	down := false
	if _, err := startTriggerListener(cfg, upfMat.ServerTLS(), nil, nil,
		x2x3.NewIdentity("upf-1", upfInterceptionPoint), nil,
		func(a string) bool { return down && a == addr }); err != nil {
		t.Fatalf("startTriggerListener: %v", err)
	}

	// The destination the CC-TF provisions, which is the only source a triggered POI has.
	req := x1.NewRequester("https://"+cfg.X1Listen, "smf-1", "upf-1", tfMat.ClientTLS())
	if err := req.CreateDestination(x1.Destination{
		DID: did, DeliveryType: "X3Only", Address: "192.0.2.1", Port: 42069,
	}); err != nil {
		t.Fatalf("CreateDestination: %v", err)
	}

	ask := func(t *testing.T) string {
		t.Helper()

		return postX1(t, cfg.X1Listen, tfMat,
			bulkRequest("GetAllDestinationDetailsRequest", "smf-1", "upf-1"))
	}

	if body := ask(t); !strings.Contains(body, "activeAndWorking") {
		t.Errorf("a reachable X3 destination was not reported as working:\n%s", body)
	}

	// The X3 delivery connection to the mediation function fails. Nothing about the tasking
	// changes, so the interrogation is the only thing that can say so.
	down = true

	body := ask(t)
	if !strings.Contains(body, "deliveryFault") {
		t.Errorf("the CC-POI reports X3 delivery as working while its own shipper cannot "+
			"reach the mediation function; a dropped content copy leaves no other trace, so "+
			"this answer is the only thing that could have revealed it:\n%s", body)
	}
}
