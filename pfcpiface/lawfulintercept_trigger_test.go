// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/x1"
)

// liCA creates one throwaway LI certificate authority, writes its certificate to
// dir, and returns the path plus the material needed to issue leaves from it.
// Every certificate in a test must come from this one CA: a second CA would make
// the peers reject each other on chain validity, which looks nothing like the
// identity-binding refusals these tests are about.
func liCA(t *testing.T, dir string) (caPath string, caCert *x509.Certificate, caKey *rsa.PrivateKey) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test LI CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}

	caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	caPath = dir + "/ca.crt"
	writePEM(t, caPath, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	return caPath, caCert, caKey
}

// liLeaf issues a certificate from ca binding identifier for the given X1 role.
// The binding is an annex G subjectAltName URN, one of the two forms clause 8.2.4
// accepts.
func liLeaf(t *testing.T, dir string, caCert *x509.Certificate, caKey *rsa.PrivateKey, role, identifier string) (certPath, keyPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}

	binding, err := url.Parse("urn:etsi:li:103221-1:cert-binding:" + role + ":" + identifier)
	if err != nil {
		t.Fatalf("binding urn: %v", err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: identifier},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{identifier, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		URIs:         []*url.URL{binding},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}

	certPath = dir + "/" + identifier + ".crt"
	keyPath = dir + "/" + identifier + ".key"

	writePEM(t, certPath, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	writePEM(t, keyPath, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPath, keyPath
}

// writePEM writes PEM blocks to path with owner-only permissions, as LI
// credentials are.
func writePEM(t *testing.T, path string, blocks ...*pem.Block) {
	t.Helper()

	var out []byte
	for _, b := range blocks {
		out = append(out, pem.EncodeToMemory(b)...)
	}

	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// freePort returns a port nothing is listening on, so the test does not collide
// with a fixed number.
func freePort(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	addr := ln.Addr().String()
	_ = ln.Close()

	return addr
}

// TestTriggerListenerAcceptsCCTFTasking drives a real LI_T3 trigger over mutual
// TLS into the CC-POI's listener and checks the UPF ends up holding what it needs
// to attribute content: the warrant XID and the session's correlation identifier,
// findable by the F-SEID the datapath tags onto every duplicated packet.
func TestTriggerListenerAcceptsCCTFTasking(t *testing.T) {
	dir := t.TempDir()
	// Server credentials for the UPF, client credentials for the SMF's CC-TF. The
	// CC-TF presents the "ADMF" role: on this interface it is the tasking party.
	caPath, caCert, caKey := liCA(t, dir)
	upfCert, upfKey := liLeaf(t, dir, caCert, caKey, "NE", "upf-1")
	tfCert, tfKey := liLeaf(t, dir, caCert, caKey, "ADMF", "smf-1")

	upfMat, err := mtls.Load(upfCert, upfKey, caPath)
	if err != nil {
		t.Fatalf("load upf material: %v", err)
	}

	cfg := &LiConfig{
		NEID:     "upf-1",
		TFID:     "smf-1",
		X1Listen: freePort(t),
	}

	tasks, err := startTriggerListener(cfg, upfMat.ServerTLS(), nil)
	if err != nil {
		t.Fatalf("startTriggerListener: %v", err)
	}

	tfMat, err := mtls.Load(tfCert, tfKey, caPath)
	if err != nil {
		t.Fatalf("load tf material: %v", err)
	}

	const seid = 14426627323429955319

	req := x1.NewRequester("https://"+cfg.X1Listen, "smf-1", "upf-1", tfMat.ClientTLS())
	trigger := x1.Trigger{
		XID:           "11111111-1111-4111-8111-111111111111",
		ProductID:     "22222222-2222-4222-8222-222222222222",
		CorrelationID: 0x2632898145f4d191,
		SEID:          seid,
		SEIDAddress:   "127.0.0.1",
		DIDs:          []string{"33333333-3333-4333-8333-333333333333"},
	}

	if err := req.ActivateTask(trigger); err != nil {
		t.Fatalf("ActivateTask: %v", err)
	}

	task, ok := lookupTrigger(tasks, seid)
	if !ok {
		t.Fatal("no trigger found for the tasked session")
	}

	if task.DeliveryXID() != trigger.ProductID {
		t.Errorf("DeliveryXID() = %q, want the warrant XID %q", task.DeliveryXID(), trigger.ProductID)
	}

	if task.CorrelationID != trigger.CorrelationID {
		t.Errorf("CorrelationID = %d, want %d", task.CorrelationID, trigger.CorrelationID)
	}

	// A session nobody tasked must not resolve to a warrant, or content would be
	// delivered labelled with someone else's (review R34).
	if _, ok := lookupTrigger(tasks, seid+1); ok {
		t.Error("an untasked session resolved to a trigger")
	}

	if err := req.DeactivateTask(trigger.XID); err != nil {
		t.Fatalf("DeactivateTask: %v", err)
	}

	if _, ok := lookupTrigger(tasks, seid); ok {
		t.Error("trigger still installed after DeactivateTask")
	}
}

// TestTriggerListenerRejectsForeignTasker is R26's attack aimed at this interface:
// a certificate the LI CA legitimately issued, asserting an identity it is not
// bound to. Being inside the LI trust domain is not authority to task this UPF.
func TestTriggerListenerRejectsForeignTasker(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := liCA(t, dir)
	upfCert, upfKey := liLeaf(t, dir, caCert, caKey, "NE", "upf-1")
	// A valid LI-CA certificate, but bound to a different element's identity.
	otherCert, otherKey := liLeaf(t, dir, caCert, caKey, "ADMF", "smf-2")

	upfMat, err := mtls.Load(upfCert, upfKey, caPath)
	if err != nil {
		t.Fatalf("load upf material: %v", err)
	}

	cfg := &LiConfig{NEID: "upf-1", TFID: "smf-1", X1Listen: freePort(t)}

	tasks, err := startTriggerListener(cfg, upfMat.ServerTLS(), nil)
	if err != nil {
		t.Fatalf("startTriggerListener: %v", err)
	}

	otherMat, err := mtls.Load(otherCert, otherKey, caPath)
	if err != nil {
		t.Fatalf("load other material: %v", err)
	}

	const seid = 99

	// Assert the authorised triggering function's identifier while holding a
	// certificate bound to smf-2.
	req := x1.NewRequester("https://"+cfg.X1Listen, "smf-1", "upf-1", otherMat.ClientTLS())
	err = req.ActivateTask(x1.Trigger{
		XID:           "11111111-1111-4111-8111-111111111111",
		ProductID:     "22222222-2222-4222-8222-222222222222",
		CorrelationID: 1,
		SEID:          seid,
		DIDs:          []string{"33333333-3333-4333-8333-333333333333"},
	})
	if err == nil {
		t.Fatal("a certificate bound to another element was allowed to task this UPF")
	}

	var reqErr *x1.RequestError
	if e, ok := err.(*x1.RequestError); ok {
		reqErr = e
	}

	if reqErr == nil || reqErr.Code != 1030 {
		t.Errorf("err = %v, want X1 error 1030 (identifier does not match certificate)", err)
	}

	if _, ok := lookupTrigger(tasks, seid); ok {
		t.Error("a refused trigger was installed anyway")
	}
}

// TestTriggerListenerBindFailureIsReported checks the fail-closed behaviour: a
// CC-POI that cannot be tasked must not come up looking healthy, and the fault
// goes to the ADMF rather than a general log (design D11).
func TestTriggerListenerBindFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := liCA(t, dir)
	upfCert, upfKey := liLeaf(t, dir, caCert, caKey, "NE", "upf-1")

	upfMat, err := mtls.Load(upfCert, upfKey, caPath)
	if err != nil {
		t.Fatalf("load upf material: %v", err)
	}

	// Occupy the port so the listener cannot bind.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = busy.Close() }()

	rec := &recordingReporter{}
	cfg := &LiConfig{NEID: "upf-1", TFID: "smf-1", X1Listen: busy.Addr().String()}

	if _, err := startTriggerListener(cfg, upfMat.ServerTLS(), rec); err == nil {
		t.Fatal("startTriggerListener reported success on a port it could not bind")
	}

	if len(rec.issues) != 1 || rec.issues[0] != x1.NEIssueX1ListenFailed {
		t.Errorf("reported issues = %v, want one %s", rec.issues, x1.NEIssueX1ListenFailed)
	}
}

// recordingReporter captures the NE issues raised, so a test can assert what the
// ADMF would have been told.
type recordingReporter struct {
	issues []string
}

func (r *recordingReporter) ReportNEIssue(issueType, description string) error {
	r.issues = append(r.issues, issueType)

	return nil
}
