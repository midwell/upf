// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
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

	//nolint:noctx // test listener; no context needed
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

	// The destination has to exist before a trigger may name it: this POI refuses a
	// content trigger whose destinations it does not know, so that a triggering
	// function whose provisioning has been lost finds out.
	const did = "33333333-3333-4333-8333-333333333333"
	if err := req.CreateDestination(x1.Destination{
		DID: did, DeliveryType: "X3Only", Address: "192.0.2.1", Port: 42069,
	}); err != nil {
		t.Fatalf("CreateDestination: %v", err)
	}

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

	// The same trigger naming a destination this POI has never heard of must be
	// refused rather than acknowledged. Accepting it would duplicate a subject's
	// traffic and discard every copy while the triggering function believed
	// interception was running — which is what a POI restart used to cause.
	unknown := trigger
	unknown.XID = "99999999-9999-4999-8999-999999999999"
	unknown.SEID = seid + 7
	unknown.DIDs = []string{"55555555-5555-4555-8555-555555555555"}
	if err := req.ActivateTask(unknown); err == nil {
		t.Error("a content trigger naming an unknown destination was accepted")
	}
	if _, _, ok := lookupTrigger(tasks, seid+7); ok {
		t.Error("a refused trigger was installed anyway")
	}

	task, _, ok := lookupTrigger(tasks, seid)
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
	// delivered labelled with someone else's.
	if _, _, ok := lookupTrigger(tasks, seid+1); ok {
		t.Error("an untasked session resolved to a trigger")
	}

	if err := req.DeactivateTask(trigger.XID); err != nil {
		t.Fatalf("DeactivateTask: %v", err)
	}

	if _, _, ok := lookupTrigger(tasks, seid); ok {
		t.Error("trigger still installed after DeactivateTask")
	}
}

// TestTriggerListenerRejectsForeignTasker aims the same attack at this interface:
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

	if _, _, ok := lookupTrigger(tasks, seid); ok {
		t.Error("a refused trigger was installed anyway")
	}
}

// TestTriggerListenerBindFailureIsReported checks the fail-closed behaviour: a
// CC-POI that cannot be tasked must not come up looking healthy, and the fault
// goes to the ADMF rather than a general log.
func TestTriggerListenerBindFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := liCA(t, dir)
	upfCert, upfKey := liLeaf(t, dir, caCert, caKey, "NE", "upf-1")

	upfMat, err := mtls.Load(upfCert, upfKey, caPath)
	if err != nil {
		t.Fatalf("load upf material: %v", err)
	}

	// Occupy the port so the listener cannot bind.
	//nolint:noctx // test listener; no context needed
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

	if len(rec.reported()) != 1 || rec.reported()[0] != x1.NEIssueX1ListenFailed {
		t.Errorf("reported issues = %v, want one %s", rec.reported(), x1.NEIssueX1ListenFailed)
	}
}

// TestShipDropsContentWithoutATask is the guard at the point of delivery.
// Duplication (PFCP DUPL) and tasking (LI_T3) arrive over different interfaces
// and can disagree, so content whose session has no task must be dropped and
// reported — never shipped with an XID no mediation function can attribute.
func TestShipDropsContentWithoutATask(t *testing.T) {
	const seid = 42

	// [fseid(8)][action(1)][inner IP packet]
	tagged := make([]byte, 0, 9+20)
	tagged = binary.LittleEndian.AppendUint64(tagged, seid)
	tagged = append(tagged, farForwardUAndDuplicate)
	tagged = append(tagged, 0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2)

	newShipper := func(rec *recordingReporter) *liShipper {
		return &liShipper{
			tasks:    store.New(),
			reporter: rec,
			senders:  make(map[string]x2x3.Sender),
		}
	}

	t.Run("untasked session", func(t *testing.T) {
		rec := &recordingReporter{}
		s := newShipper(rec)

		s.ship(tagged)

		if len(s.senders) != 0 {
			t.Error("a delivery client was created for content with no interception task")
		}

		if len(rec.reported()) != 1 || rec.reported()[0] != x1.NEIssueContentUntasked {
			t.Errorf("reported = %v, want one %s", rec.reported(), x1.NEIssueContentUntasked)
		}
	})

	t.Run("tasked but no X3 destination", func(t *testing.T) {
		rec := &recordingReporter{}
		s := newShipper(rec)
		// A task whose only destination is for signalling: content must not be sent
		// to an X2 endpoint.
		s.tasks.Activate(types.InterceptTask{
			XID:           "11111111-1111-4111-8111-111111111111",
			ProductID:     "22222222-2222-4222-8222-222222222222",
			CorrelationID: 7,
			Targets:       []types.TargetIdentifier{types.TargetIdentifier{Type: types.TargetFSEID, Value: "42"}},
			Products:      []types.ProductType{types.ProductCC},
			Deliveries:    []types.DeliveryEndpoint{{Type: types.DeliveryX2, Address: "10.0.0.1:42069"}},
		})

		s.ship(tagged)

		if len(s.senders) != 0 {
			t.Error("content was prepared for delivery with no X3 destination")
		}

		if len(rec.reported()) != 1 || rec.reported()[0] != x1.NEIssueInvalidConfig {
			t.Errorf("reported = %v, want one %s", rec.reported(), x1.NEIssueInvalidConfig)
		}
	})

	t.Run("no delivery credentials", func(t *testing.T) {
		rec := &recordingReporter{}
		s := newShipper(rec)
		s.tasks.Activate(types.InterceptTask{
			XID:           "11111111-1111-4111-8111-111111111111",
			ProductID:     "22222222-2222-4222-8222-222222222222",
			CorrelationID: 7,
			Targets:       []types.TargetIdentifier{types.TargetIdentifier{Type: types.TargetFSEID, Value: "42"}},
			Products:      []types.ProductType{types.ProductCC},
			Deliveries:    []types.DeliveryEndpoint{{Type: types.DeliveryX3, Address: "10.0.0.1:42069"}},
		})

		s.ship(tagged)

		// Intercept product is never delivered over an unauthenticated connection,
		// so with no LI credentials loaded there is no sender and the fault is
		// reported instead.
		if len(s.senders) != 0 {
			t.Error("a delivery client was created without LI credentials")
		}

		if len(rec.reported()) != 1 || rec.reported()[0] != x1.NEIssueMDFUnreachable {
			t.Errorf("reported = %v, want one %s", rec.reported(), x1.NEIssueMDFUnreachable)
		}
	})
}

// recordingReporter captures the NE issues raised, so a test can assert what the
// ADMF would have been told. Guarded, because reports also arrive from background
// goroutines — the keepalive fail-safe raises one from its own watchdog.
type recordingReporter struct {
	mu     sync.Mutex
	issues []string
}

func (r *recordingReporter) Notify(issueType, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.issues = append(r.issues, issueType)
}

// reported returns a copy of what has been raised so far.
func (r *recordingReporter) reported() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.issues...)
}

// TestTriggerKeepaliveFailSafePurgesTasking: tasking must not
// outlive the party responsible for it. A triggering function that restarts
// forgets the triggers it installed, and content intercepted under a trigger
// nobody can withdraw keeps flowing past the point where the warrant itself is
// revoked. The fail-safe makes that lapse instead.
func TestTriggerKeepaliveFailSafePurgesTasking(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := liCA(t, dir)
	upfCert, upfKey := liLeaf(t, dir, caCert, caKey, "NE", "upf-1")
	tfCert, tfKey := liLeaf(t, dir, caCert, caKey, "ADMF", "smf-1")

	upfMat, err := mtls.Load(upfCert, upfKey, caPath)
	if err != nil {
		t.Fatalf("load upf material: %v", err)
	}

	rec := &recordingReporter{}
	cfg := &LiConfig{
		NEID: "upf-1", TFID: "smf-1", X1Listen: freePort(t),
		// Short enough to observe, long enough that the tasking below lands first.
		TriggerKeepalive: "1s",
	}

	tasks, err := startTriggerListener(cfg, upfMat.ServerTLS(), rec)
	if err != nil {
		t.Fatalf("startTriggerListener: %v", err)
	}

	tfMat, err := mtls.Load(tfCert, tfKey, caPath)
	if err != nil {
		t.Fatalf("load tf material: %v", err)
	}

	const seid = 4242
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
		CorrelationID: 7,
		SEID:          seid,
		DIDs:          []string{did},
	}); err != nil {
		t.Fatalf("ActivateTask: %v", err)
	}

	if _, _, ok := lookupTrigger(tasks, seid); !ok {
		t.Fatal("trigger was not installed")
	}

	// A keepalive keeps it alive: the fail-safe must not remove tasking merely
	// because no new session happened to be established.
	for range 3 {
		time.Sleep(600 * time.Millisecond)

		if err := req.Keepalive(); err != nil {
			t.Fatalf("Keepalive: %v", err)
		}
	}

	if _, _, ok := lookupTrigger(tasks, seid); !ok {
		t.Fatal("tasking was purged while the triggering function was still talking")
	}

	// Now it goes quiet, as a restarted one does.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, ok := lookupTrigger(tasks, seid); !ok {
			break
		}

		time.Sleep(300 * time.Millisecond)
	}

	if _, _, ok := lookupTrigger(tasks, seid); ok {
		t.Error("tasking outlived the triggering function; content would keep being intercepted with nobody able to withdraw it")
	}

	// And the ADMF is told, because interception stopping must not be silent.
	var purged bool
	for _, i := range rec.reported() {
		if i == x1.NEIssueTaskingPurged {
			purged = true
		}
	}

	if !purged {
		t.Errorf("reported %v, want %s", rec.reported(), x1.NEIssueTaskingPurged)
	}
}

// TestOverlappingWarrantsPickTheSameOneEveryTime: when two warrants cover one
// session this POI delivers each packet under exactly one of them, so which one
// has to be the same on every packet. Selecting from a map's iteration order —
// which is what reading store.Match unsorted amounted to — scattered a session's
// packets across the covering warrants at random, leaving each agency with an
// arbitrary fraction of the content and none of them with a usable stream. The
// agency that ends up with nothing is the ADMF's problem to resolve, so the
// overlap is reported rather than left to be inferred from an absence of product.
func TestOverlappingWarrantsPickTheSameOneEveryTime(t *testing.T) {
	const seid = 42

	target := types.TargetIdentifier{Type: types.TargetFSEID, Value: "42"}
	tasks := store.New()
	for _, xid := range []types.XID{
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	} {
		tasks.Activate(types.InterceptTask{
			XID: xid, ProductID: xid, CorrelationID: 7, Targets: []types.TargetIdentifier{target},
			Products:   []types.ProductType{types.ProductCC},
			Deliveries: []types.DeliveryEndpoint{{Type: types.DeliveryX3, Address: "10.0.0.1:42069"}},
		})
	}

	const wantXID = types.XID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	for i := range 50 {
		task, covering, ok := lookupTrigger(tasks, seid)
		if !ok {
			t.Fatalf("pass %d: tasked session did not resolve to a trigger", i)
		}
		if task.XID != wantXID {
			t.Fatalf("pass %d: selected warrant %q, want %q on every packet", i, task.XID, wantXID)
		}
		if covering != 3 {
			t.Fatalf("pass %d: covering = %d, want 3", i, covering)
		}
	}

	// And the shipper tells the ADMF, since two of these three warrants are
	// authorised and receiving nothing.
	tagged := make([]byte, 0, 9+20)
	tagged = binary.LittleEndian.AppendUint64(tagged, seid)
	tagged = append(tagged, farForwardUAndDuplicate)
	tagged = append(tagged, 0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2)

	rec := &recordingReporter{}
	s := &liShipper{tasks: tasks, reporter: rec, senders: make(map[string]x2x3.Sender)}
	s.ship(tagged)

	if !slices.Contains(rec.reported(), x1.NEIssueContentTaskOverlap) {
		t.Errorf("reported = %v, want it to include %s", rec.reported(), x1.NEIssueContentTaskOverlap)
	}
}

// TestTriggerKeepaliveMustBeValid: an unparseable fail-safe window used to be
// checked only after the X1 listener was already serving, so the error returned
// here left an element accepting and applying tasking into a store its caller had
// abandoned — un-tasked to its operator, holding warrants in fact.
func TestTriggerKeepaliveMustBeValid(t *testing.T) {
	for _, v := range []string{"nonsense", "-5m", "0s"} {
		if _, err := triggerKeepalive(v); err == nil {
			t.Errorf("triggerKeepalive(%q) accepted an unusable window", v)
		}
	}
	if d, err := triggerKeepalive(""); err != nil || d != 0 {
		t.Errorf(`triggerKeepalive("") = %v, %v; want 0, nil (fail-safe off)`, d, err)
	}
	if d, err := triggerKeepalive("5m"); err != nil || d != 5*time.Minute {
		t.Errorf(`triggerKeepalive("5m") = %v, %v; want 5m, nil`, d, err)
	}

	// Nothing may be left listening when the window is rejected.
	addr := freePort(t)
	cfg := &LiConfig{NEID: "upf-1", TFID: "smf-1", X1Listen: addr, TriggerKeepalive: "nonsense"}
	if _, err := startTriggerListener(cfg, &tls.Config{}, nil); err == nil {
		t.Fatal("startTriggerListener accepted an invalid trigger_keepalive")
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("X1 port still bound after a rejected trigger_keepalive: %v", err)
	}
	_ = ln.Close()
}
