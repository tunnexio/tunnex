package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

func aiInternalTestClient(t *testing.T, base string) *control.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gw"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	client, err := control.NewClient(base, "tunnex-control", "gw", certPEM,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// The internal AI endpoint listener has no setting and no backend requirement, but it needs the
// authenticated HTTPS control channel; without it the capability is absent.
func TestAIInternalRuntimeNeedsTheAuthenticatedControlChannel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	noop := func() {}
	serving := func([]netip.Addr, int) {}
	if configureAIInternalRuntime(nil, noop, serving, logger) != nil {
		t.Fatal("a runtime without a control client")
	}
	if configureAIInternalRuntime(aiInternalTestClient(t, "http://control:8443"), noop, serving, logger) != nil {
		t.Fatal("a runtime over plain HTTP control")
	}
	runtime := configureAIInternalRuntime(aiInternalTestClient(t, "https://control:8443"), noop, serving, logger)
	if runtime == nil {
		t.Fatal("no runtime over the authenticated control channel")
	}
	defer runtime.Close()
	var ps control.PolicyStatus
	aiInternalReport(&ps, runtime)
	if ps.AIInternalEndpointVersion != 1 || ps.AIInternalEndpointReady || ps.AIInternalEndpointAddresses == nil || len(ps.AIInternalEndpointAddresses) != 0 {
		t.Fatalf("an unconfigured runtime reports %+v", ps)
	}
	var absent control.PolicyStatus
	aiInternalReport(&absent, nil)
	if absent.AIInternalEndpointVersion != 0 || absent.AIInternalEndpointReady || absent.AIInternalEndpointAddresses == nil {
		t.Fatalf("an absent runtime reports %+v", absent)
	}
	// main calls these on a nil runtime when the channel is unavailable.
	var none = configureAIInternalRuntime(nil, noop, serving, logger)
	none.Kick()
	none.Close()
	if !agentReady(true, true, false, false, false) {
		t.Fatal("an absent internal AI listener withdrew ordinary VPN readiness")
	}
}
