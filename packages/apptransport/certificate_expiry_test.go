package apptransport

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureLeaf(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey, serial int64, expiry time.Time, client bool) tls.Certificate {
	t.Helper()
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, DNSNames: []string{"fixture.test"}}
	der, e := x509.CreateCertificate(rand.Reader, cert, ca, &leafKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalECPrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	if e != nil {
		t.Fatal(e)
	}
	return pair
}

func TestActualMTLSCredentialExpiryClosesRenewingActiveChannel(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	expiry := time.Now().Add(3500 * time.Millisecond).Truncate(time.Second)
	clientCert := fixtureLeaf(t, ca, key, 2, expiry, true)
	serverCert := fixtureLeaf(t, ca, key, 3, time.Now().Add(time.Hour), false)
	var calls atomic.Int64
	binding := Binding{Purpose: "origin_check"}
	broker := NewBroker(func(context.Context, Binding, string) (time.Time, error) {
		calls.Add(1)
		return time.Now().Add(4 * time.Second), nil
	})
	defer broker.Close()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = broker.Accept(w, r, binding, "actual-serial") }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	u, _ := url.Parse(server.URL)
	peer, e := tls.Dial("tcp", u.Host, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "fixture.test", Certificates: []tls.Certificate{clientCert}, NextProtos: []string{"http/1.1"}})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: "/agent/app-access/channel"}, Host: u.Host, Header: make(http.Header)}
	if e = request.Write(peer); e != nil {
		t.Fatal(e)
	}
	response, e := http.ReadResponse(bufio.NewReader(peer), request)
	if e != nil || response.StatusCode != 200 {
		t.Fatal("mTLS channel admission", e)
	}
	active, e := broker.Dial(t.Context(), binding)
	if e != nil {
		t.Fatal(e)
	}
	defer active.Close()
	if _, e = active.Write([]byte("positive")); e != nil {
		t.Fatal(e)
	}
	bytes := make([]byte, 8)
	if _, e = peer.Read(bytes); e != nil || string(bytes) != "positive" {
		t.Fatal("no initial traffic", e)
	}
	_ = peer.SetReadDeadline(expiry.Add(250 * time.Millisecond))
	_, e = peer.Read(bytes)
	var timeout net.Error
	if e == nil || (errors.As(e, &timeout) && timeout.Timeout()) {
		t.Fatal("expired identity kept active stream", e)
	}
	if time.Now().After(expiry.Add(250 * time.Millisecond)) {
		t.Fatal("expiry closure exceeded watchdog bound")
	}
	if calls.Load() < 2 {
		t.Fatal("positive renewal not exercised")
	}
	waitConnections(t, broker, 0)
}

func TestVerifiedIssuerExpiryAndUnverifiedTLSRefusal(t *testing.T) {
	expiry := time.Now().Add(time.Second)
	r := &http.Request{TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{NotAfter: time.Now().Add(time.Hour)}, {NotAfter: expiry}}}}}
	if !authenticatedCertificateExpiry(r).Equal(expiry) {
		t.Fatal("issuer lifetime omitted")
	}
	if !capCredentialLease(time.Now().Add(time.Hour), expiry).Equal(expiry) {
		t.Fatal("lease extended past identity")
	}
	if authenticatedCertificateExpiry(&http.Request{TLS: &tls.ConnectionState{}}).After(time.Now()) {
		t.Fatal("unverified TLS given future authority")
	}
	for _, chains := range [][][]*x509.Certificate{{{}}, {{nil}}, {{{}}}} {
		if authenticatedCertificateExpiry(&http.Request{TLS: &tls.ConnectionState{VerifiedChains: chains}}).After(time.Now()) {
			t.Fatal("empty malformed verified chain given future authority")
		}
	}
	if !authenticatedCertificateExpiry(&http.Request{}).IsZero() {
		t.Fatal("explicit nonshipping injected-authority seam changed")
	}
}

func TestOversizedAuthorityLeaseNotHiddenByCredentialExpiry(t *testing.T) {
	broker := NewBroker(func(context.Context, Binding, string) (time.Time, error) { return time.Now().Add(time.Hour), nil })
	defer broker.Close()
	r := httptest.NewRequest("CONNECT", "/agent/app-access/channel", nil)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{NotAfter: time.Now().Add(time.Second)}}}}
	w := httptest.NewRecorder()
	if broker.Accept(w, r, Binding{Purpose: "origin_check"}, "serial") == nil || w.Code != 403 {
		t.Fatal("oversized authorizer lease admitted through certificate cap")
	}
}
