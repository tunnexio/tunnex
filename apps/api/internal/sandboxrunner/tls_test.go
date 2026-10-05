package sandboxrunner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestRealMutualTLSRoundtrip(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(id string, serial int64) tls.Certificate {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		uri, _ := url.Parse(id)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		cert, e := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		if e != nil {
			t.Fatal(e)
		}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
		if e != nil {
			t.Fatal(e)
		}
		return pair
	}
	controller := "spiffe://tunnex/controller/one"
	runner := "spiffe://tunnex/runner/one"
	broker, _ := NewBroker(runner)
	server := httptest.NewUnstartedServer(broker)
	server.TLS, e = TLSConfig(issue(controller, 2), roots)
	if e != nil {
		t.Fatal(e)
	}
	server.StartTLS()
	defer server.Close()
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	client, e := NewClient(server.URL, "localhost", controller, issue(runner, 3), roots, root)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.Run(ctx, func(context.Context, Command) (json.RawMessage, error) { return json.RawMessage(`{"ready":true}`), nil })
	}()
	payload, e := broker.Call(ctx, json.RawMessage(`{"op":"ping"}`))
	if e != nil || string(payload) != `{"ready":true}` {
		t.Fatal(string(payload), e)
	}
	cancel()
	<-done
	// A valid certificate with a foreign runner identity still fails authorization.
	foreign, e := NewClient(server.URL, "localhost", controller, issue("spiffe://tunnex/runner/other", 4), roots, root)
	if e != nil {
		t.Fatal(e)
	}
	_, status, e := foreign.exchange(context.Background(), "/internal/sandbox-runners/v1/poll", nil)
	if e != nil || status != 403 {
		t.Fatal("foreign peer admitted", status, e)
	}
}
