package control

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// testCA is a throwaway CA that mimics the control plane's cert issuance.
type testCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// sign issues a leaf for a CSR (client or server auth), returning cert PEM + serial.
func (c *testCA) sign(t *testing.T, csrDER []byte, eku x509.ExtKeyUsage) (string, string) {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: csr.Subject, DNSNames: []string{"tunnex-control"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(sn.Bytes())
}

func (c *testCA) clientCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, csr, _ := GenerateKeyAndCSR(cn)
	blk, _ := pem.Decode(csr)
	cp, _ := c.sign(t, blk.Bytes, x509.ExtKeyUsageClientAuth)
	return []byte(cp), key
}

// TestClientRenewHotSwaps proves the happy path: an agent renews over the
// channel and subsequent requests use the FRESH cert (hot-swap), uninterrupted.
func TestClientRenewHotSwaps(t *testing.T) {
	ca := newTestCA(t)

	var mu sync.Mutex
	var lastSerial string
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/desired-state", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastSerial = hex.EncodeToString(r.TLS.PeerCertificates[0].SerialNumber.Bytes())
		mu.Unlock()
		_, _ = w.Write([]byte(`{"protocol_version":1,"node_id":"n","peers":[]}`))
	})
	mux.HandleFunc("/agent/renew", func(w http.ResponseWriter, r *http.Request) {
		csrPEM, _ := io.ReadAll(r.Body)
		blk, _ := pem.Decode(csrPEM)
		leaf, _ := ca.sign(t, blk.Bytes, x509.ExtKeyUsageClientAuth)
		_, _ = w.Write([]byte(leaf))
	})

	// Server presents a CA-signed server cert and requires client certs vs the CA.
	srvKeyPEM, srvCsr, _ := GenerateKeyAndCSR("tunnex-control")
	sb, _ := pem.Decode(srvCsr)
	srvCertPEM, _ := ca.sign(t, sb.Bytes, x509.ExtKeyUsageServerAuth)
	srvCert, _ := tls.X509KeyPair([]byte(srvCertPEM), srvKeyPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.pem)

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	defer srv.Close()

	certPEM, keyPEM := ca.clientCert(t, "gw-1")
	client, err := NewClient(srv.URL, "tunnex-control", "gw-1", certPEM, keyPEM, ca.pem)
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	if _, err := client.FetchDesired(t.Context()); err != nil {
		t.Fatalf("fetch before renew: %v", err)
	}
	mu.Lock()
	before := lastSerial
	mu.Unlock()

	newCert, newKey, err := client.Renew(t.Context(), "0.2.0")
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if _, err := tls.X509KeyPair(newCert, newKey); err != nil {
		t.Fatalf("renewed cert+key not a valid pair: %v", err)
	}

	// After renew, the NEXT request presents the fresh cert (hot-swap, no rebuild).
	if _, err := client.FetchDesired(t.Context()); err != nil {
		t.Fatalf("fetch after renew: %v", err)
	}
	mu.Lock()
	after := lastSerial
	mu.Unlock()
	if before == after {
		t.Fatal("renewal did not hot-swap the client certificate")
	}
}
