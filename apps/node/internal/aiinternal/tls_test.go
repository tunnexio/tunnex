package aiinternal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Internal AI CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

var serial int64 = 100

// leaf signs pub for the given SANs and validity.
func (ca *testCA) leaf(t *testing.T, pub any, ips []net.IP, names []string, notBefore, notAfter time.Time) string {
	t.Helper()
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: notBefore, NotAfter: notAfter, IPAddresses: ips, DNSNames: names,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// sign answers a CSR the way the control plane does: exactly the CSR's SANs, 30 days.
func (ca *testCA) sign(t *testing.T, csrPEM string) control.AIInternalCertificate {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("bad CSR: %v", err)
	}
	now := time.Now()
	return control.AIInternalCertificate{CertificatePEM: ca.leaf(t, csr.PublicKey, csr.IPAddresses, csr.DNSNames, now.Add(-time.Minute), now.Add(30*24*time.Hour)),
		ChainPEM: ca.pem, NotAfter: now.Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)}
}

func testEndpoint(t *testing.T) *Endpoint {
	t.Helper()
	ep, err := ParseDesired(validDoc())
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

func TestCSRNamesExactlyTheConfiguredSANsWithAFreshP256Key(t *testing.T) {
	ep := testEndpoint(t)
	key, csrPEM, err := newCSR(ep)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		t.Fatalf("not one CSR PEM block: %q", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatal(err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || !pub.Equal(&key.PublicKey) {
		t.Fatal("the CSR is not for a P-256 key the gateway holds")
	}
	if len(csr.IPAddresses) != 2 || !csr.IPAddresses[0].Equal(net.ParseIP("10.123.0.1")) || !csr.IPAddresses[1].Equal(net.ParseIP("192.168.10.5")) {
		t.Fatalf("IP SANs: %v", csr.IPAddresses)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "ai.internal.example" || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		t.Fatalf("other SANs: %v %v %v", csr.DNSNames, csr.EmailAddresses, csr.URIs)
	}
	ep.DNSName = ""
	_, csrPEM, _ = newCSR(ep)
	block, _ = pem.Decode([]byte(csrPEM))
	csr, _ = x509.ParseCertificateRequest(block.Bytes)
	if len(csr.DNSNames) != 0 {
		t.Fatalf("a DNS SAN without a DNS name: %v", csr.DNSNames)
	}
	other, _, _ := newCSR(ep)
	if other.Equal(key) {
		t.Fatal("two CSRs share a key")
	}
}

func TestVerifyIssuedAcceptsOnlyAMatchingCoveringChainedLeaf(t *testing.T) {
	ca := newTestCA(t)
	ep := testEndpoint(t)
	key, csr, _ := newCSR(ep)
	good := ca.sign(t, csr)
	now := time.Now()
	s, err := verifyIssued(key, good, ep, now)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(s.leaf.Raw)
	if s.sha256 != hex.EncodeToString(sum[:]) || len(s.cert.Certificate) != 1 || s.cert.PrivateKey != key {
		t.Fatalf("served: %+v", s)
	}
	ips := []net.IP{net.ParseIP("10.123.0.1"), net.ParseIP("192.168.10.5")}
	names := []string{"ai.internal.example"}
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherCA := newTestCA(t)
	cases := map[string]control.AIInternalCertificate{
		"another key":           {CertificatePEM: ca.leaf(t, &otherKey.PublicKey, ips, names, now.Add(-time.Minute), now.Add(time.Hour)), ChainPEM: ca.pem},
		"missing an address":    {CertificatePEM: ca.leaf(t, &key.PublicKey, ips[:1], names, now.Add(-time.Minute), now.Add(time.Hour)), ChainPEM: ca.pem},
		"missing the name":      {CertificatePEM: ca.leaf(t, &key.PublicKey, ips, nil, now.Add(-time.Minute), now.Add(time.Hour)), ChainPEM: ca.pem},
		"expired":               {CertificatePEM: ca.leaf(t, &key.PublicKey, ips, names, now.Add(-2*time.Hour), now.Add(-time.Hour)), ChainPEM: ca.pem},
		"not yet valid":         {CertificatePEM: ca.leaf(t, &key.PublicKey, ips, names, now.Add(time.Hour), now.Add(2*time.Hour)), ChainPEM: ca.pem},
		"another CA":            {CertificatePEM: good.CertificatePEM, ChainPEM: otherCA.pem},
		"no chain":              {CertificatePEM: good.CertificatePEM},
		"the leaf as its chain": {CertificatePEM: good.CertificatePEM, ChainPEM: good.CertificatePEM},
		"two leaves":            {CertificatePEM: good.CertificatePEM + good.CertificatePEM, ChainPEM: ca.pem},
		"trailing junk":         {CertificatePEM: good.CertificatePEM + "junk", ChainPEM: ca.pem},
		"a key in the answer":   {CertificatePEM: good.CertificatePEM + "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n", ChainPEM: ca.pem},
		"empty":                 {},
	}
	for name, resp := range cases {
		if _, err := verifyIssued(key, resp, ep, now); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestNeedsIssueRenewsAtOneThirdLeftOrOnSANChange(t *testing.T) {
	ca := newTestCA(t)
	ep := testEndpoint(t)
	key, csr, _ := newCSR(ep)
	s, err := verifyIssued(key, ca.sign(t, csr), ep, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !needsIssue(nil, ep, time.Now()) {
		t.Fatal("no certificate needs one")
	}
	life := s.leaf.NotAfter.Sub(s.leaf.NotBefore)
	if needsIssue(s, ep, s.leaf.NotBefore.Add(life/2)) {
		t.Fatal("renewed at half life")
	}
	if !needsIssue(s, ep, s.leaf.NotAfter.Add(-life/3)) {
		t.Fatal("not renewed with a third left")
	}
	if !needsIssue(s, ep, s.leaf.NotAfter) {
		t.Fatal("an expired leaf is kept")
	}
	moved := *ep
	moved.Addresses = append(moved.Addresses[:1:1], ep.Addresses[0].Next())
	if !needsIssue(s, &moved, time.Now()) {
		t.Fatal("a changed address keeps the old leaf")
	}
	renamed := *ep
	renamed.DNSName = "other.internal.example"
	if !needsIssue(s, &renamed, time.Now()) {
		t.Fatal("a changed name keeps the old leaf")
	}
}

func writeCustom(t *testing.T, dir string, certPEM string, key *ecdsa.PrivateKey, keyMode os.FileMode) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, customCertFile), []byte(certPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, customKeyFile)
	_ = os.Remove(path)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, keyMode); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCustomRequiresAPrivateKeyFileAndAValidPair(t *testing.T) {
	ca := newTestCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	certPEM := ca.leaf(t, &key.PublicKey, []net.IP{net.ParseIP("10.123.0.1")}, nil, now.Add(-time.Minute), now.Add(time.Hour))
	dir := t.TempDir()
	writeCustom(t, dir, certPEM, key, 0o600)
	s, err := loadCustom(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.notAfter.IsZero() || len(s.sha256) != 64 {
		t.Fatalf("served: %+v", s)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		writeCustom(t, dir, certPEM, key, mode)
		if _, err := loadCustom(dir, now); !errors.Is(err, errKeyPermissions) {
			t.Fatalf("mode %o: %v", mode, err)
		}
	}
	writeCustom(t, dir, certPEM, key, 0o400)
	if _, err := loadCustom(dir, now); err != nil {
		t.Fatalf("mode 0400: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	writeCustom(t, dir, certPEM, other, 0o600)
	if _, err := loadCustom(dir, now); err == nil {
		t.Fatal("a mismatched pair was loaded")
	}
	writeCustom(t, dir, certPEM, key, 0o600)
	if _, err := loadCustom(dir, now.Add(2*time.Hour)); err == nil {
		t.Fatal("an expired certificate was loaded")
	}
	if _, err := loadCustom(t.TempDir(), now); err == nil {
		t.Fatal("missing files were loaded")
	}
}

func TestSNIRule(t *testing.T) {
	for _, tc := range []struct {
		name, sni string
		want      bool
	}{
		{"ai.internal.example", "", true},
		{"ai.internal.example", "ai.internal.example", true},
		{"ai.internal.example", "AI.Internal.Example", true},
		{"ai.internal.example", "ai.internal.example.", true},
		{"ai.internal.example", "other.example", false},
		{"ai.internal.example", "evil.ai.internal.example", false},
		{"", "", true},
		{"", "ai.internal.example", false},
	} {
		if got := sniAllowed(tc.name, tc.sni); got != tc.want {
			t.Fatalf("name=%q sni=%q: %v", tc.name, tc.sni, got)
		}
	}
}
