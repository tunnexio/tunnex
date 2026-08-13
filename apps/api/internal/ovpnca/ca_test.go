package ovpnca

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func newSealer(t *testing.T) *crypto.Sealer {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i) // deterministic; the sealer is exercised, not the key's secrecy
	}
	s, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

// newCA builds a CA WITHOUT the DB (via the private generate) so the crypto/trust tests need no
// TUNNEX_TEST_DATABASE_URL. The DB round-trip (LoadOrCreate) is covered by the ovpn service test.
func newCA(t *testing.T) *CA {
	t.Helper()
	ca, _, _, err := generate(newSealer(t))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return ca
}

func parseLeaf(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		t.Fatal("malformed issued cert PEM")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	return leaf
}

// TestClientCAIsolatedFromOtherRoot is the D-S9.1-1 trust-isolation red: a client cert is bound to
// its ISSUING CA and does NOT verify against any other root. Two independent CAs stand in for the
// agent-CA / client-CA split — the property is "a cert from one root can never authenticate under
// another root's pool," which is exactly what keeps an OVPN client cert from authenticating as an
// agent (the agent mTLS layer trusts ONLY agentca's pool, never this one).
func TestClientCAIsolatedFromOtherRoot(t *testing.T) {
	ca1 := newCA(t)
	ca2 := newCA(t) // an independent root (stands in for the agent CA)

	p, err := ca1.IssueClient("device-abc")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	leaf := parseLeaf(t, p.CertPEM)

	// Verifies against its OWN issuer.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     ca1.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("client cert must verify against its issuing CA: %v", err)
	}
	// Must NOT verify against the OTHER root — trust isolation.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     ca2.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Fatal("D-S9.1-1 VIOLATED: a client cert verified against a foreign root — an OVPN client " +
			"cert must never authenticate under another CA (e.g. as an agent)")
	}
}

// TestIssueClientLifetimeAndUsage locks D-S9.2-2 (365d) + the client-auth EKU: the leaf is a
// CLIENT-auth cert (not server/agent), lives ~ClientCertTTL, and carries a non-empty serial (the
// CRL identity). Server-side keygen (D-S9.2-1) means the returned Profile also carries the private
// key — asserted present here, and asserted NEVER persisted by the service test.
func TestIssueClientLifetimeAndUsage(t *testing.T) {
	ca := newCA(t)
	p, err := ca.IssueClient("device-xyz")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if p.Serial == "" {
		t.Fatal("issued cert must carry a serial (the CRL identity)")
	}
	if p.PrivateKeyPEM == "" {
		t.Fatal("D-S9.2-1: server-side keygen must return the private key for one-time delivery")
	}
	leaf := parseLeaf(t, p.CertPEM)

	// Client-auth EKU only — NOT server auth (a client cert must not be usable as a server/agent id).
	foundClient := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			t.Fatal("client cert must NOT carry server-auth EKU")
		}
		if eku == x509.ExtKeyUsageClientAuth {
			foundClient = true
		}
	}
	if !foundClient {
		t.Fatal("client cert must carry the client-auth EKU")
	}

	// Lifetime ~= ClientCertTTL (long-lived, D-S9.2-2). Allow a minute of skew from NotBefore backdate.
	got := leaf.NotAfter.Sub(leaf.NotBefore)
	if got < ClientCertTTL-2*time.Minute || got > ClientCertTTL+2*time.Minute {
		t.Fatalf("lifetime = %s, want ~%s (D-S9.2-2)", got, ClientCertTTL)
	}
	if leaf.NotAfter.Before(time.Now().Add(300 * 24 * time.Hour)) {
		t.Fatalf("client cert should be long-lived; NotAfter = %s", leaf.NotAfter)
	}
}

// TestSerialsAreUnique guards the CRL key: every issuance draws a fresh 128-bit serial, so the
// ovpn_client_certs unique index never collides in practice.
func TestSerialsAreUnique(t *testing.T) {
	ca := newCA(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, err := ca.IssueClient("dev")
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if seen[p.Serial] {
			t.Fatalf("serial collision: %s", p.Serial)
		}
		seen[p.Serial] = true
	}
}

// TestSelfTest exercises the boot self-test path.
func TestSelfTest(t *testing.T) {
	if err := newCA(t).SelfTest(); err != nil {
		t.Fatalf("selftest: %v", err)
	}
}

// TestIssueServerIsServerAuthNotClient (S9.1 Slice 4a) locks the client/server EKU split: the server
// leaf carries server-auth ONLY (a client must never authenticate as the server, and the server leaf
// must never pass as a client). Both chain to the same CA but are role-separated by EKU.
func TestIssueServerIsServerAuthNotClient(t *testing.T) {
	ca := newCA(t)
	p, err := ca.IssueServer("gateway-aws-1")
	if err != nil {
		t.Fatalf("issue server: %v", err)
	}
	if p.PrivateKeyPEM == "" || p.Serial == "" {
		t.Fatal("server issuance must return the key + serial")
	}
	leaf := parseLeaf(t, p.CertPEM)

	// server-auth present, client-auth ABSENT.
	var srv, cli bool
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			srv = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			cli = true
		}
	}
	if !srv {
		t.Fatal("server cert must carry the server-auth EKU")
	}
	if cli {
		t.Fatal("server cert must NOT carry client-auth EKU (role separation)")
	}
	// verifies as a SERVER against the CA, and FAILS the client-auth usage.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server cert must verify for server-auth: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("server cert must NOT verify for client-auth (a server leaf can't pass as a client)")
	}
}

// TestGenerateCRL is the Slice 5 D-S9.5-1/2 red: the CA signs a COMPLETE, verifiable CRL from the
// revoked set; an issued cert's serial appears on it; the CRL's signature checks against the CA; and an
// EMPTY revoked set still yields a valid, signed, EMPTY CRL (crl-verify always-on, never a missing file).
func TestGenerateCRL(t *testing.T) {
	ca := newCA(t)
	p, err := ca.IssueClient("device-x")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Non-empty CRL: the revoked serial must appear, and the CRL must verify against the CA.
	crlPEM, err := ca.GenerateCRL([]RevokedCert{{Serial: p.Serial, RevokedAt: time.Now()}}, 1)
	if err != nil {
		t.Fatalf("generate crl: %v", err)
	}
	blk, _ := pem.Decode(crlPEM)
	if blk == nil {
		t.Fatal("malformed CRL PEM")
	}
	crl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		t.Fatalf("parse crl: %v", err)
	}
	if err := crl.CheckSignatureFrom(ca.cert); err != nil {
		t.Fatalf("CRL must be signed by the CA: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL must list exactly the one revoked serial; got %d", len(crl.RevokedCertificateEntries))
	}
	leaf := parseLeaf(t, p.CertPEM)
	if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("the CRL entry's serial must equal the revoked cert's serial")
	}
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		t.Fatal("CRL must carry a nextUpdate after thisUpdate (never-expired discipline)")
	}

	// Empty CRL is FIRST-CLASS: a valid, signed CRL with zero entries (never a missing file).
	empty, err := ca.GenerateCRL(nil, 2)
	if err != nil {
		t.Fatalf("empty crl: %v", err)
	}
	eb, _ := pem.Decode(empty)
	ecrl, err := x509.ParseRevocationList(eb.Bytes)
	if err != nil {
		t.Fatalf("parse empty crl: %v", err)
	}
	if err := ecrl.CheckSignatureFrom(ca.cert); err != nil {
		t.Fatalf("empty CRL must still be CA-signed: %v", err)
	}
	if len(ecrl.RevokedCertificateEntries) != 0 {
		t.Fatal("empty CRL must have zero entries")
	}
}
