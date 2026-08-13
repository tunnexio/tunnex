package control

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// goldenSPKIB64 / goldenFingerprint pin the re-key key-fingerprint digest (S13.1 D10).
//
// THREE IMPLEMENTATIONS OF ONE DIGEST EXIST, IN PLACES THAT CANNOT IMPORT EACH OTHER:
//
//  1. this agent (control.KeyFingerprintFromSPKI) — computes the identifier it SENDS
//  2. the control plane (nodes.KeyFingerprint) — computes the audit/log prefix
//  3. PostgreSQL (nodes.cert_key_fingerprint, a GENERATED column, migration 0061) — what the lookup MATCHES ON
//
// (1) and (3) are load-bearing: if they disagree, re-key by fingerprint silently never matches, and the failure looks
// exactly like "this gateway cannot be recovered" — the outcome D10 exists to prevent. Two Go modules and one SQL
// expression cannot share code, so they share a GOLDEN VECTOR instead, asserted in all three places. Changing the
// digest fails here, in the control plane's unit test, and in the integration test against the generated column.
//
// A PUBLIC key deliberately: the vector is an SPKI, so no private key material enters the repository to prove this.
const (
	goldenSPKIB64     = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxdvgFUdNnFAg1ksdPieol2FK5vt7iQ6oI9AtqA2wZW7tet/f7tRS2xSz4vpUCHJGb12x3auzeVf3/7q/QL9/XgrWh5MBp1wVRuKQG/I86Rr6fp4070xmBhXk2NjmT8CH+honySylp2nJ3LAFFtHPwoV/zyRqpB9BS0iuooFS3Pr+HbEtEX91I5i7Z0ymzwjdnbMVd5YHCf2JjODV1uGpRlf8HoG9kA4UOR3Eki4B69nl3kA2uz+8g4Ka20icXAwaNjMEq8R6oeDW1wmu+ZXPS9YnVYSvEntwDzPz9Kkal372q9Ojt03W27E2X6ouXTlT1KblEXvv73bV6C7VuvCB6QIDAQAB"
	goldenFingerprint = "1e98cb7cd8f91d59b2f90727f5543f9c9e5413332b160c93534c283ea3bdba94"
)

func TestKeyFingerprintMatchesTheGoldenVector(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(goldenSPKIB64)
	if err != nil {
		t.Fatal(err)
	}
	if got := KeyFingerprintFromSPKI(der); got != goldenFingerprint {
		t.Fatalf("the fingerprint construction changed.\n got %s\nwant %s\n\nThis digest is matched against a "+
			"database-GENERATED column and computed independently by the control plane. A change here that is not "+
			"made there makes re-key-by-fingerprint match nothing — and the failure is indistinguishable from "+
			"'this gateway cannot be recovered'.", got, goldenFingerprint)
	}
}

// TestKeyFingerprintFromPEMAgreesWithTheSPKIForm — the wrapper must not introduce a second construction. It is what
// the agent actually calls, over a private key; the golden is pinned on the SPKI form.
func TestKeyFingerprintFromPEMAgreesWithTheSPKIForm(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := KeyFingerprintFromPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got != KeyFingerprintFromSPKI(der) {
		t.Fatal("KeyFingerprintFromPEM must be the SPKI digest of the key's public half, not a second construction")
	}
}
