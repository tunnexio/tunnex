package rekey

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
)

type keypair struct {
	key  *rsa.PrivateKey
	spki string
}

func newKeypair(t *testing.T) keypair {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return keypair{key: k, spki: base64.StdEncoding.EncodeToString(der)}
}

// csrFor mints a CSR signed by `signer`'s key — normally the agent's NEW key, which is deliberately a DIFFERENT
// key from the one proving possession.
func csrFor(t *testing.T, signer *rsa.PrivateKey, cn string) (pemBytes, der []byte) {
	t.Helper()
	d, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: d}), d
}

func sign(t *testing.T, k *rsa.PrivateKey, nonce, csrDER []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(SignedMessage(nonce, csrDER))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// TestValidProofVerifies — the happy path, and it exercises the shape recovery actually uses: the OLD key proves
// possession, while the CSR carries a BRAND NEW key. The old private key may be compromised or about to be
// discarded; re-key must issue a certificate over fresh material.
func TestValidProofVerifies(t *testing.T) {
	old, fresh := newKeypair(t), newKeypair(t)
	nonce := []byte("server-issued-nonce-0123456789ab")
	csrPEM, csrDER := csrFor(t, fresh.key, "aws-gw-1")

	if err := Verify(old.spki, nonce, csrPEM, sign(t, old.key, nonce, csrDER)); err != nil {
		t.Fatalf("a proof signed by the recorded key over (nonce ‖ CSR) must verify: %v", err)
	}
}

// TestProofIsBOUNDToTheCSR — HAZARD 1 (D9), and the one that would be a silent takeover.
//
// A proof captured from a legitimate exchange must not be pairable with a DIFFERENT CSR. If it were, an attacker
// who never possesses the node's key could replay someone else's proof alongside their own CSR and receive a
// certificate for that node.
func TestProofIsBOUNDToTheCSR(t *testing.T) {
	old, victimFresh, attackerFresh := newKeypair(t), newKeypair(t), newKeypair(t)
	nonce := []byte("server-issued-nonce-0123456789ab")

	// The legitimate agent's proof, over ITS csr.
	_, victimDER := csrFor(t, victimFresh.key, "aws-gw-1")
	captured := sign(t, old.key, nonce, victimDER)

	// The attacker submits their OWN csr with the captured proof.
	attackerCSR, _ := csrFor(t, attackerFresh.key, "aws-gw-1")

	err := Verify(old.spki, nonce, attackerCSR, captured)
	if err == nil {
		t.Fatal("a proof must NOT verify against a different CSR — otherwise a captured proof plus an attacker's " +
			"own CSR yields a certificate for a node whose key the attacker never held. That is a takeover, not " +
			"a recovery")
	}
	if !errors.Is(err, ErrProofInvalid) {
		t.Errorf("refusals must be the single undifferentiated error, so the response cannot become an oracle; got %v", err)
	}
}

// TestProofIsBOUNDToTheNONCE — HAZARD 2 (D9). The same (proof, CSR) pair must not verify under a different nonce,
// which is what makes a server-issued single-use nonce able to stop request replay at all.
func TestProofIsBOUNDToTheNONCE(t *testing.T) {
	old, fresh := newKeypair(t), newKeypair(t)
	issued := []byte("nonce-A-0123456789abcdef01234567")
	csrPEM, csrDER := csrFor(t, fresh.key, "aws-gw-1")
	proof := sign(t, old.key, issued, csrDER)

	if err := Verify(old.spki, []byte("nonce-B-0123456789abcdef01234567"), csrPEM, proof); err == nil {
		t.Fatal("a proof bound to one nonce must NOT verify under another — without that, a captured request " +
			"replays forever and the nonce store protects nothing")
	}
}

// TestWrongKeyIsRefused — possession is the whole claim; a proof from any other key must fail.
func TestWrongKeyIsRefused(t *testing.T) {
	recorded, impostor, fresh := newKeypair(t), newKeypair(t), newKeypair(t)
	nonce := []byte("server-issued-nonce-0123456789ab")
	csrPEM, csrDER := csrFor(t, fresh.key, "aws-gw-1")

	if err := Verify(recorded.spki, nonce, csrPEM, sign(t, impostor.key, nonce, csrDER)); err == nil {
		t.Fatal("a signature from a key the CP did not record must be refused")
	}
}

// TestNoRecordedKeyIsRefusedNotAssumed — the coverage limitation, asserted.
//
// Every node enrolled before migration 0057 and not since renewed has no recorded key. That must REFUSE, never
// fall through to some weaker check: absence of verification material is not evidence of possession. Those nodes
// recover via the join token, which is precisely why D1 keeps (a) as the always-available manual path.
func TestNoRecordedKeyIsRefusedNotAssumed(t *testing.T) {
	old, fresh := newKeypair(t), newKeypair(t)
	nonce := []byte("server-issued-nonce-0123456789ab")
	csrPEM, csrDER := csrFor(t, fresh.key, "aws-gw-1")

	err := Verify("", nonce, csrPEM, sign(t, old.key, nonce, csrDER))
	if err == nil {
		t.Fatal("a node with NO recorded public key must be refused: there is nothing to verify against, and " +
			"'I cannot check' must never resolve to 'it is fine'")
	}
	if !errors.Is(err, ErrProofInvalid) {
		t.Errorf("must be the uniform refusal; got %v", err)
	}
}

// TestMissingNonceIsRefused guards the caller as much as the crypto: verifying with no nonce would accept an
// unbound, infinitely replayable proof. Cheap to check, catastrophic to omit.
func TestMissingNonceIsRefused(t *testing.T) {
	old, fresh := newKeypair(t), newKeypair(t)
	csrPEM, csrDER := csrFor(t, fresh.key, "aws-gw-1")

	if err := Verify(old.spki, nil, csrPEM, sign(t, old.key, nil, csrDER)); err == nil {
		t.Fatal("verification with an empty nonce must be refused — it would accept a proof that replays forever")
	}
}

// TestUnverifiedCSRIsRefused — an independent property. Even with a perfect proof of possession, a CSR that is not
// self-signed by its own key lets a caller request a certificate over a public key they do not control.
func TestUnverifiedCSRIsRefused(t *testing.T) {
	old, a, b := newKeypair(t), newKeypair(t), newKeypair(t)
	nonce := []byte("server-issued-nonce-0123456789ab")

	// Forge a CSR whose body claims a's key but whose signature comes from b: parseable, not self-consistent.
	_, aDER := csrFor(t, a.key, "aws-gw-1")
	forged := append([]byte(nil), aDER...)
	forged[len(forged)-1] ^= 0xff // corrupt the signature bytes
	forgedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: forged})
	_ = b

	if err := Verify(old.spki, nonce, forgedPEM, sign(t, old.key, nonce, forged)); err == nil {
		t.Fatal("a CSR whose self-signature does not verify must be refused, even when the proof of possession is " +
			"valid — otherwise a caller obtains a certificate over a key they do not hold")
	}
}
