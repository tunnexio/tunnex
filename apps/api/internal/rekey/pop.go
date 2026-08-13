// Package rekey verifies PROOF OF POSSESSION for gateway recovery (EPIC 13 / S13.1, D1(c) + D9).
//
// The problem it solves: a gateway whose certificate expired cannot authenticate to the mTLS agent channel — and
// /agent/renew lives behind that channel, so the only endpoint that could issue a new certificate requires the one
// that expired. Recovery therefore needs a credential the agent still holds. It holds its PRIVATE KEY: the same
// key the expired certificate binds, and the same key certificate renewal would have used. Proving possession of
// it re-attests a grant the control plane already made, rather than creating a new one.
//
// TWO HAZARDS, BOTH RULED (D9), BOTH STRUCTURAL HERE RATHER THAN PROCEDURAL:
//
//  1. BINDING. The signature must cover the NEW CSR. Without that, a proof captured from a legitimate exchange can
//     be paired with an attacker's own CSR — the attacker never possesses the key and still obtains a certificate
//     for the node. So the signed message is (nonce ‖ CSR DER), and Verify takes the CSR rather than trusting a
//     caller to have checked it separately.
//  2. REPLAY. Binding alone still permits replaying the entire captured request. So the nonce is server-issued,
//     single-use and short-lived; this package verifies against the nonce it is given, and the store enforces
//     single use.
//
// Verification alone authorizes NOTHING. It answers "does this caller hold the node's key". Whether that node may
// be re-keyed at all is nodes.RekeyAuthorized (D3), which is checked FIRST — before any cryptographic work — so
// that re-key cannot be used as a timing oracle for node liveness.
package rekey

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// ErrProofInvalid is the ONLY error a caller may surface to a client, and it is deliberately undifferentiated.
//
// The uniform-refusal rule (D8/D9): a live node, a nonexistent node, a malformed proof and a wrong-key proof must
// be indistinguishable in the response. Anything finer turns the endpoint into an oracle — for whether a serial
// exists, for whether a gateway is alive, for whether a key guess was close. Internal detail goes to the log,
// where an operator can see it and an attacker cannot.
var ErrProofInvalid = errors.New("proof of possession is invalid")

// SignedMessage is the exact byte string an agent must sign: the server nonce followed by the DER of the CSR it is
// submitting.
//
// CORRECTED (pass-3 #43). This used to say "one definition, imported by both sides' tests." THAT WAS NEVER TRUE:
// the agent is a SEPARATE GO MODULE and cannot import this package, so it necessarily carries its own
// construction (apps/node/internal/control.signedMessage). The comment vouched for a coupling that does not
// exist, which is the more dangerous kind of wrong — a future author adding the length-prefixing contemplated
// below would have trusted it and broken every gateway's ability to recover, silently.
//
// What actually binds the two is a GOLDEN VECTOR asserted in BOTH modules' tests (D10's precedent, used for the
// key fingerprint). Change this function and the golden fails on this side; change the agent's and it fails on
// theirs.
//
// The nonce comes FIRST so that a signature cannot be transplanted onto a longer message with a different nonce
// prefix; with a fixed-length nonce and length-prefixed hashing this is belt-and-braces, but the ordering costs
// nothing and removes a class of question.
func SignedMessage(nonce []byte, csrDER []byte) []byte {
	msg := make([]byte, 0, len(nonce)+len(csrDER))
	msg = append(msg, nonce...)
	return append(msg, csrDER...)
}

// Verify checks that `signature` was produced by the private key matching `spkiB64`, over SignedMessage(nonce,
// CSR), and that the CSR is itself well-formed and self-signed.
//
// storedSPKI is base64(SPKI DER) as recorded in nodes.cert_public_key at enroll/renew (migration 0057). An empty
// value means the control plane never recorded a key for this node — every node enrolled before 0057 and not since
// renewed. That is not a failure of the proof; it is an absence of verification material, and it is why the join
// token remains the always-available manual path (D1(a)).
func Verify(storedSPKIB64 string, nonce, csrPEM []byte, signature []byte) error {
	if storedSPKIB64 == "" {
		return fmt.Errorf("%w: no public key on record for this node", ErrProofInvalid)
	}
	if len(nonce) == 0 {
		// A caller reaching here with no nonce would be verifying an unbound, infinitely-replayable proof.
		return fmt.Errorf("%w: no nonce", ErrProofInvalid)
	}

	spki, err := base64.StdEncoding.DecodeString(storedSPKIB64)
	if err != nil {
		return fmt.Errorf("%w: stored key is not decodable", ErrProofInvalid)
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return fmt.Errorf("%w: stored key is not a public key", ErrProofInvalid)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		// Agents generate RSA-2048 (control.GenerateKeyAndCSR). Refusing anything else is not a limitation to
		// work around later — it keeps the verifier from silently accepting a key type whose signature semantics
		// nobody here has reasoned about.
		return fmt.Errorf("%w: stored key is not RSA", ErrProofInvalid)
	}

	blk, _ := pem.Decode(csrPEM)
	if blk == nil {
		return fmt.Errorf("%w: CSR is not PEM", ErrProofInvalid)
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return fmt.Errorf("%w: CSR does not parse", ErrProofInvalid)
	}
	// The CSR must be self-signed by ITS OWN key. Independent of the proof, and still required: an unverified CSR
	// lets a caller request a certificate over a public key they do not control.
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("%w: CSR self-signature invalid", ErrProofInvalid)
	}

	sum := sha256.Sum256(SignedMessage(nonce, blk.Bytes))
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, sum[:], signature); err != nil {
		return fmt.Errorf("%w: signature does not verify against the recorded key", ErrProofInvalid)
	}
	return nil
}
