package control

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// THE PROOF-OF-POSSESSION GOLDEN VECTOR (pass-3 #43), on D10's precedent.
//
// The re-key proof is a signature over (server nonce ‖ CSR DER). That construction exists in TWO Go modules that
// CANNOT import each other — apps/api/internal/rekey.SignedMessage and this package's signedMessage — because
// the node agent is a separate module and the control plane's package is internal. The API's comment used to
// claim "one definition, imported by both sides' tests"; it never was.
//
// D10 hit the identical problem with the key-fingerprint digest and solved it with a GOLDEN VECTOR asserted in
// every implementation (see fingerprint_test.go). Same solution here: one nonce, one CSR DER, one SHA-256 of the
// message they compose. The SAME THREE CONSTANTS are asserted in apps/api/internal/rekey/pop_test.go.
//
// WHAT BREAKS IF THIS IS NOT PINNED. The API's own comment contemplates length-prefixed hashing as a future
// hardening. Add it on one side only and every re-key proof is rejected — and the failure surfaces as the uniform
// 403, which by design says nothing about why. Every expired gateway in the fleet would report "the control plane
// refused re-key; mint a join token", the identity-destroying remedy, for a signature-format change. The golden
// makes that a loud test failure on whichever side moved.
const (
	goldenPoPNonceB64  = "bm9uY2UtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
	goldenPoPCSRDERB64 = "MIIBIjBFAgEAMBwxCjAIBgNVBAMMAWc="
	goldenPoPMessage   = "16be900279c9148706ae60f12876b02d5b21dbe64d4a6a3ff2b700ce72e42fe4"
)

func TestSignedMessageGoldenVector(t *testing.T) {
	nonce, err := base64.StdEncoding.DecodeString(goldenPoPNonceB64)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := base64.StdEncoding.DecodeString(goldenPoPCSRDERB64)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(signedMessage(nonce, csrDER))
	if got := hex.EncodeToString(sum[:]); got != goldenPoPMessage {
		t.Fatalf("the agent's proof-of-possession message construction CHANGED.\n  got  %s\n  want %s\n\n"+
			"This is the byte string every re-key signature is computed over, and the control plane builds it "+
			"independently in apps/api/internal/rekey.SignedMessage — a different Go module that cannot import "+
			"this one. If only one side changed, every expired gateway now fails re-key with the UNIFORM 403, "+
			"which says nothing about why, and each one will tell its operator to mint a join token and destroy "+
			"the node. Change both sides and this vector together, deliberately.", got, goldenPoPMessage)
	}
}
