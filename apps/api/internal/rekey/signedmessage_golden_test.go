package rekey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// THE CONTROL PLANE'S HALF OF THE PROOF-OF-POSSESSION GOLDEN VECTOR (pass-3 #43).
//
// These three constants are BYTE-IDENTICAL to the ones in
// apps/node/internal/control/signedmessage_golden_test.go, and that duplication is the point: the node agent is a
// separate Go module and cannot import this package, so the two constructions can only be bound by a shared
// value, not by shared code. D10 bound the key-fingerprint digest the same way.
//
// If you change SignedMessage — for instance to add the length-prefixed hashing the function's own comment
// contemplates — this test fails HERE and the agent's fails THERE. Both must move together, or the fleet loses
// the ability to recover and every gateway reports the uniform 403 as "mint a join token".
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
	sum := sha256.Sum256(SignedMessage(nonce, csrDER))
	if got := hex.EncodeToString(sum[:]); got != goldenPoPMessage {
		t.Fatalf("the control plane's proof-of-possession message construction CHANGED.\n  got  %s\n  want %s\n\n"+
			"The agent builds this string independently in apps/node/internal/control.signedMessage — a separate "+
			"module that cannot import this package. Change both sides and this vector together, deliberately.",
			got, goldenPoPMessage)
	}
}
