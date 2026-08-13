package sso

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestPKCEChallengeIsS256OfVerifier(t *testing.T) {
	verifier, challenge, err := PKCE()
	if err != nil {
		t.Fatalf("PKCE: %v", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("challenge is not S256(verifier): got %q want %q", challenge, want)
	}
	// Fresh randomness each call.
	v2, _, _ := PKCE()
	if verifier == v2 {
		t.Fatal("PKCE verifier not random across calls")
	}
}

func TestRandomTokenUnique(t *testing.T) {
	a, _ := RandomToken()
	b, _ := RandomToken()
	if a == "" || a == b {
		t.Fatalf("RandomToken not unique/non-empty: %q %q", a, b)
	}
}
