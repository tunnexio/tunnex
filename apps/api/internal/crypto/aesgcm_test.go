package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func newTestSealer(t *testing.T) *Sealer {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	s, err := NewSealer(key)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := newTestSealer(t)
	plain := []byte("super-secret-idp-client-secret")

	sealed, err := s.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(sealed, string(plain)) {
		t.Fatal("sealed output leaks plaintext")
	}

	got, err := s.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plain)
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	s := newTestSealer(t)
	a, _ := s.Seal([]byte("same"))
	b, _ := s.Seal([]byte("same"))
	if a == b {
		t.Fatal("identical ciphertext for repeated plaintext — nonce not random")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	s := newTestSealer(t)
	sealed, _ := s.Seal([]byte("payload"))

	raw, _ := base64.StdEncoding.DecodeString(sealed)
	raw[len(raw)-1] ^= 0xff // flip a bit in the tag/ciphertext
	tampered := base64.StdEncoding.EncodeToString(raw)

	if _, err := s.Open(tampered); err == nil {
		t.Fatal("Open accepted tampered ciphertext")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	s1 := newTestSealer(t)
	s2 := newTestSealer(t)
	sealed, _ := s1.Seal([]byte("payload"))
	if _, err := s2.Open(sealed); err == nil {
		t.Fatal("Open with wrong key succeeded")
	}
}

func TestNewSealerRejectsBadKeyLength(t *testing.T) {
	if _, err := NewSealer(make([]byte, 16)); err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestSelfTest(t *testing.T) {
	if err := SelfTest(newTestSealer(t)); err != nil {
		t.Fatalf("SelfTest: %v", err)
	}
}
