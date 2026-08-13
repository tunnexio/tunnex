package crypto

import (
	"strings"
	"testing"
)

// TestFingerprint pins the proof-of-secret convention (S4.5): keyed, stable,
// short, and NOT the sealed ciphertext.
func TestFingerprint(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	s, err := NewSealer(key)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	fp := s.Fingerprint([]byte("super-secret-client-secret"))
	if len(fp) != 12 {
		t.Fatalf("fingerprint len = %d (%q), want 12", len(fp), fp)
	}
	if strings.ToLower(fp) != fp || strings.TrimLeft(fp, "0123456789abcdef") != "" {
		t.Fatalf("fingerprint %q is not lowercase hex", fp)
	}

	// Deterministic for the same input (so a later GET can be compared to the
	// write-time value).
	if again := s.Fingerprint([]byte("super-secret-client-secret")); again != fp {
		t.Fatalf("fingerprint not deterministic: %q vs %q", fp, again)
	}
	// Different inputs → different fingerprints.
	if other := s.Fingerprint([]byte("a-different-secret")); other == fp {
		t.Fatal("distinct secrets produced the same fingerprint")
	}

	// KEYED: a different master key yields a different fingerprint for the same
	// plaintext (this is what makes it safe to store unsealed — not a bare hash).
	key2 := make([]byte, KeySize)
	for i := range key2 {
		key2[i] = byte(255 - i)
	}
	s2, _ := NewSealer(key2)
	if s2.Fingerprint([]byte("super-secret-client-secret")) == fp {
		t.Fatal("fingerprint is not keyed — same plaintext under a different key must differ")
	}

	// The fingerprint must NOT be the sealed value (never a way back to the secret).
	sealed, _ := s.Seal([]byte("super-secret-client-secret"))
	if strings.Contains(sealed, fp) {
		t.Fatal("fingerprint appears inside the sealed ciphertext")
	}
}
