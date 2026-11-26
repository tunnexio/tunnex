package crypto

import (
	"bytes"
	"testing"
)

// VAULT-UX-1 V19: associated data is authenticated but not encrypted, and Seal/Open are unchanged.
func TestSealWithAADBindsContext(t *testing.T) {
	s, err := NewSealer(bytes.Repeat([]byte{7}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.SealWithAAD([]byte("value"), []byte("context-a"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.OpenWithAAD(sealed, []byte("context-a"))
	if err != nil || string(got) != "value" {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if _, err = s.OpenWithAAD(sealed, []byte("context-b")); err == nil {
		t.Fatal("opened under different associated data")
	}
	if _, err = s.Open(sealed); err == nil {
		t.Fatal("AAD ciphertext opened without its associated data")
	}
	plain, err := s.Seal([]byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.OpenWithAAD(plain, []byte("context-a")); err == nil {
		t.Fatal("plain ciphertext opened with associated data")
	}
	if _, err = s.OpenWithAAD("!!", nil); err == nil {
		t.Fatal("malformed input accepted")
	}
}
