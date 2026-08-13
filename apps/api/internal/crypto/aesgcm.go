// Package crypto provides authenticated encryption for data at rest.
//
// Every sensitive per-org value (starting with SSO/IdP client secrets in
// S2.3/S2.4) is sealed with AES-256-GCM under the bootstrap master key
// (see internal/secrets). GCM is authenticated, so tampering with stored
// ciphertext is detected on Open rather than silently decrypting to garbage.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// KeySize is the master-key length for AES-256.
const KeySize = 32

// fingerprintLabel domain-separates the fingerprint subkey from the AEAD key
// (derived from the same master key) so the two primitives never share bytes.
const fingerprintLabel = "tunnex-fingerprint-v1"

// Sealer encrypts and decrypts values under a fixed master key.
type Sealer struct {
	aead  cipher.AEAD
	fpKey []byte // HMAC subkey for Fingerprint (derived from the master key)
}

// NewSealer builds a Sealer from a 32-byte master key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Derive a distinct HMAC key for fingerprints from the master key.
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fingerprintLabel))
	return &Sealer{aead: aead, fpKey: mac.Sum(nil)}, nil
}

// Fingerprint returns a short, KEYED proof-of-a-secret: the first 12 hex chars
// of HMAC-SHA256(subkey, plaintext). It is safe to store unsealed and return in
// API responses — being keyed (not a bare hash), it is NOT an offline-guessing
// oracle against the plaintext, so it holds even for low-entropy inputs. Use it
// to prove "the stored secret is the one you pasted" (compare the fingerprint
// returned at write time against a later GET) WITHOUT ever revealing the secret.
// This is the codebase's proof-of-secret convention (reuse it for API keys /
// webhook secrets); never display or store a bare hash of a secret instead.
func (s *Sealer) Fingerprint(plaintext []byte) string {
	mac := hmac.New(sha256.New, s.fpKey)
	mac.Write(plaintext)
	return hex.EncodeToString(mac.Sum(nil))[:12]
}

// Seal encrypts plaintext and returns base64(nonce || ciphertext || tag).
// A fresh random nonce is used per call.
func (s *Sealer) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal. It returns an error if the input is malformed or if the
// authentication tag does not verify (tampered or wrong key).
func (s *Sealer) Open(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode sealed value: %w", err)
	}
	ns := s.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("sealed value too short")
	}
	nonce, ciphertext := raw[:ns], raw[ns:]
	return s.aead.Open(nil, nonce, ciphertext, nil)
}

// SelfTest performs a seal/open round-trip at startup so a misconfigured or
// truncated master key fails loudly before any real data is written.
func SelfTest(s *Sealer) error {
	const probe = "tunnex-crypto-selftest"
	sealed, err := s.Seal([]byte(probe))
	if err != nil {
		return fmt.Errorf("selftest seal: %w", err)
	}
	out, err := s.Open(sealed)
	if err != nil {
		return fmt.Errorf("selftest open: %w", err)
	}
	if string(out) != probe {
		return errors.New("selftest round-trip mismatch")
	}
	return nil
}
