package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// newToken returns a URL-safe secret (given to the user) and its sha-256 hash
// (stored). Only the hash is ever persisted.
func newToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashToken(raw), nil
}

func hashToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}
