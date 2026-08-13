// Package wgkey holds WireGuard key helpers shared by the control plane:
// validating a reported public key and (for the browser flow) generating a
// keypair whose private key is delivered once and never stored.
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

// Valid reports whether s is a standard-base64-encoded 32-byte key (the shape of
// a Curve25519 WireGuard public key) and not the all-zero degenerate point.
func Valid(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return false
	}
	var zero bool = true
	for _, b := range raw {
		if b != 0 {
			zero = false
			break
		}
	}
	return !zero
}

// Generate returns a fresh X25519 keypair as base64 (private, public). The caller
// delivers the private key to the client ONCE and never persists it — the
// control plane stores only the public key.
func Generate() (privB64, pubB64 string, err error) {
	pk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pk.Bytes()),
		base64.StdEncoding.EncodeToString(pk.PublicKey().Bytes()), nil
}
