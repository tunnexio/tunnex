// Package ipsec contains the bounded primitives for future IPsec configuration.
package ipsec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

const (
	pskEnvelopeVersion = 1
	pskEnvelopePurpose = "tunnex-ipsec-psk"
	maxPSKBytes        = 4096
	maxSealedPSKBytes  = 16384
)

// ErrPSKEnvelope reveals no secret, ciphertext, or ownership details. Callers
// must not append those values when reporting a failure.
var ErrPSKEnvelope = errors.New("IPsec credential unavailable")

// PSKBinding identifies the exact owner and revision of a stored tunnel secret.
// Callers must obtain this identity from authoritative ownership and an
// authenticated principal, not from unverified request claims.
type PSKBinding struct {
	OrgID        uuid.UUID
	ConnectionID uuid.UUID
	TunnelID     uuid.UUID
	Revision     int64
}

type pskEnvelope struct {
	Version      int       `json:"version"`
	Purpose      string    `json:"purpose"`
	OrgID        uuid.UUID `json:"org_id"`
	ConnectionID uuid.UUID `json:"connection_id"`
	TunnelID     uuid.UUID `json:"tunnel_id"`
	Revision     int64     `json:"revision"`
	Value        string    `json:"value"`
}

func validBinding(binding PSKBinding) bool {
	return binding.OrgID != uuid.Nil && binding.ConnectionID != uuid.Nil && binding.TunnelID != uuid.Nil && binding.Revision > 0
}

func validPSK(value string) bool {
	if len(value) == 0 || len(value) > maxPSKBytes || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// SealPSK preserves accepted input exactly. These are storage bounds, not a
// provider's PSK format rules. Temporary plaintext buffers are cleared; Go
// strings and copies made by the JSON implementation cannot be guaranteed erased.
func SealPSK(sealer *crypto.Sealer, binding PSKBinding, value string) (string, error) {
	if sealer == nil || !validBinding(binding) || !validPSK(value) {
		return "", ErrPSKEnvelope
	}
	var raw bytes.Buffer
	defer func() { clear(raw.Bytes()) }()
	encoder := json.NewEncoder(&raw)
	// Avoid six-byte HTML escapes exceeding the ciphertext bound for otherwise
	// valid 4096-byte input. This envelope is never rendered as HTML.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(pskEnvelope{
		Version: pskEnvelopeVersion, Purpose: pskEnvelopePurpose,
		OrgID: binding.OrgID, ConnectionID: binding.ConnectionID,
		TunnelID: binding.TunnelID, Revision: binding.Revision, Value: value,
	}); err != nil {
		return "", ErrPSKEnvelope
	}
	sealed, err := sealer.Seal(raw.Bytes())
	if err != nil || len(sealed) > maxSealedPSKBytes {
		return "", ErrPSKEnvelope
	}
	return sealed, nil
}

// OpenPSK refuses ciphertext copied to another owner, purpose, or revision.
// Expected binding must come from authoritative stored ownership.
func OpenPSK(sealer *crypto.Sealer, binding PSKBinding, sealed string) (string, error) {
	if sealer == nil || !validBinding(binding) || sealed == "" || len(sealed) > maxSealedPSKBytes {
		return "", ErrPSKEnvelope
	}
	raw, err := sealer.Open(sealed)
	if err != nil {
		return "", ErrPSKEnvelope
	}
	defer clear(raw)
	if !utf8.Valid(raw) {
		return "", ErrPSKEnvelope
	}
	var envelope pskEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF {
		return "", ErrPSKEnvelope
	}
	if envelope.Version != pskEnvelopeVersion || envelope.Purpose != pskEnvelopePurpose ||
		envelope.OrgID != binding.OrgID || envelope.ConnectionID != binding.ConnectionID ||
		envelope.TunnelID != binding.TunnelID || envelope.Revision != binding.Revision || !validPSK(envelope.Value) {
		return "", ErrPSKEnvelope
	}
	return envelope.Value, nil
}
