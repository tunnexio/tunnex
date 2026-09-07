package aigateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func TestKeyEnvelopeBinding(t *testing.T) {
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{0x17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	org, device := uuid.New(), uuid.New()
	keyID, value := uuid.NewString(), "sk-bf-test-secret"
	sealed, err := SealKey(sealer, org, device, keyID, 7, value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, value) {
		t.Fatal("key was not sealed")
	}
	if got, err := OpenKey(sealer, org, device, keyID, 7, sealed); err != nil || got != value {
		t.Fatal("roundtrip failed")
	}
	second, err := SealKey(sealer, org, device, keyID, 7, value)
	if err != nil || second == sealed {
		t.Fatal("fresh nonce missing")
	}
	for _, tc := range []struct {
		name        string
		org, device uuid.UUID
		keyID       string
		revision    int64
	}{
		{"org", uuid.New(), device, keyID, 7},
		{"device", org, uuid.New(), keyID, 7},
		{"native_key", org, device, uuid.NewString(), 7},
		{"revision", org, device, keyID, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OpenKey(sealer, tc.org, tc.device, tc.keyID, tc.revision, sealed)
			if got != "" || err != ErrKeyEnvelope {
				t.Fatal("substitution accepted or error exposed details")
			}
		})
	}
	rotated, _ := crypto.NewSealer(bytes.Repeat([]byte{0x18}, 32))
	if got, err := OpenKey(rotated, org, device, keyID, 7, sealed); got != "" || err != ErrKeyEnvelope {
		t.Fatal("wrong master key accepted")
	}
	raw, _ := base64.StdEncoding.DecodeString(sealed)
	raw[len(raw)-1] ^= 1
	if got, err := OpenKey(sealer, org, device, keyID, 7, base64.StdEncoding.EncodeToString(raw)); got != "" || err != ErrKeyEnvelope {
		t.Fatal("corrupted ciphertext accepted")
	}
	base := keyEnvelope{Version: keyEnvelopeVersion, Purpose: keyEnvelopePurpose, Org: org, Device: device, KeyID: keyID, Revision: 7, Value: value}
	for _, kind := range []string{"version", "purpose", "invalid_value", "unknown_field", "trailing_json"} {
		t.Run(kind, func(t *testing.T) {
			envelope := base
			switch kind {
			case "version":
				envelope.Version++
			case "purpose":
				envelope.Purpose = "other"
			case "invalid_value":
				envelope.Value = "bad\nheader"
			}
			body, _ := json.Marshal(envelope)
			if kind == "unknown_field" {
				body = append(body[:len(body)-1], []byte(`,"extra":true}`)...)
			}
			if kind == "trailing_json" {
				body = append(body, []byte(` {}`)...)
			}
			ciphertext, _ := sealer.Seal(body)
			if got, err := OpenKey(sealer, org, device, keyID, 7, ciphertext); got != "" || err != ErrKeyEnvelope {
				t.Fatal("invalid authenticated envelope accepted")
			}
		})
	}
}

func TestKeyEnvelopeInputBounds(t *testing.T) {
	sealer, _ := crypto.NewSealer(bytes.Repeat([]byte{0x17}, 32))
	org, device := uuid.New(), uuid.New()
	for _, tc := range []struct {
		org, device uuid.UUID
		id          string
		revision    int64
		value       string
	}{
		{uuid.Nil, device, "id", 1, "key"}, {org, uuid.Nil, "id", 1, "key"}, {org, device, "", 1, "key"},
		{org, device, strings.Repeat("x", 256), 1, "key"}, {org, device, "id", 0, "key"}, {org, device, "id", -1, "key"},
		{org, device, "id", 1, ""}, {org, device, "id", 1, strings.Repeat("x", 4097)}, {org, device, "bad\nid", 1, "key"},
	} {
		if got, err := SealKey(sealer, tc.org, tc.device, tc.id, tc.revision, tc.value); got != "" || err != ErrKeyEnvelope {
			t.Fatal("invalid binding accepted")
		}
	}
	if got, err := SealKey(nil, org, device, "id", 1, "key"); got != "" || err != ErrKeyEnvelope {
		t.Fatal("nil sealer accepted")
	}
	for _, sealed := range []string{"", "invalid", strings.Repeat("x", maxSealedKeyBytes+1)} {
		if got, err := OpenKey(sealer, org, device, "id", 1, sealed); got != "" || err != ErrKeyEnvelope {
			t.Fatal("invalid ciphertext bounds accepted")
		}
	}
	if got, err := OpenKey(nil, org, device, "id", 1, "invalid"); got != "" || err != ErrKeyEnvelope {
		t.Fatal("nil opener accepted")
	}
}
