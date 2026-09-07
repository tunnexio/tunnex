package aigateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

const keyEnvelopePurpose = "tunnex-ai-bifrost-key"
const keyEnvelopeVersion = 1
const maxSealedKeyBytes = 8192

// ErrKeyEnvelope deliberately reveals no ciphertext, key material or binding
// details. Callers must never wrap it with those values in logs or responses.
var ErrKeyEnvelope = errors.New("AI internal credential unavailable")

type keyEnvelope struct {
	Version  int       `json:"version"`
	Purpose  string    `json:"purpose"`
	Org      uuid.UUID `json:"org_id"`
	Device   uuid.UUID `json:"device_id"`
	KeyID    string    `json:"key_id"`
	Revision int64     `json:"revision"`
	Value    string    `json:"value"`
}

func validKeyBinding(org, device uuid.UUID, keyID string, revision int64) bool {
	return org != uuid.Nil && device != uuid.Nil && revision > 0 && len(keyID) <= 255 && validKey(keyID)
}

// SealKey binds a Bifrost internal key to its exact CP owner and policy
// revision. The platform Sealer supplies authenticated encryption; the
// encrypted envelope supplies purpose and identity binding without new crypto.
func SealKey(sealer *crypto.Sealer, org, device uuid.UUID, keyID string, revision int64, value string) (string, error) {
	if sealer == nil || !validKeyBinding(org, device, keyID, revision) || !validKey(value) {
		return "", ErrKeyEnvelope
	}
	raw, err := json.Marshal(keyEnvelope{Version: keyEnvelopeVersion, Purpose: keyEnvelopePurpose, Org: org, Device: device, KeyID: keyID, Revision: revision, Value: value})
	if err != nil {
		return "", ErrKeyEnvelope
	}
	defer clear(raw)
	sealed, err := sealer.Seal(raw)
	if err != nil || len(sealed) > maxSealedKeyBytes {
		return "", ErrKeyEnvelope
	}
	return sealed, nil
}

// OpenKey refuses a valid ciphertext moved across tenants, devices, native
// keys, purposes or policy revisions. Expected binding must come from trusted
// database state, never caller-supplied inference headers.
func OpenKey(sealer *crypto.Sealer, org, device uuid.UUID, keyID string, revision int64, sealed string) (string, error) {
	if sealer == nil || !validKeyBinding(org, device, keyID, revision) || sealed == "" || len(sealed) > maxSealedKeyBytes {
		return "", ErrKeyEnvelope
	}
	raw, err := sealer.Open(sealed)
	if err != nil {
		return "", ErrKeyEnvelope
	}
	defer clear(raw)
	var envelope keyEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF {
		return "", ErrKeyEnvelope
	}
	if envelope.Version != keyEnvelopeVersion || envelope.Purpose != keyEnvelopePurpose || envelope.Org != org || envelope.Device != device || envelope.KeyID != keyID || envelope.Revision != revision || !validKey(envelope.Value) {
		return "", ErrKeyEnvelope
	}
	return envelope.Value, nil
}
