package serveraccess

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func TestRecoveryEnvelopeRotationRetainsCiphertextAndRejectsCompromise(t *testing.T) {
	oldMaster, newMaster := make([]byte, 32), make([]byte, 32)
	rand.Read(oldMaster)
	rand.Read(newMaster)
	oldSeal, _ := secret.NewSealer(oldMaster)
	newSeal, _ := secret.NewSealer(newMaster)
	defer clear(oldMaster)
	defer clear(newMaster)
	org, id := uuid.New(), uuid.New()
	dek := make([]byte, 32)
	rand.Read(dek)
	defer clear(dek)
	plaintext, _ := json.Marshal(recordingKey{org, id, dek})
	defer clear(plaintext)
	oldEnvelope, _ := oldSeal.Seal(plaintext)
	event := recordingEvent{Seq: 0, Millis: 1, Type: "output", Data: []byte("synthetic recovery fixture")}
	ciphertext, e := sealEvent(dek, org, id, event)
	if e != nil {
		t.Fatal(e)
	}
	opened, e := oldSeal.Open(oldEnvelope)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(opened)
	newEnvelope, e := newSeal.Seal(opened)
	if e != nil {
		t.Fatal(e)
	}
	migrated := &Service{sealer: newSeal}
	if _, e = migrated.recordingKey(org, id, []byte(oldEnvelope)); e == nil {
		t.Fatal("wrong wrapping master accepted")
	}
	rotatedKey, e := migrated.recordingKey(org, id, []byte(newEnvelope))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(rotatedKey)
	got, e := openEvent(rotatedKey, org, id, 0, ciphertext)
	if e != nil || !bytes.Equal(got.Data, event.Data) {
		t.Fatal("rewrap required ciphertext rewrite or lost contents")
	}
	if _, e = migrated.recordingKey(uuid.New(), id, []byte(newEnvelope)); e == nil {
		t.Fatal("foreign org accepted rotated envelope")
	}
	if _, e = migrated.recordingKey(org, uuid.New(), []byte(newEnvelope)); e == nil {
		t.Fatal("foreign recording accepted rotated envelope")
	}
	modified := bytes.Clone(ciphertext)
	modified[len(modified)-1] ^= 1
	if _, e = openEvent(rotatedKey, org, id, 0, modified); e == nil {
		t.Fatal("compromised ciphertext accepted after rotation")
	}
}
