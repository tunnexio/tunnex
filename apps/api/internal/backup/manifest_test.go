package backup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func sealerWithRandomKey(t *testing.T) *crypto.Sealer {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestRestoreRefusesAWrongMasterKey — the slice's central negative, and the one that arrived by accident
// three times before it was ever written (S11-8: bringing the compose stack up seals an agent CA under the
// stack's key, after which the test suite's key cannot open it).
//
// The catastrophic outcome is NOT a failed restore. It is a restore that SUCCEEDS with the wrong key: the
// control plane starts, serves requests, and cannot read its own agent CA — so every enrolled gateway is
// orphaned, and the operator learns this later, from the fleet, with the backup already written over the
// evidence. Hence: refuse, loudly, before anything is written.
func TestRestoreRefusesAWrongMasterKey(t *testing.T) {
	original := sealerWithRandomKey(t)
	different := sealerWithRandomKey(t)

	m := NewManifest(original, 53, "nightly")

	// The right key verifies.
	if err := Verify(m, original); err != nil {
		t.Fatalf("the key this backup was taken under must verify, got %v", err)
	}

	// A DIFFERENT key must be refused — this is the orphan-the-fleet case.
	err := Verify(m, different)
	if err == nil {
		t.Fatal("a restore under a DIFFERENT master key was ACCEPTED — this produces a control plane that " +
			"looks healthy and cannot read its own agent CA, orphaning every enrolled gateway")
	}
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("the refusal must be identifiable as a key mismatch, got %v", err)
	}
	// The message must be actionable: both fingerprints, and what would happen if it proceeded.
	for _, want := range []string{"AGENT CA", "orphaned", KeyFingerprint(different), m.MasterKeyFingerprint} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must name %q so the operator can act on it; got: %v", want, err)
		}
	}
}

// TestManifestCarriesNoKeyMaterial — the property the whole design rests on. A backup that carries its own
// key is equivalent to no encryption at rest for whoever obtains the file, and backups are the most-copied,
// least-guarded artifact in a deployment. This red exists so a future "helpful" change that adds the key for
// restore convenience fails the build instead of silently making every historical backup a full compromise.
func TestManifestCarriesNoKeyMaterial(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 1) // a known, searchable key
	}
	s, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := NewManifest(s, 53, "note").Write(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()

	if bytes.Contains(out, key) {
		t.Fatal("the manifest contains the RAW MASTER KEY — every backup ever taken would be a full " +
			"compromise of the material it protects")
	}
	// Any plausible encoding of it, too.
	for name, enc := range map[string]string{
		"hex":    "0102030405060708",
		"base64": "AQIDBAUGBwg",
	} {
		if bytes.Contains(out, []byte(enc)) {
			t.Fatalf("the manifest appears to contain the master key %s-encoded", name)
		}
	}

	// And the fingerprint that IS present must not be a bare hash of the key (that would be an offline
	// guessing oracle); it is keyed, so a different key over the same probe yields a different value.
	other := sealerWithRandomKey(t)
	if KeyFingerprint(s) == KeyFingerprint(other) {
		t.Fatal("the fingerprint does not distinguish master keys — it cannot verify anything")
	}
}

// TestVerifyRefusesAnUnverifiableManifest — a manifest with no fingerprint must not be waved through.
// "Cannot verify" and "verified" are different answers, and only one of them may proceed.
func TestVerifyRefusesAnUnverifiableManifest(t *testing.T) {
	s := sealerWithRandomKey(t)
	if err := Verify(Manifest{Version: ManifestVersion}, s); err == nil {
		t.Fatal("a manifest with no fingerprint was accepted — restoring blind risks a CP that cannot read " +
			"its own agent CA")
	}
	if err := Verify(Manifest{Version: 99, MasterKeyFingerprint: "x"}, s); err == nil {
		t.Fatal("an unsupported manifest version was accepted")
	}
}

// TestManifestRoundTrip — the manifest survives write/read unchanged.
func TestManifestRoundTrip(t *testing.T) {
	s := sealerWithRandomKey(t)
	want := NewManifest(s, 53, "pre-upgrade")
	var buf bytes.Buffer
	if err := want.Write(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.MasterKeyFingerprint != want.MasterKeyFingerprint || got.SchemaVersion != want.SchemaVersion ||
		got.Version != want.Version || got.Note != want.Note {
		t.Fatalf("manifest did not round-trip: got %+v want %+v", got, want)
	}
	if err := Verify(got, s); err != nil {
		t.Fatalf("a round-tripped manifest must still verify: %v", err)
	}
}
