package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

// b64key returns a valid base64-encoded random n-byte key (an external source).
func b64key(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestLoadOrInitGeneratesThenReuses(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrInit(dir)
	if err != nil {
		t.Fatalf("first LoadOrInit: %v", err)
	}
	if !first.GeneratedAny {
		t.Fatal("expected GeneratedAny=true on first boot")
	}
	if len(first.MasterKey) != crypto.KeySize {
		t.Fatalf("master key len = %d, want %d", len(first.MasterKey), crypto.KeySize)
	}

	second, err := LoadOrInit(dir)
	if err != nil {
		t.Fatalf("second LoadOrInit: %v", err)
	}
	if second.GeneratedAny {
		t.Fatal("expected GeneratedAny=false on reuse — keys must not regenerate")
	}
	if Fingerprint(first.MasterKey) != Fingerprint(second.MasterKey) {
		t.Fatal("master key changed across loads — regeneration bug")
	}
}

func TestGeneratedSecretsAre0600(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrInit(dir); err != nil {
		t.Fatalf("LoadOrInit: %v", err)
	}
	for _, name := range []string{masterKeyFile, sessionSecretFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != secretPerm {
			t.Fatalf("%s perms = %o, want %o", name, perm, secretPerm)
		}
	}
}

func TestFailsLoudOnMalformedMasterKey(t *testing.T) {
	dir := t.TempDir()
	// A present-but-garbage master key must never be silently replaced.
	if err := os.WriteFile(filepath.Join(dir, masterKeyFile), []byte("not-valid-base64!!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrInit(dir); err == nil {
		t.Fatal("expected LoadOrInit to fail on malformed master key, got nil")
	}
}

func TestFailsLoudOnWrongLengthMasterKey(t *testing.T) {
	dir := t.TempDir()
	// Valid base64 but only 16 bytes — wrong for AES-256; must fail, not regen.
	if err := os.WriteFile(filepath.Join(dir, masterKeyFile), []byte("AAAAAAAAAAAAAAAAAAAAAA=="), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrInit(dir); err == nil {
		t.Fatal("expected LoadOrInit to fail on wrong-length master key, got nil")
	}
}

// --- S10.1 externalization reds ---

// An external MASTER key via env VALUE is used verbatim, and the volume is NOT
// written for it (a fully-external master needs no writable master.key file).
func TestExternalMasterKeyFromEnvValueUsedNotWritten(t *testing.T) {
	dir := t.TempDir()
	key := b64key(t, crypto.KeySize)
	decoded, _ := base64.StdEncoding.DecodeString(key)

	s, err := LoadOrInitExt(dir, ExternalSecrets{Master: ExternalSource{Value: key}})
	if err != nil {
		t.Fatalf("LoadOrInitExt: %v", err)
	}
	if Fingerprint(s.MasterKey) != Fingerprint(decoded) {
		t.Fatal("external master key not used verbatim")
	}
	if _, err := os.Stat(filepath.Join(dir, masterKeyFile)); !os.IsNotExist(err) {
		t.Fatal("master.key was written to the volume despite an external source — must not touch the volume")
	}
	// Session had no external source, so its volume file IS present.
	if _, err := os.Stat(filepath.Join(dir, sessionSecretFile)); err != nil {
		t.Fatalf("session volume file expected (no external session source): %v", err)
	}
}

// An external MASTER key via a mounted FILE is used verbatim. File is the preferred shape.
func TestExternalMasterKeyFromFileUsed(t *testing.T) {
	dir := t.TempDir()
	key := b64key(t, crypto.KeySize)
	decoded, _ := base64.StdEncoding.DecodeString(key)
	keyPath := filepath.Join(t.TempDir(), "master")
	if err := os.WriteFile(keyPath, []byte(key+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	s, err := LoadOrInitExt(dir, ExternalSecrets{Master: ExternalSource{File: keyPath}})
	if err != nil {
		t.Fatalf("LoadOrInitExt: %v", err)
	}
	if Fingerprint(s.MasterKey) != Fingerprint(decoded) {
		t.Fatal("external master key file not used verbatim")
	}
}

// File PREFERRED over env value when both are set.
func TestExternalMasterKeyFilePreferredOverValue(t *testing.T) {
	dir := t.TempDir()
	fileKey := b64key(t, crypto.KeySize)
	fileDecoded, _ := base64.StdEncoding.DecodeString(fileKey)
	keyPath := filepath.Join(t.TempDir(), "master")
	if err := os.WriteFile(keyPath, []byte(fileKey), 0o400); err != nil {
		t.Fatal(err)
	}
	s, err := LoadOrInitExt(dir, ExternalSecrets{Master: ExternalSource{File: keyPath, Value: b64key(t, crypto.KeySize)}})
	if err != nil {
		t.Fatalf("LoadOrInitExt: %v", err)
	}
	if Fingerprint(s.MasterKey) != Fingerprint(fileDecoded) {
		t.Fatal("file source must win over env value")
	}
}

// A set-but-unreadable external source is FATAL — never a fall-through to the
// volume (a different key would orphan all sealed data).
func TestExternalMasterKeyMissingFileIsFatal(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadOrInitExt(dir, ExternalSecrets{Master: ExternalSource{File: filepath.Join(dir, "does-not-exist")}})
	if err == nil {
		t.Fatal("expected a fatal error when the external master file is set but unreadable, got nil")
	}
	// The volume must not have been silently populated.
	if _, statErr := os.Stat(filepath.Join(dir, masterKeyFile)); !os.IsNotExist(statErr) {
		t.Fatal("volume master.key was created despite a fatal external source — no fall-through allowed")
	}
}

// A malformed external key fails loudly (base64 and length).
func TestExternalMasterKeyMalformedIsFatal(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrInitExt(dir, ExternalSecrets{Master: ExternalSource{Value: "not-base64!!!"}}); err == nil {
		t.Fatal("expected malformed external base64 to fail")
	}
	if _, err := LoadOrInitExt(dir, ExternalSecrets{Master: ExternalSource{Value: "AAAAAAAAAAAAAAAAAAAAAA=="}}); err == nil {
		t.Fatal("expected wrong-length external key to fail")
	}
}

// A fully-external deployment (both master + session provided) never touches the
// volume — a read-only / absent secrets dir must be fine.
func TestFullyExternalTouchesNoVolume(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nonexistent-secrets-dir")
	ext := ExternalSecrets{
		Master:  ExternalSource{Value: b64key(t, crypto.KeySize)},
		Session: ExternalSource{Value: b64key(t, 32)},
	}
	if _, err := LoadOrInitExt(dir, ext); err != nil {
		t.Fatalf("fully-external LoadOrInitExt should not need the volume: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("secrets dir was created despite both secrets being external")
	}
}

func TestGeneratedMasterKeyWorksWithSealer(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadOrInit(dir)
	if err != nil {
		t.Fatalf("LoadOrInit: %v", err)
	}
	sealer, err := crypto.NewSealer(s.MasterKey)
	if err != nil {
		t.Fatalf("NewSealer with bootstrapped key: %v", err)
	}
	if err := crypto.SelfTest(sealer); err != nil {
		t.Fatalf("SelfTest: %v", err)
	}
}
