package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

func TestPublicationVerificationRejectsMissingOrAlteredDownloadedExecutables(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := strings.Repeat("a", 40)
	assets := make([]release.RuntimeAsset, 0, 2)
	for _, arch := range []string{"amd64", "arm64"} {
		name := "releaseverify-linux-" + arch
		body := []byte("fixture " + arch)
		sum := sha256.Sum256(body)
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
		assets = append(assets, release.RuntimeAsset{Name: name, SHA256: hex.EncodeToString(sum[:]), SourceSHA: source})
	}
	m := release.BootstrapVerifierManifest{SchemaVersion: 1, Purpose: release.BootstrapVerifierPurpose, Version: "v1.2.3", SourceSHA: source, BootstrapVerifierAssets: release.BootstrapVerifierAssets{LinuxAMD64: assets[0], LinuxARM64: assets[1]}}
	signed, err := release.SignBootstrapVerifier(m, key, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(signed)
	path := filepath.Join(dir, "descriptor.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	// Main verifies the release envelope before calling this artifact checker.
	manifest := release.SignedManifest{KeyID: "fixture", Manifest: release.Manifest{Version: m.Version, SourceSHA: source, ManagedAgentRuntime: release.ManagedAgentRuntime{Version: m.Version}}}
	encoded := base64.RawURLEncoding.EncodeToString(pub)
	if err := verifyBootstrapAssets(manifest, encoded, path, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, assets[0].Name), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBootstrapAssets(manifest, encoded, path, dir); err == nil {
		t.Fatal("accepted changed executable")
	}
	if err := os.Remove(filepath.Join(dir, assets[1].Name)); err != nil {
		t.Fatal(err)
	}
	if err := verifyBootstrapAssets(manifest, encoded, path, dir); err == nil {
		t.Fatal("accepted missing architecture")
	}
	if err := verifyBootstrapAssets(manifest, encoded, path, ""); err != nil {
		t.Fatal("descriptor-only verification failed", err)
	}
}
