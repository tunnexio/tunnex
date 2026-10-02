package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

func TestDetachedSigningUsesSeparateSchemaAndAuthenticatesAssets(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Repeat("a", 40)
	m := release.BootstrapVerifierManifest{SchemaVersion: 1, Purpose: release.BootstrapVerifierPurpose, Version: "v1.2.3", SourceSHA: source, BootstrapVerifierAssets: release.BootstrapVerifierAssets{LinuxAMD64: release.RuntimeAsset{Name: "releaseverify-linux-amd64", SHA256: strings.Repeat("b", 64), SourceSHA: source}, LinuxARM64: release.RuntimeAsset{Name: "releaseverify-linux-arm64", SHA256: strings.Repeat("c", 64), SourceSHA: source}}}
	b, _ := json.Marshal(m)
	signed, err := signInput(b, key, "fixture", true)
	if err != nil {
		t.Fatal(err)
	}
	expected := release.BootstrapRelease{SourceSHA: source, Runtime: release.ManagedAgentRuntime{Version: m.Version}, VerifierKeyID: "fixture", VerifierPublicKey: base64.RawURLEncoding.EncodeToString(pub)}
	if _, err := release.ParseBootstrapVerifier(signed, expected); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{[]byte(`{}`), append(append([]byte{}, b...), []byte(" {}")...), []byte(strings.Replace(string(b), `"purpose":`, `"unknown":true,"purpose":`, 1))} {
		if _, err := signInput(invalid, key, "fixture", true); err == nil {
			t.Fatal("signed invalid descriptor")
		}
	}
	// Legacy mode still emits exactly the original release envelope, never a
	// verifier member that old canonical-signature readers would reject.
	legacy, err := signInput([]byte(`{"schema_version":1,"version":"v1.2.3"}`), key, "fixture", false)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(legacy, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope) != 3 || envelope["manifest"] == nil || envelope["verifier"] != nil {
		t.Fatal("changed old signed envelope")
	}
	if strings.Contains(string(envelope["manifest"]), "bootstrap_verifier") {
		t.Fatal("changed old release schema")
	}
}
