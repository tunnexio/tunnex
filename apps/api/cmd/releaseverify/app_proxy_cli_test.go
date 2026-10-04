package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

// Exercise the actual command with ephemeral test trust, never a release signing key.
func TestAppProxyOptInCommand(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "releaseverify")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build verifier: %v %s", err, out)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Repeat("a", 40)
	m := release.Manifest{SchemaVersion: 1, Sequence: 1, Version: "v0.1.1", SourceSHA: source, Images: map[string]release.Images{}}
	for _, name := range []string{"api", "web", "nginx", "node-agent", "migrate", "app-proxy"} {
		m.Images[name] = release.Images{AMD64Digest: "sha256:" + strings.Repeat("1", 64), ARM64Digest: "sha256:" + strings.Repeat("2", 64)}
	}
	m.ManagedAgentRuntime = release.ManagedAgentRuntime{Binary: "tunnex-agent-runtime", Version: m.Version,
		Unit:       release.RuntimeAsset{Name: "tunnex-agent-runtime.service", SHA256: strings.Repeat("3", 64), SourceSHA: source},
		LinuxAMD64: release.RuntimeAsset{Name: "tunnex-agent-runtime-linux-amd64", SHA256: strings.Repeat("4", 64), SourceSHA: source},
		LinuxARM64: release.RuntimeAsset{Name: "tunnex-agent-runtime-linux-arm64", SHA256: strings.Repeat("5", 64), SourceSHA: source}}
	manifestPath := filepath.Join(dir, "release.json")
	write := func(sign bool) {
		t.Helper()
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		signer := private
		if !sign {
			_, signer, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
		}
		data, err := json.Marshal(release.SignedManifest{Manifest: m, KeyID: "ephemeral-local-test", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, raw))})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(platform string, require bool, extra ...string) ([]byte, error) {
		args := []string{"-manifest", manifestPath, "-public-key", base64.RawURLEncoding.EncodeToString(pub), "-platform", platform, "-print-env"}
		if require {
			args = append(args, "-require-app-proxy")
		}
		args = append(args, extra...)
		return exec.Command(binary, args...).CombinedOutput()
	}
	write(true)
	for _, arch := range []string{"amd64", "arm64"} {
		out, err := run(arch, true)
		if err != nil {
			t.Fatalf("valid %s rejected: %v %s", arch, err, out)
		}
		digit := "1"
		if arch == "arm64" {
			digit = "2"
		}
		expected := "TUNNEX_APP_PROXY_IMAGE=ghcr.io/tunnexio/tunnex-app-proxy@sha256:" + strings.Repeat(digit, 64) + "\n"
		if !strings.Contains(string(out), expected) {
			t.Fatalf("wrong immutable %s pin: %s", arch, out)
		}
	}
	for _, extra := range [][]string{{"-expected-source-sha", strings.Repeat("b", 40)}, {"-expected-key-id", "wrong-key"}} {
		if out, err := run("arm64", true, extra...); err == nil || strings.Contains(string(out), "TUNNEX_API_IMAGE=") {
			t.Fatalf("mismatched installation exported pins: %v %s", err, out)
		}
	}
	if out, err := run("unsupported", true); err == nil || strings.Contains(string(out), "TUNNEX_API_IMAGE=") {
		t.Fatalf("unsupported platform exported pins: %v %s", err, out)
	}
	write(false)
	if out, err := run("arm64", true); err == nil || strings.Contains(string(out), "TUNNEX_APP_PROXY_IMAGE=") {
		t.Fatalf("untrusted signature exported pin: %v %s", err, out)
	}
	delete(m.Images, "app-proxy")
	write(true)
	if out, err := run("arm64", true); err == nil || strings.Contains(string(out), "TUNNEX_API_IMAGE=") {
		t.Fatalf("missing opt-in image exported pins: %v %s", err, out)
	}
	if out, err := run("arm64", false); err != nil || strings.Contains(string(out), "TUNNEX_APP_PROXY_IMAGE=") {
		t.Fatalf("legacy release compatibility: %v %s", err, out)
	}
	m.Images["app-proxy"] = release.Images{AMD64Digest: "sha256:" + strings.Repeat("1", 64)}
	write(true)
	if out, err := run("arm64", true); err == nil || strings.Contains(string(out), "TUNNEX_API_IMAGE=") {
		t.Fatalf("incomplete architecture exported pins: %v %s", err, out)
	}
}
