package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signedFixture(t *testing.T) (SignedManifest, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceSHA := strings.Repeat("a", 40)
	m := Manifest{SchemaVersion: SchemaVersion, Sequence: 7, Version: "v0.4.0", SourceSHA: sourceSHA,
		PublishedAt: time.Unix(1_700_000_000, 0).UTC(), MinProtocol: 3, Compatibility: "N and N-1 agents",
		Downtime: "rolling; brief API restart", ReleaseNotesURL: "https://tunnex.io/releases/0.4.0",
		Images: map[string]Images{}}
	for _, name := range []string{"api", "web", "nginx", "node-agent", "migrate"} {
		m.Images[name] = Images{AMD64Digest: "sha256:" + strings.Repeat("1", 64), ARM64Digest: "sha256:" + strings.Repeat("2", 64)}
	}
	m.ManagedAgentRuntime = ManagedAgentRuntime{Binary: "tunnex-agent-runtime", Version: m.Version,
		Unit:       RuntimeAsset{Name: "tunnex-agent-runtime.service", SHA256: strings.Repeat("5", 64), SourceSHA: sourceSHA},
		LinuxAMD64: RuntimeAsset{Name: "tunnex-agent-runtime-linux-amd64", SHA256: strings.Repeat("3", 64), SourceSHA: sourceSHA},
		LinuxARM64: RuntimeAsset{Name: "tunnex-agent-runtime-linux-arm64", SHA256: strings.Repeat("4", 64), SourceSHA: sourceSHA}}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return SignedManifest{Manifest: m, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, b)), KeyID: "release-2026-01"}, pub
}

func TestVerifyAcceptsSignedImmutableManifest(t *testing.T) {
	s, pub := signedFixture(t)
	if err := Verify(s, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperingAndMissingArchitecture(t *testing.T) {
	s, pub := signedFixture(t)
	s.Manifest.Version = "0.4.1"
	if err := Verify(s, pub); err == nil {
		t.Fatal("tampered version must invalidate signature")
	}
	s, pub = signedFixture(t)
	delete(s.Manifest.Images, "web")
	if err := Verify(s, pub); err == nil || !strings.Contains(err.Error(), `image "web"`) {
		t.Fatalf("missing image must fail closed, got %v", err)
	}
}

func TestVerifyRejectsIncompleteManagedAgentRuntime(t *testing.T) {
	s, pub := signedFixture(t)
	s.Manifest.ManagedAgentRuntime.LinuxARM64.SHA256 = ""
	if err := Verify(s, pub); err == nil || !strings.Contains(err.Error(), "runtime asset") {
		t.Fatalf("missing runtime architecture must fail closed, got %v", err)
	}
	s, pub = signedFixture(t)
	s.Manifest.ManagedAgentRuntime.LinuxAMD64.SHA256 = strings.ToUpper(strings.Repeat("a", 64))
	if err := Verify(s, pub); err == nil || !strings.Contains(err.Error(), "invalid SHA-256") {
		t.Fatalf("uppercase runtime digest must fail closed, got %v", err)
	}
	s, pub = signedFixture(t)
	s.Manifest.ManagedAgentRuntime.LinuxAMD64.SourceSHA = strings.Repeat("b", 40)
	if err := Verify(s, pub); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("wrong runtime source must fail closed, got %v", err)
	}
	s, pub = signedFixture(t)
	s.Manifest.ManagedAgentRuntime.Unit.SHA256 = ""
	if err := Verify(s, pub); err == nil || !strings.Contains(err.Error(), `runtime asset "unit"`) {
		t.Fatalf("missing signed service unit must fail closed, got %v", err)
	}
	s, pub = signedFixture(t)
	s.Manifest.ManagedAgentRuntime.Unit.Name = "unsigned.service"
	if err := Verify(s, pub); err == nil || !strings.Contains(err.Error(), `runtime asset "unit"`) {
		t.Fatalf("wrong service unit name must fail closed, got %v", err)
	}
}

func TestParseRejectsUnknownManagedAgentRuntimeArchitecture(t *testing.T) {
	signed, pub := signedFixture(t)
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	manifest := document["manifest"].(map[string]any)
	runtime := manifest["managed_agent_runtime"].(map[string]any)
	runtime["linux_s390x"] = map[string]any{"name": "unexpected"}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(raw, hexKey(pub)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown runtime architecture must fail closed, got %v", err)
	}
}

func TestCompareRefusesDowngradeAndIncompatibleRelease(t *testing.T) {
	s, _ := signedFixture(t)
	current := Current{Sequence: 7, Version: "0.4.0", SourceSHA: strings.Repeat("b", 40), Protocol: 3}
	if got := Compare(current, s.Manifest); got.Available || got.Reason != "no newer release is available" {
		t.Fatalf("same sequence must not be offered: %+v", got)
	}
	s.Manifest.Sequence = 8
	s.Manifest.MinProtocol = 4
	if got := Compare(current, s.Manifest); got.Available || !strings.Contains(got.Reason, "requires protocol 4") {
		t.Fatalf("incompatible release must be refused: %+v", got)
	}
	s.Manifest.MinProtocol = 3
	if got := Compare(current, s.Manifest); !got.Available || got.Reason != "" {
		t.Fatalf("new compatible release should be available: %+v", got)
	}
}

func TestCheckerAcceptsOnlySignedCatalogAndKeepsLastVerifiedStatus(t *testing.T) {
	signed, pub := signedFixture(t)
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	good := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if good {
			_, _ = w.Write(body)
			return
		}
		_, _ = w.Write([]byte(`{"manifest":{"version":"forged"}}`))
	}))
	defer server.Close()
	checker := NewChecker(Current{Sequence: 6, SourceSHA: strings.Repeat("b", 40), Protocol: 3}, hexKey(pub), server.URL, nil)
	if err := checker.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh signed catalog: %v", err)
	}
	if got := checker.Status(); got == nil || !got.Available || !got.Verified || got.Sequence != 7 {
		t.Fatalf("verified catalog status = %+v", got)
	}
	good = false
	if err := checker.Refresh(t.Context()); err == nil {
		t.Fatal("forged catalog must fail")
	}
	if got := checker.Status(); got == nil || got.Sequence != 7 || !got.Verified {
		t.Fatalf("failed refresh replaced last verified status: %+v", got)
	}
}

func hexKey(key ed25519.PublicKey) string { return fmt.Sprintf("%x", key) }
