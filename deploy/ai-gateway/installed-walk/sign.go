package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"time"
)

const SchemaVersion = 1

type Manifest struct {
	SchemaVersion       int                 `json:"schema_version"`
	Sequence            int64               `json:"sequence"`
	Version             string              `json:"version"`
	SourceSHA           string              `json:"source_sha"`
	PublishedAt         time.Time           `json:"published_at"`
	MinProtocol         int                 `json:"min_protocol"`
	Compatibility       string              `json:"compatibility"`
	Downtime            string              `json:"downtime"`
	ReleaseNotesURL     string              `json:"release_notes_url"`
	Images              map[string]Images   `json:"images"`
	ManagedAgentRuntime ManagedAgentRuntime `json:"managed_agent_runtime"`
}

type Images struct {
	AMD64Digest string `json:"linux_amd64_digest"`
	ARM64Digest string `json:"linux_arm64_digest"`
}

// ManagedAgentRuntime binds the managed-agent binaries and service unit to
// this signed release. Every asset is mandatory: an incomplete descriptor is
// not installable.
type ManagedAgentRuntime struct {
	Binary     string       `json:"binary"`
	Version    string       `json:"version"`
	Unit       RuntimeAsset `json:"unit"`
	LinuxAMD64 RuntimeAsset `json:"linux_amd64"`
	LinuxARM64 RuntimeAsset `json:"linux_arm64"`
}

type RuntimeAsset struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SourceSHA string `json:"source_sha"`
}

type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"`
	KeyID     string   `json:"kid"`
}

func main() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
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
	b, _ := json.Marshal(m)
	out, _ := json.Marshal(SignedManifest{Manifest: m, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, b)), KeyID: "local-ai-fixture-only"})
	os.WriteFile(os.Args[1]+"/release.json", out, 0600)
	os.WriteFile(os.Args[1]+"/release.pub", []byte(base64.RawURLEncoding.EncodeToString(pub)), 0600)
}
