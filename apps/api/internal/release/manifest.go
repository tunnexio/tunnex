// Package release verifies the signed release descriptor used by the control-plane
// upgrade center. The descriptor is deliberately separate from the image tag: it
// binds operator-facing notes and compatibility facts to immutable image digests.
package release

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const SchemaVersion = 1

// DefaultCatalogURL is the signed online discovery pointer published only after
// a fully successful main CI image set. Its contents remain untrusted until
// Verify succeeds with the deployment's pinned public key.
const DefaultCatalogURL = "https://github.com/tunnexio/tunnex/releases/download/tunnex-updates/release.json"

type Manifest struct {
	SchemaVersion   int               `json:"schema_version"`
	Sequence        int64             `json:"sequence"`
	Version         string            `json:"version"`
	SourceSHA       string            `json:"source_sha"`
	PublishedAt     time.Time         `json:"published_at"`
	MinProtocol     int               `json:"min_protocol"`
	Compatibility   string            `json:"compatibility"`
	Downtime        string            `json:"downtime"`
	ReleaseNotesURL string            `json:"release_notes_url"`
	Images          map[string]Images `json:"images"`
}

type Images struct {
	AMD64Digest string `json:"linux_amd64_digest"`
	ARM64Digest string `json:"linux_arm64_digest"`
}

type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"`
	KeyID     string   `json:"kid"`
}

type Current struct {
	Sequence  int64
	Version   string
	SourceSHA string
	Protocol  int
}

type Status struct {
	Available        bool
	Verified         bool
	CurrentVersion   string
	CurrentSourceSHA string
	Version          string
	SourceSHA        string
	Sequence         int64
	Compatibility    string
	Downtime         string
	ReleaseNotesURL  string
	Reason           string
	State            string
	PreflightState   string
	BackupState      string
	RollbackState    string
	ApprovalMode     string
}

func Verify(s SignedManifest, publicKey ed25519.PublicKey) error {
	if s.Manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported release manifest schema %d", s.Manifest.SchemaVersion)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("release public key has invalid length")
	}
	if s.Manifest.Sequence <= 0 || s.Manifest.Version == "" || len(s.Manifest.SourceSHA) != 40 {
		return errors.New("release manifest has invalid identity")
	}
	if _, err := hex.DecodeString(s.Manifest.SourceSHA); err != nil {
		return errors.New("release source_sha is not hexadecimal")
	}
	for _, name := range []string{"api", "web", "nginx", "node-agent", "migrate"} {
		image, ok := s.Manifest.Images[name]
		if !ok || !validDigest(image.AMD64Digest) || !validDigest(image.ARM64Digest) {
			return fmt.Errorf("release manifest image %q is missing a valid amd64/arm64 digest", name)
		}
	}
	canonical, err := json.Marshal(s.Manifest)
	if err != nil {
		return fmt.Errorf("marshal release manifest: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, sig) {
		return errors.New("release manifest signature is invalid")
	}
	return nil
}

func validDigest(v string) bool {
	return strings.HasPrefix(v, "sha256:") && len(v) == len("sha256:")+64
}

func Load(path, encodedPublicKey string) (SignedManifest, error) {
	var s SignedManifest
	b, err := os.ReadFile(path)
	if err != nil {
		return s, fmt.Errorf("read release manifest: %w", err)
	}
	return Parse(b, encodedPublicKey)
}

// Parse validates a descriptor received from either local disk or the online
// catalog. The signature check is deliberately identical for both paths.
func Parse(b []byte, encodedPublicKey string) (SignedManifest, error) {
	var s SignedManifest
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("decode release manifest: %w", err)
	}
	key, err := decodeKey(encodedPublicKey)
	if err != nil {
		return s, err
	}
	if err := Verify(s, key); err != nil {
		return s, err
	}
	return s, nil
}

// Checker keeps the last verified update status. A catalog transport error never
// fabricates an update or replaces an already verified local status.
type Checker struct {
	current Current
	key     string
	url     string
	client  *http.Client

	mu     sync.RWMutex
	status *Status
}

func NewChecker(current Current, key, url string, initial *Status) *Checker {
	return &Checker{current: current, key: key, url: url, status: cloneStatus(initial), client: &http.Client{Timeout: 5 * time.Second}}
}

func (c *Checker) Status() *Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneStatus(c.status)
}

// Refresh obtains one catalog descriptor. It accepts only a bounded, signed,
// structurally valid body and leaves the last known state unchanged on failure.
func (c *Checker) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("build release catalog request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch release catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("release catalog returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read release catalog: %w", err)
	}
	signed, err := Parse(body, c.key)
	if err != nil {
		return fmt.Errorf("verify release catalog: %w", err)
	}
	status := Compare(c.current, signed.Manifest)
	c.mu.Lock()
	c.status = &status
	c.mu.Unlock()
	return nil
}

func cloneStatus(in *Status) *Status {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func Compare(current Current, next Manifest) Status {
	status := Status{Verified: true, CurrentVersion: current.Version, CurrentSourceSHA: current.SourceSHA,
		Version: next.Version, SourceSHA: next.SourceSHA, Sequence: next.Sequence, Compatibility: next.Compatibility,
		Downtime: next.Downtime, ReleaseNotesURL: next.ReleaseNotesURL, State: "available",
		PreflightState: "required", BackupState: "required", RollbackState: "restore_from_backup",
		ApprovalMode: "host_command_only"}
	switch {
	case next.Sequence <= current.Sequence:
		status.Reason = "no newer release is available"
	case next.MinProtocol > current.Protocol:
		status.Reason = fmt.Sprintf("release requires protocol %d; this control plane supports %d", next.MinProtocol, current.Protocol)
	case current.SourceSHA == next.SourceSHA:
		status.Reason = "the installed source commit already matches this release"
	default:
		status.Available = true
	}
	return status
}

func decodeKey(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("release public key is not configured")
	}
	for _, enc := range []func(string) ([]byte, error){hex.DecodeString, base64.RawURLEncoding.DecodeString} {
		if b, err := enc(raw); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, errors.New("release public key is not valid hex or base64url")
}
