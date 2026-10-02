package release

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const BootstrapVerifierDescriptorName = "agent-bootstrap-verifier.json"
const BootstrapVerifierPurpose = "tunnex-agent-bootstrap-verifier"
const bootstrapVerifierMaxBytes = 16 << 10

// BootstrapVerifierAssets is a public projection, never executable bytes or a key.
type BootstrapVerifierAssets struct {
	LinuxAMD64 RuntimeAsset `json:"linux_amd64"`
	LinuxARM64 RuntimeAsset `json:"linux_arm64"`
}

// BootstrapVerifierManifest is deliberately detached from Manifest. Extending
// release.json would break existing strict decoders and their canonical signatures.
type BootstrapVerifierManifest struct {
	SchemaVersion int    `json:"schema_version"`
	Purpose       string `json:"purpose"`
	Version       string `json:"version"`
	SourceSHA     string `json:"source_sha"`
	BootstrapVerifierAssets
}

type SignedBootstrapVerifier struct {
	Verifier  BootstrapVerifierManifest `json:"verifier"`
	Signature string                    `json:"signature"`
	KeyID     string                    `json:"kid"`
}

func ValidateBootstrapVerifier(m BootstrapVerifierManifest) error {
	if m.SchemaVersion != 1 || m.Purpose != BootstrapVerifierPurpose || m.Version == "" || len(m.SourceSHA) != 40 {
		return errors.New("invalid bootstrap verifier identity")
	}
	if _, err := hex.DecodeString(m.SourceSHA); err != nil || strings.ToLower(m.SourceSHA) != m.SourceSHA {
		return errors.New("invalid bootstrap verifier source")
	}
	for arch, asset := range map[string]RuntimeAsset{"amd64": m.LinuxAMD64, "arm64": m.LinuxARM64} {
		if err := verifyRuntimeAsset("verifier-"+arch, asset, "releaseverify-linux-"+arch, m.SourceSHA); err != nil {
			return err
		}
	}
	return nil
}

// SignBootstrapVerifier is shared by CI and verification fixtures. Its signature
// authenticates the descriptor's distinct purpose as well as both executables.
func SignBootstrapVerifier(m BootstrapVerifierManifest, key ed25519.PrivateKey, kid string) (SignedBootstrapVerifier, error) {
	if err := ValidateBootstrapVerifier(m); err != nil {
		return SignedBootstrapVerifier{}, err
	}
	if len(key) != ed25519.PrivateKeySize || strings.TrimSpace(kid) == "" {
		return SignedBootstrapVerifier{}, errors.New("invalid bootstrap verifier signing identity")
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return SignedBootstrapVerifier{}, err
	}
	return SignedBootstrapVerifier{Verifier: m, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical)), KeyID: kid}, nil
}

func ParseBootstrapVerifier(b []byte, expected BootstrapRelease) (*BootstrapVerifierAssets, error) {
	if len(b) > bootstrapVerifierMaxBytes {
		return nil, errors.New("bootstrap verifier descriptor exceeds size limit")
	}
	var signed SignedBootstrapVerifier
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&signed); err != nil {
		return nil, fmt.Errorf("decode bootstrap verifier: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing bootstrap verifier data")
	}
	m := signed.Verifier
	if err := ValidateBootstrapVerifier(m); err != nil {
		return nil, err
	}
	if m.SourceSHA != expected.SourceSHA || m.Version != expected.Runtime.Version || signed.KeyID == "" || signed.KeyID != expected.VerifierKeyID {
		return nil, errors.New("bootstrap verifier does not match installed release")
	}
	key, err := decodeKey(expected.VerifierPublicKey)
	if err != nil {
		return nil, errors.New("invalid bootstrap verifier public key")
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, canonical, sig) {
		return nil, errors.New("invalid bootstrap verifier signature")
	}
	assets := m.BootstrapVerifierAssets
	return &assets, nil
}

// FetchBootstrapVerifier runs before token issuance, not during CP startup.
// Only a genuine 404 means a legacy release. Every other failure is actionable
// and cannot be converted into an unsigned or guessed executable descriptor.
func FetchBootstrapVerifier(ctx context.Context, expected BootstrapRelease) (*BootstrapVerifierAssets, error) {
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: bootstrapVerifierRedirect}
	return fetchBootstrapVerifier(ctx, expected, client)
}

func bootstrapVerifierRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
		return errors.New("unsafe bootstrap verifier redirect")
	}
	origin := via[0].URL
	sameHost := req.URL.Host == origin.Host
	githubAsset := origin.Host == "github.com" && req.URL.Host == "release-assets.githubusercontent.com"
	if !sameHost && !githubAsset {
		return errors.New("bootstrap verifier redirect host refused")
	}
	return nil
}

func fetchBootstrapVerifier(ctx context.Context, expected BootstrapRelease, client *http.Client) (*BootstrapVerifierAssets, error) {
	tag, err := ImmutableReleaseTag(expected.Runtime.Version, expected.SourceSHA)
	if err != nil || tag != expected.Tag {
		return nil, errors.New("bootstrap verifier requires the installed release tag")
	}
	u, err := url.Parse(expected.ManifestURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Path, "/"+expected.Tag+"/release.json") {
		return nil, errors.New("bootstrap verifier requires immutable HTTPS release URL")
	}
	u.Path = strings.TrimSuffix(u.Path, "release.json") + BootstrapVerifierDescriptorName
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch bootstrap verifier: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bootstrap verifier returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, bootstrapVerifierMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read bootstrap verifier: %w", err)
	}
	return ParseBootstrapVerifier(b, expected)
}
