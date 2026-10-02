package release

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func verifierFixture(t *testing.T) (SignedBootstrapVerifier, BootstrapRelease, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Repeat("a", 40)
	m := BootstrapVerifierManifest{SchemaVersion: 1, Purpose: BootstrapVerifierPurpose, Version: "v0.4.0", SourceSHA: source,
		BootstrapVerifierAssets: BootstrapVerifierAssets{
			LinuxAMD64: RuntimeAsset{Name: "releaseverify-linux-amd64", SHA256: strings.Repeat("1", 64), SourceSHA: source},
			LinuxARM64: RuntimeAsset{Name: "releaseverify-linux-arm64", SHA256: strings.Repeat("2", 64), SourceSHA: source}}}
	signed, err := SignBootstrapVerifier(m, key, "fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	return signed, BootstrapRelease{Tag: m.Version, SourceSHA: source, ManifestURL: "https://github.com/tunnexio/tunnex/releases/download/v0.4.0/release.json", Runtime: ManagedAgentRuntime{Version: m.Version}, VerifierKeyID: signed.KeyID, VerifierPublicKey: base64.RawURLEncoding.EncodeToString(pub)}, key
}

func verifierBytes(t *testing.T, s SignedBootstrapVerifier) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBootstrapVerifierAuthenticatesBothArchitecturesAndReleaseIdentity(t *testing.T) {
	signed, expected, key := verifierFixture(t)
	got, err := ParseBootstrapVerifier(verifierBytes(t, signed), expected)
	if err != nil || got == nil || *got != signed.Verifier.BootstrapVerifierAssets {
		t.Fatalf("verified projection: %v %v", got, err)
	}
	tests := map[string]func(*SignedBootstrapVerifier, *BootstrapRelease){
		"changed_digest": func(s *SignedBootstrapVerifier, e *BootstrapRelease) {
			s.Verifier.LinuxAMD64.SHA256 = strings.Repeat("3", 64)
		},
		"wrong_key": func(s *SignedBootstrapVerifier, e *BootstrapRelease) {
			e.VerifierPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
		"invalid_key":      func(s *SignedBootstrapVerifier, e *BootstrapRelease) { e.VerifierPublicKey = "invalid" },
		"wrong_key_id":     func(s *SignedBootstrapVerifier, e *BootstrapRelease) { s.KeyID = "another-key" },
		"missing_key_id":   func(s *SignedBootstrapVerifier, e *BootstrapRelease) { s.KeyID = "" },
		"wrong_source":     func(s *SignedBootstrapVerifier, e *BootstrapRelease) { e.SourceSHA = strings.Repeat("b", 40) },
		"wrong_version":    func(s *SignedBootstrapVerifier, e *BootstrapRelease) { e.Runtime.Version = "v0.4.1" },
		"missing_arm64":    func(s *SignedBootstrapVerifier, e *BootstrapRelease) { s.Verifier.LinuxARM64 = RuntimeAsset{} },
		"wrong_asset_name": func(s *SignedBootstrapVerifier, e *BootstrapRelease) { s.Verifier.LinuxAMD64.Name = "../other" },
		"asset_wrong_source": func(s *SignedBootstrapVerifier, e *BootstrapRelease) {
			s.Verifier.LinuxAMD64.SourceSHA = strings.Repeat("b", 40)
		},
		"invalid_digest": func(s *SignedBootstrapVerifier, e *BootstrapRelease) {
			s.Verifier.LinuxAMD64.SHA256 = strings.Repeat("z", 64)
		},
		"uppercase_digest": func(s *SignedBootstrapVerifier, e *BootstrapRelease) {
			s.Verifier.LinuxAMD64.SHA256 = strings.Repeat("A", 64)
		},
		"wrong_purpose":  func(s *SignedBootstrapVerifier, e *BootstrapRelease) { s.Verifier.Purpose = "release-manifest" },
		"unknown_schema": func(s *SignedBootstrapVerifier, e *BootstrapRelease) { s.Verifier.SchemaVersion = 2 },
		"bad_signature":  func(s *SignedBootstrapVerifier, e *BootstrapRelease) { s.Signature = "bogus" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			s, e := signed, expected
			mutate(&s, &e)
			if _, err := ParseBootstrapVerifier(verifierBytes(t, s), e); err == nil {
				t.Fatal("accepted invalid descriptor")
			}
		})
	}
	// Even a correctly signed descriptor for another release cannot be projected.
	signed.Verifier.Version = "v0.4.1"
	signed, err = SignBootstrapVerifier(signed.Verifier, key, signed.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseBootstrapVerifier(verifierBytes(t, signed), expected); err == nil {
		t.Fatal("accepted another signed version")
	}
}

func TestBootstrapVerifierStrictBoundedFormat(t *testing.T) {
	signed, expected, _ := verifierFixture(t)
	b := verifierBytes(t, signed)
	for name, body := range map[string][]byte{
		"trailing_json": append(append([]byte{}, b...), []byte(" {}")...),
		"trailing_text": append(append([]byte{}, b...), []byte(" bad")...),
		"unknown_field": []byte(strings.Replace(string(b), `"kid":`, `"unexpected":true,"kid":`, 1)),
		"too_large":     []byte(strings.Repeat(" ", bootstrapVerifierMaxBytes) + string(b)),
		"empty":         nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBootstrapVerifier(body, expected); err == nil {
				t.Fatal("accepted invalid body")
			}
		})
	}
	if _, err := SignBootstrapVerifier(signed.Verifier, nil, signed.KeyID); err == nil {
		t.Fatal("accepted missing signing key")
	}
	if _, err := SignBootstrapVerifier(signed.Verifier, ed25519.NewKeyFromSeed(make([]byte, 32)), ""); err == nil {
		t.Fatal("accepted missing key id")
	}
}

func TestFetchBootstrapVerifierOnly404AllowsLegacy(t *testing.T) {
	signed, expected, _ := verifierFixture(t)
	for _, status := range []int{200, 404, 401, 403, 429, 500, 503, 204} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/releases/v0.4.0/"+BootstrapVerifierDescriptorName {
					t.Errorf("unexpected descriptor request %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(status)
				_, _ = w.Write(verifierBytes(t, signed))
			}))
			defer server.Close()
			expected.ManifestURL = server.URL + "/releases/v0.4.0/release.json"
			got, err := fetchBootstrapVerifier(context.Background(), expected, server.Client())
			switch status {
			case 200:
				if err != nil || got == nil {
					t.Fatalf("valid descriptor: %v %v", got, err)
				}
			case 404:
				if err != nil || got != nil {
					t.Fatalf("legacy: %v %v", got, err)
				}
			default:
				if err == nil || got != nil {
					t.Fatalf("failure did not fail closed: %v %v", got, err)
				}
			}
		})
	}
}

func TestFetchBootstrapVerifierRejectsUnsafeURLsBodiesAndCancellation(t *testing.T) {
	_, expected, _ := verifierFixture(t)
	client := &http.Client{Timeout: time.Second}
	for _, address := range []string{"http://example.test/releases/v0.4.0/release.json", "https://user:pass@example.test/releases/v0.4.0/release.json", "https://example.test/releases/latest/release.json", "https://example.test/releases/v0.4.0/release.json?token=x", "https://example.test/releases/v0.4.0/release.json#fragment"} {
		expected.ManifestURL = address
		if _, err := fetchBootstrapVerifier(context.Background(), expected, client); err == nil {
			t.Fatalf("accepted URL %s", address)
		}
	}
	// A valid descriptor delivered incompletely is a transport error, never legacy.
	signed, _, _ := verifierFixture(t)
	partial := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10000")
		_, _ = w.Write(verifierBytes(t, signed))
	}))
	expected.ManifestURL = partial.URL + "/releases/v0.4.0/release.json"
	if _, err := fetchBootstrapVerifier(context.Background(), expected, partial.Client()); err == nil {
		t.Fatal("accepted truncated HTTP response")
	}
	partial.Close()
	for _, body := range []string{"not signed", strings.Repeat(" ", bootstrapVerifierMaxBytes+1)} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		expected.ManifestURL = server.URL + "/releases/v0.4.0/release.json"
		if _, err := fetchBootstrapVerifier(context.Background(), expected, server.Client()); err == nil {
			t.Fatal("accepted invalid remote body")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := fetchBootstrapVerifier(ctx, expected, server.Client()); err == nil {
			t.Fatal("ignored cancellation")
		}
		server.Close()
	}
}

func TestBootstrapVerifierRedirectPolicy(t *testing.T) {
	request := func(address string) *http.Request {
		u, err := url.Parse(address)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u}
	}
	origin := request("https://github.com/tunnexio/tunnex/releases/download/v0.4.0/agent-bootstrap-verifier.json")
	for _, address := range []string{"https://github.com/sibling", "https://release-assets.githubusercontent.com/asset?signature=public-download"} {
		if err := bootstrapVerifierRedirect(request(address), []*http.Request{origin}); err != nil {
			t.Fatal(err)
		}
	}
	for _, address := range []string{"http://github.com/sibling", "https://evil.test/asset", "https://user:pass@github.com/asset", "https://github.com:444/asset"} {
		if err := bootstrapVerifierRedirect(request(address), []*http.Request{origin}); err == nil {
			t.Fatalf("accepted redirect %s", address)
		}
	}
	if err := bootstrapVerifierRedirect(origin, nil); err == nil {
		t.Fatal("accepted missing origin")
	}
	if err := bootstrapVerifierRedirect(origin, []*http.Request{origin, origin, origin, origin, origin}); err == nil {
		t.Fatal("accepted redirect loop")
	}
	if err := bootstrapVerifierRedirect(request("https://release-assets.githubusercontent.com/asset"), []*http.Request{request("https://mirror.test/asset")}); err == nil {
		t.Fatal("mirror may not redirect to arbitrary provider")
	}
}
