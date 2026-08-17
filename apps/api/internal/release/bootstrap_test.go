package release

import (
	"strings"
	"testing"
)

func TestImmutableReleaseTagUsesPublishedDeploymentConvention(t *testing.T) {
	sha := strings.Repeat("a", 40)
	if got, err := ImmutableReleaseTag("v0.4.0", sha); err != nil || got != "v0.4.0" {
		t.Fatalf("tagged release = %q, %v", got, err)
	}
	if got, err := ImmutableReleaseTag("sha-aaaaaaa", sha); err != nil || got != "tunnex-build-"+sha {
		t.Fatalf("SHA release = %q, %v", got, err)
	}
	if _, err := ImmutableReleaseTag("dev", sha); err == nil {
		t.Fatal("unpublished version must not become a release tag")
	}
}

func TestBootstrapReleaseProjectionContainsNoVerifierKeyMaterial(t *testing.T) {
	signed, _ := signedFixture(t)
	got, err := BootstrapReleaseFromSigned(signed)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tag != signed.Manifest.Version || got.SourceSHA != signed.Manifest.SourceSHA || got.VerifierKeyID != signed.KeyID {
		t.Fatalf("projection lost signed provenance: %+v", got)
	}
	if strings.Contains(got.ManifestURL, "latest") || strings.Contains(got.ManifestURL, "catalog") {
		t.Fatalf("projection used mutable URL: %q", got.ManifestURL)
	}
}

func TestBootstrapReleaseProjectionAcceptsOnlyConfiguredImmutableURL(t *testing.T) {
	signed, _ := signedFixture(t)
	got, err := BootstrapReleaseFromSigned(signed, "https://mirror.example/releases/v0.4.0/release.json")
	if err != nil || got.ManifestURL != "https://mirror.example/releases/v0.4.0/release.json" {
		t.Fatalf("configured immutable URL = %q, %v", got.ManifestURL, err)
	}
	if _, err := BootstrapReleaseFromSigned(signed, "https://mirror.example/releases/latest/release.json"); err == nil {
		t.Fatal("mutable release URL must be refused")
	}
}
