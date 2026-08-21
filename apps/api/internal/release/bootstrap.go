package release

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// BootstrapRelease is the non-secret, server-owned release projection needed
// by the managed-agent installer. It is built only from a manifest that has
// already passed Parse/Verify. It includes the configured Ed25519 public
// verifier so a copied bootstrap command is self-contained; it never includes
// a signing key or credential.
type BootstrapRelease struct {
	Tag               string
	SourceSHA         string
	ManifestURL       string
	VerifierKeyID     string
	VerifierPublicKey string
	Runtime           ManagedAgentRuntime
}

// ImmutableReleaseTag is the publication convention used by deploy/install.sh
// and deploy/get.sh. It is deliberately narrow: arbitrary descriptor versions
// must not become download tags by accident.
func ImmutableReleaseTag(version, sourceSHA string) (string, error) {
	switch {
	case strings.HasPrefix(version, "v"):
		return version, nil
	case strings.HasPrefix(version, "sha-") && len(sourceSHA) == 40:
		return "tunnex-build-" + sourceSHA, nil
	default:
		return "", fmt.Errorf("release version has no immutable publication tag")
	}
}

func BootstrapReleaseFromSigned(s SignedManifest, configuredManifestURL, configuredPublicKey string) (BootstrapRelease, error) {
	tag, err := ImmutableReleaseTag(s.Manifest.Version, s.Manifest.SourceSHA)
	if err != nil {
		return BootstrapRelease{}, err
	}
	manifestURL := "https://github.com/tunnexio/tunnex/releases/download/" + tag + "/release.json"
	if strings.TrimSpace(configuredManifestURL) != "" {
		manifestURL = strings.TrimSpace(configuredManifestURL)
		u, parseErr := url.Parse(manifestURL)
		if parseErr != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Path, "/"+tag+"/release.json") {
			return BootstrapRelease{}, fmt.Errorf("configured release manifest URL is not immutable for tag %s", tag)
		}
	}
	publicKey, err := decodeKey(configuredPublicKey)
	if err != nil {
		return BootstrapRelease{}, fmt.Errorf("configured bootstrap verifier key: %w", err)
	}
	return BootstrapRelease{
		Tag:               tag,
		SourceSHA:         s.Manifest.SourceSHA,
		ManifestURL:       manifestURL,
		VerifierKeyID:     s.KeyID,
		VerifierPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		Runtime:           s.Manifest.ManagedAgentRuntime,
	}, nil
}
