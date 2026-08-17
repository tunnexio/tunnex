package release

import (
	"fmt"
	"net/url"
	"strings"
)

// BootstrapRelease is the non-secret, server-owned release projection needed
// by the managed-agent installer. It is built only from a manifest that has
// already passed Parse/Verify; the signing key itself is never projected.
type BootstrapRelease struct {
	Tag           string
	SourceSHA     string
	ManifestURL   string
	VerifierKeyID string
	Runtime       ManagedAgentRuntime
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

func BootstrapReleaseFromSigned(s SignedManifest, configuredManifestURL ...string) (BootstrapRelease, error) {
	tag, err := ImmutableReleaseTag(s.Manifest.Version, s.Manifest.SourceSHA)
	if err != nil {
		return BootstrapRelease{}, err
	}
	manifestURL := "https://github.com/tunnexio/tunnex/releases/download/" + tag + "/release.json"
	if len(configuredManifestURL) > 0 && strings.TrimSpace(configuredManifestURL[0]) != "" {
		manifestURL = strings.TrimSpace(configuredManifestURL[0])
		u, parseErr := url.Parse(manifestURL)
		if parseErr != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Path, "/"+tag+"/release.json") {
			return BootstrapRelease{}, fmt.Errorf("configured release manifest URL is not immutable for tag %s", tag)
		}
	}
	return BootstrapRelease{
		Tag:           tag,
		SourceSHA:     s.Manifest.SourceSHA,
		ManifestURL:   manifestURL,
		VerifierKeyID: s.KeyID,
		Runtime:       s.Manifest.ManagedAgentRuntime,
	}, nil
}
