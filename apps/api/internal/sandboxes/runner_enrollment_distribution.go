package sandboxes

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// RunnerDistribution is a public release manifest. It conveys byte pins and
// support boundaries, never native qualification, identity or network grants.
type RunnerDistribution struct {
	SchemaVersion              int                       `json:"schema_version"`
	SourceSHA                  string                    `json:"source_sha"`
	Repository                 string                    `json:"repository"`
	ReleaseTag                 string                    `json:"release_tag"`
	OS                         string                    `json:"os"`
	APIEditions                []string                  `json:"api_editions"`
	BootstrapScript            RunnerArtifact            `json:"bootstrap_script"`
	Bundles                    map[string]RunnerArtifact `json:"bundles"`
	InstallerArchitectures     []string                  `json:"installer_architectures"`
	NativeRuntimeQualification bool                      `json:"native_runtime_qualification"`
	WorkloadImagesBuilt        bool                      `json:"workload_images_built"`
	WorkloadImageDelivery      *RunnerArtifact           `json:"workload_image_delivery,omitempty"`
}

func uniqueRunnerJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			if err := uniqueRunnerJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for decoder.More() {
			if err := uniqueRunnerJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func ApplyRunnerDistribution(raw []byte, c RunnerEnrollmentConfig) (RunnerEnrollmentConfig, error) {
	if len(raw) > 32768 {
		return c, ErrInvalid
	}
	duplicateGuard := json.NewDecoder(bytes.NewReader(raw))
	if uniqueRunnerJSON(duplicateGuard) != nil {
		return c, ErrInvalid
	}
	if _, err := duplicateGuard.Token(); err != io.EOF {
		return c, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest RunnerDistribution
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.SchemaVersion != 1 || manifest.OS != "linux" || !runnerSHA.MatchString(manifest.SourceSHA) || manifest.Repository == "" || manifest.ReleaseTag == "" || manifest.NativeRuntimeQualification {
		return c, ErrInvalid
	}
	if c.Profile.Install.SourceSHA != "" && c.Profile.Install.SourceSHA != manifest.SourceSHA {
		return c, ErrConflict
	}
	if c.Profile.Architecture != "amd64" || len(manifest.InstallerArchitectures) != 1 || manifest.InstallerArchitectures[0] != "amd64" || len(manifest.Bundles) != 2 {
		return c, ErrInvalid
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		a, ok := manifest.Bundles[architecture]
		if !ok || !runnerHTTPS(a.URL, false) || !runnerHash.MatchString(a.SHA256) {
			return c, ErrInvalid
		}
	}
	if !runnerHTTPS(manifest.BootstrapScript.URL, false) || !runnerHash.MatchString(manifest.BootstrapScript.SHA256) {
		return c, ErrInvalid
	}
	if manifest.WorkloadImagesBuilt != (manifest.WorkloadImageDelivery != nil) {
		return c, ErrInvalid
	}
	if a := manifest.WorkloadImageDelivery; a != nil {
		if !runnerHTTPS(a.URL, false) || !runnerHash.MatchString(a.SHA256) {
			return c, ErrInvalid
		}
	}
	edition := false
	for _, e := range manifest.APIEditions {
		if e != "open" && e != "enterprise" {
			return c, ErrInvalid
		}
		edition = edition || e == c.Profile.Install.Edition
	}
	if !edition {
		return c, ErrInvalid
	}
	// Only installer distribution pins change. The reviewed organization,
	// gateway, images, controller trust and qualification cannot be supplied by
	// this manifest or broadened by an ARM64 compile artifact.
	c.Profile.BootstrapScript = manifest.BootstrapScript
	c.Profile.Install.Bundle = manifest.Bundles["amd64"]
	c.Profile.Install.SourceSHA = manifest.SourceSHA
	if manifest.WorkloadImageDelivery != nil {
		delivery := *manifest.WorkloadImageDelivery
		c.WorkloadImageDelivery = &delivery
	}
	return c, nil
}
func LoadRunnerDistributionConfig(path string, c RunnerEnrollmentConfig) (RunnerEnrollmentConfig, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return c, ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 32768 {
		return c, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return c, ErrInvalid
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(info, current) {
		return c, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil {
		return c, ErrInvalid
	}
	return ApplyRunnerDistribution(raw, c)
}
