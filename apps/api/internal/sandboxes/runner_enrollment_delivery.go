package sandboxes

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
)

const RunnerWorkloadArchiveName = "tunnex-sandbox-ubuntu26-linux-amd64.docker.tar"

type RunnerWorkloadArchive struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
}
type RunnerWorkloadImageDelivery struct {
	SchemaVersion             int                   `json:"schema_version"`
	SourceSHA                 string                `json:"source_sha"`
	OS                        string                `json:"os"`
	Architecture              string                `json:"architecture"`
	DependencyLockSHA256      string                `json:"dependency_lock_sha256"`
	BaseManifestDigest        string                `json:"base_manifest_digest"`
	Archive                   RunnerWorkloadArchive `json:"archive"`
	ConfigDigest              string                `json:"config_digest"`
	UnpackedImageBytes        int64                 `json:"unpacked_image_bytes"`
	NativeQualification       bool                  `json:"native_qualification"`
	ServicesStarted           bool                  `json:"services_started"`
	PackagesInstalledAtLaunch bool                  `json:"packages_installed_at_launch"`
}

func ParseRunnerWorkloadImageDelivery(raw []byte, expected RunnerArtifact, source string) (RunnerWorkloadImageDelivery, error) {
	var descriptor RunnerWorkloadImageDelivery
	if len(raw) > 32768 || !runnerHTTPS(expected.URL, false) || !runnerHash.MatchString(expected.SHA256) {
		return descriptor, ErrInvalid
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != expected.SHA256 {
		return descriptor, ErrConflict
	}
	guard := json.NewDecoder(bytes.NewReader(raw))
	if uniqueRunnerJSON(guard) != nil {
		return descriptor, ErrInvalid
	}
	if _, err := guard.Token(); err != io.EOF {
		return descriptor, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&descriptor) != nil || d.Decode(new(any)) != io.EOF {
		return descriptor, ErrInvalid
	}
	if descriptor.SchemaVersion != 1 || descriptor.SourceSHA != source || !runnerSHA.MatchString(source) || descriptor.OS != "linux" || descriptor.Architecture != "amd64" || !runnerHash.MatchString(descriptor.DependencyLockSHA256) || len(descriptor.BaseManifestDigest) != 71 || descriptor.BaseManifestDigest[:7] != "sha256:" || !runnerHash.MatchString(descriptor.BaseManifestDigest[7:]) || descriptor.Archive.Filename != RunnerWorkloadArchiveName || !runnerHash.MatchString(descriptor.Archive.SHA256) || descriptor.Archive.Bytes <= 0 || descriptor.Archive.Bytes > 512<<20 || len(descriptor.ConfigDigest) != 71 || descriptor.ConfigDigest[:7] != "sha256:" || !runnerHash.MatchString(descriptor.ConfigDigest[7:]) || descriptor.UnpackedImageBytes <= 0 || descriptor.UnpackedImageBytes > 1<<30 || descriptor.NativeQualification || descriptor.ServicesStarted || descriptor.PackagesInstalledAtLaunch {
		return descriptor, ErrInvalid
	}
	return descriptor, nil
}
func ApplyRunnerWorkloadImageDelivery(raw []byte, c RunnerEnrollmentConfig) (RunnerEnrollmentConfig, error) {
	if c.WorkloadImageDelivery == nil {
		return c, ErrInvalid
	}
	descriptor, err := ParseRunnerWorkloadImageDelivery(raw, *c.WorkloadImageDelivery, c.Profile.Install.SourceSHA)
	if err != nil {
		return c, err
	}
	u, _ := url.Parse(c.WorkloadImageDelivery.URL)
	u.Path = path.Join(path.Dir(u.Path), descriptor.Archive.Filename)
	u.RawPath = ""
	matched := false
	images := append([]RunnerInstallImage(nil), c.Profile.Install.Images...)
	for i, im := range images {
		// A release artifact can provide delivery pins, never replace a reviewed
		// template/config image identity or invent a native attestation.
		if im.ConfigDigest != descriptor.ConfigDigest {
			continue
		}
		if im.Architecture != "amd64" {
			return c, ErrConflict
		}
		images[i].URL = u.String()
		images[i].SHA256 = descriptor.Archive.SHA256
		matched = true
	}
	if !matched {
		return c, ErrConflict
	}
	c.Profile.Install.Images = images
	return c, nil
}
func LoadRunnerWorkloadImageDeliveryConfig(file string, c RunnerEnrollmentConfig) (RunnerEnrollmentConfig, error) {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return c, ErrInvalid
	}
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 32768 {
		return c, ErrInvalid
	}
	f, err := os.Open(file)
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
	return ApplyRunnerWorkloadImageDelivery(raw, c)
}
