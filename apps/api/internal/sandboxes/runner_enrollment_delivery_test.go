package sandboxes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunnerImageDeliveryUpdatesOnlyReviewedImageDeliveryPins(t *testing.T) {
	d := RunnerWorkloadImageDelivery{SchemaVersion: 1, SourceSHA: strings.Repeat("1", 40), OS: "linux", Architecture: "amd64", DependencyLockSHA256: strings.Repeat("2", 64), BaseManifestDigest: "sha256:" + strings.Repeat("3", 64), Archive: RunnerWorkloadArchive{RunnerWorkloadArchiveName, strings.Repeat("4", 64), 100 << 20}, ConfigDigest: "sha256:" + strings.Repeat("5", 64), UnpackedImageBytes: 220 << 20}
	raw, _ := json.Marshal(d)
	hash := sha256.Sum256(raw)
	pin := RunnerArtifact{"https://releases.example.invalid/tag/workload-image.json", hex.EncodeToString(hash[:])}
	c := RunnerEnrollmentConfig{RunnerURI: "spiffe://tunnex/scoped/runner", WorkloadImageDelivery: &pin, HostQualificationEvidence: "existing reviewed evidence", Profile: RunnerEnrollmentProfile{Install: RunnerInstallPlan{SourceSHA: d.SourceSHA, Images: []RunnerInstallImage{{ConfigDigest: d.ConfigDigest, Architecture: "amd64", QualificationEvidence: "reviewed exact immutable template"}}}}}
	got, err := ApplyRunnerWorkloadImageDelivery(raw, c)
	if err != nil || got.Profile.Install.Images[0].URL != "https://releases.example.invalid/tag/"+RunnerWorkloadArchiveName || got.Profile.Install.Images[0].SHA256 != d.Archive.SHA256 || got.Profile.Install.Images[0].ConfigDigest != d.ConfigDigest || got.Profile.Install.Images[0].QualificationEvidence != c.Profile.Install.Images[0].QualificationEvidence || got.RunnerURI != c.RunnerURI || got.HostQualificationEvidence != c.HostQualificationEvidence {
		t.Fatal("delivery changed authority", err)
	}
	file := filepath.Join(t.TempDir(), "workload-image.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadRunnerWorkloadImageDeliveryConfig(file, c); err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyRunnerWorkloadImageDelivery(append(raw, ' '), c); err == nil {
		t.Fatal("unpinned descriptor bytes accepted")
	}
	for _, change := range []func(*RunnerWorkloadImageDelivery){func(d *RunnerWorkloadImageDelivery) { d.NativeQualification = true }, func(d *RunnerWorkloadImageDelivery) { d.ServicesStarted = true }, func(d *RunnerWorkloadImageDelivery) { d.PackagesInstalledAtLaunch = true }, func(d *RunnerWorkloadImageDelivery) { d.Architecture = "arm64" }, func(d *RunnerWorkloadImageDelivery) { d.SourceSHA = strings.Repeat("9", 40) }, func(d *RunnerWorkloadImageDelivery) { d.Archive.Filename = "../private" }, func(d *RunnerWorkloadImageDelivery) { d.ConfigDigest = "latest" }} {
		var candidate RunnerWorkloadImageDelivery
		if json.Unmarshal(raw, &candidate) != nil {
			t.Fatal("fixture")
		}
		change(&candidate)
		bad, _ := json.Marshal(candidate)
		newHash := sha256.Sum256(bad)
		newPin := pin
		newPin.SHA256 = hex.EncodeToString(newHash[:])
		if _, err = ParseRunnerWorkloadImageDelivery(bad, newPin, c.Profile.Install.SourceSHA); err == nil {
			t.Fatal("unsafe image declaration accepted")
		}
	}
	c.Profile.Install.Images[0].ConfigDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err = ApplyRunnerWorkloadImageDelivery(raw, c); err == nil {
		t.Fatal("delivery invented new image identity")
	}
}
func TestRunnerDistributionOptionalImagePinRequiresMatchingPublicationFlag(t *testing.T) {
	c := RunnerEnrollmentConfig{Profile: RunnerEnrollmentProfile{Architecture: "amd64", Install: RunnerInstallPlan{Edition: "open", SourceSHA: strings.Repeat("1", 40)}}}
	m := RunnerDistribution{SchemaVersion: 1, SourceSHA: c.Profile.Install.SourceSHA, Repository: "tunnexio/tunnex", ReleaseTag: "v1.0.0", OS: "linux", APIEditions: []string{"open", "enterprise"}, BootstrapScript: RunnerArtifact{"https://releases.example.invalid/enroll.py", strings.Repeat("a", 64)}, Bundles: map[string]RunnerArtifact{"amd64": {"https://releases.example.invalid/amd64.tar.gz", strings.Repeat("b", 64)}, "arm64": {"https://releases.example.invalid/arm64.tar.gz", strings.Repeat("c", 64)}}, InstallerArchitectures: []string{"amd64"}, WorkloadImagesBuilt: true, WorkloadImageDelivery: &RunnerArtifact{"https://releases.example.invalid/workload-image.json", strings.Repeat("d", 64)}}
	raw, _ := json.Marshal(m)
	got, err := ApplyRunnerDistribution(raw, c)
	if err != nil || got.WorkloadImageDelivery == nil || *got.WorkloadImageDelivery != *m.WorkloadImageDelivery {
		t.Fatal("published image pin absent", err)
	}
	m.WorkloadImagesBuilt = false
	raw, _ = json.Marshal(m)
	if _, err = ApplyRunnerDistribution(raw, c); err == nil {
		t.Fatal("inconsistent publication flags accepted")
	}
}
