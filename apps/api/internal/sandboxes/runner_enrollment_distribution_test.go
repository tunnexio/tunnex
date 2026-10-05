package sandboxes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunnerDistributionPinsDoNotBroadenPrivateRuntimeConfig(t *testing.T) {
	plan := RunnerInstallPlan{Edition: "open", SourceSHA: strings.Repeat("1", 40)}
	config := RunnerEnrollmentConfig{RunnerURI: "spiffe://tunnex/runner/scoped", Profile: RunnerEnrollmentProfile{Architecture: "amd64", Install: plan}, HostQualificationEvidence: "private reviewed configuration"}
	manifest := RunnerDistribution{SchemaVersion: 1, SourceSHA: plan.SourceSHA, Repository: "tunnexio/tunnex", ReleaseTag: "v1.0.0", OS: "linux", APIEditions: []string{"open", "enterprise"}, BootstrapScript: RunnerArtifact{"https://releases.example.invalid/enroll.py", strings.Repeat("a", 64)}, Bundles: map[string]RunnerArtifact{"amd64": {"https://releases.example.invalid/amd64.tar.gz", strings.Repeat("b", 64)}, "arm64": {"https://releases.example.invalid/arm64.tar.gz", strings.Repeat("c", 64)}}, InstallerArchitectures: []string{"amd64"}}
	raw, _ := json.Marshal(manifest)
	got, err := ApplyRunnerDistribution(raw, config)
	if err != nil || got.Profile.BootstrapScript != manifest.BootstrapScript || got.Profile.Install.Bundle != manifest.Bundles["amd64"] || got.RunnerURI != config.RunnerURI || got.HostQualificationEvidence != config.HostQualificationEvidence {
		t.Fatal("distribution changed private authority", err)
	}
	path := filepath.Join(t.TempDir(), "distribution.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadRunnerDistributionConfig(path, config); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadRunnerDistributionConfig(path, config); err == nil {
		t.Fatal("writable publication pins accepted")
	}
	for _, change := range []func(*RunnerDistribution){func(m *RunnerDistribution) { m.SourceSHA = strings.Repeat("2", 40) }, func(m *RunnerDistribution) { m.NativeRuntimeQualification = true }, func(m *RunnerDistribution) { m.InstallerArchitectures = []string{"amd64", "arm64"} }, func(m *RunnerDistribution) { m.BootstrapScript.URL = "https://user:password@example.invalid/asset" }, func(m *RunnerDistribution) { m.BootstrapScript.URL = "https://example.invalid/asset?token=secret" }, func(m *RunnerDistribution) { delete(m.Bundles, "arm64") }} {
		var candidate RunnerDistribution
		if json.Unmarshal(raw, &candidate) != nil {
			t.Fatal("fixture")
		}
		change(&candidate)
		bad, _ := json.Marshal(candidate)
		if _, err = ApplyRunnerDistribution(bad, config); err == nil {
			t.Fatal("unscoped manifest accepted")
		}
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), raw...), []byte(`{"schema_version":1,"schema_version":1}`), []byte(`{"unknown":true}`)} {
		if _, err = ApplyRunnerDistribution(bad, config); err == nil {
			t.Fatal("ambiguous/unknown manifest accepted")
		}
	}
}
