package sandboxes

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
)

func TestRunnerEnrollmentInstallCommandAllowsOnlyPinnedPublicHTTPSRedirects(t *testing.T) {
	id := uuid.NewString()
	s := RunnerEnrollmentService{config: RunnerEnrollmentConfig{Profile: RunnerEnrollmentProfile{
		BootstrapScript: RunnerArtifact{"https://github.com/tunnexio/tunnex/releases/download/v1.0.0/Tunnex-Sandbox-Enroll.py", strings.Repeat("a", 64)},
		Install:         RunnerInstallPlan{Edition: "open", SourceSHA: strings.Repeat("1", 40), Bundle: RunnerArtifact{"https://github.com/tunnexio/tunnex/releases/download/v1.0.0/Tunnex-Sandbox-AMD64.tar.gz", strings.Repeat("b", 64)}, Controller: RunnerInstallController{APIURL: "https://api.example.invalid"}},
	}}}
	command := s.installCommand(id)
	for _, required := range []string{"--location --max-redirs 3", "--proto '=https' --proto-redir '=https' --tlsv1.2", s.config.Profile.BootstrapScript.URL, s.config.Profile.BootstrapScript.SHA256, "| sha256sum -c - && sudo python3", "--enrollment-id '" + id + "'"} {
		if !strings.Contains(command, required) {
			t.Fatal("public pinned installer command missing", required)
		}
	}
	for _, forbidden := range []string{"bootstrap_token", "certificate_request", "PRIVATE KEY", "/api/v1/sandbox-runners/bootstrap", "--data", "--request", "--insecure"} {
		if strings.Contains(command, forbidden) {
			t.Fatal("public script redirect command contains credential exchange or disables trust", forbidden)
		}
	}
}

func TestRunnerEnrollmentRequiresOneIndependentlyQualifiedImageProfile(t *testing.T) {
	legacy := persistentTestBinding()
	for i := range legacy.Profiles {
		legacy.Profiles[i].PIDs = 64
	}
	if legacy.Validate() != nil {
		t.Fatal("legacy static four-profile support regressed")
	}
	b := legacy
	b.Admission, b.CreatorID, b.TerminalDeviceID = "organization", uuid.Nil, uuid.Nil
	b.Profiles = append([]QualifiedRuntimeProfile(nil), legacy.Profiles[:1]...)
	ca, err := sandboxrunner.Enroll("controller.example.invalid", "spiffe://tunnex/controller/one-image", "spiffe://tunnex/runner/one-image", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := RunnerEnrollmentConfig{RunnerURI: "spiffe://tunnex/runner/one-image", RunnerCA: string(ca.CA), Profile: RunnerEnrollmentProfile{
		ID: uuid.New(), Name: "Ubuntu26 terminal", Architecture: "amd64", HostOS: "ubuntu", HostVersion: "26.04",
		BootstrapScript: RunnerArtifact{"https://artifacts.example.invalid/enroll.py", strings.Repeat("a", 64)},
		Install: RunnerInstallPlan{Version: 1, Edition: "open", SourceSHA: strings.Repeat("1", 40),
			Bundle: RunnerArtifact{"https://artifacts.example.invalid/bundle.tar.gz", strings.Repeat("b", 64)}, OrgID: b.OrgID,
			Gateway:    RunnerInstallGateway{NodeID: b.GatewayID, ContainerID: strings.Repeat("c", 64), ImageDigest: "sha256:" + strings.Repeat("d", 64), Interface: "wg0"},
			Controller: RunnerInstallController{URL: "https://controller.example.invalid:8444", ServerName: "controller.example.invalid", URI: "spiffe://tunnex/controller/one-image", APIURL: "https://api.example.invalid"}},
	}}
	images := func(profiles []QualifiedRuntimeProfile) []RunnerInstallImage {
		var result []RunnerInstallImage
		for _, p := range profiles {
			result = append(result, RunnerInstallImage{TemplateID: p.TemplateID, URL: "https://artifacts.example.invalid/" + p.TemplateID.String() + ".tar", SHA256: strings.Repeat("e", 64), ConfigDigest: p.ConfigDigest, Architecture: p.Architecture, QualificationEvidence: p.QualificationEvidence})
		}
		return result
	}
	c.Profile.Install.Images = images(b.Profiles)
	if err = c.Validate(b); err != nil {
		t.Fatal("one exact enrolled image rejected", err)
	}
	for _, count := range []int{2, 4} {
		candidate := b
		candidate.Profiles = append([]QualifiedRuntimeProfile(nil), legacy.Profiles[:count]...)
		if candidate.Validate() != nil {
			t.Fatal("multi-image fixture violates an unrelated runtime constraint")
		}
		config := c
		config.Profile.Install.Images = images(candidate.Profiles)
		if err = config.Validate(candidate); !errors.Is(err, ErrInvalid) {
			t.Fatal("single native trial could qualify additional untested images", count, err)
		}
	}
}
