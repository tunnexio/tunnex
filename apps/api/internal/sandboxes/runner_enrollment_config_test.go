package sandboxes

import (
	"strings"
	"testing"

	"github.com/google/uuid"
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
