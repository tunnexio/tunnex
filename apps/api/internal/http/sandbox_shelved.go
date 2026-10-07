package http

import (
	"net/http"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxproduct"
)

// Saved SSH keys belong to the sandbox product in this source: its OpenAPI
// operations use sandbox permissions and only sandbox UI consumers exist.
// Shared server-access and cross-gateway routes retain their ordinary behavior.
func isSandboxProductPath(path string) bool {
	for _, root := range []string{"/api/v1/sandbox", "/api/v1/sandbox-runners"} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	const prefix = "/api/v1/organizations/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	return len(parts) >= 2 && (parts[1] == "sandboxes" || strings.HasPrefix(parts[1], "sandbox-") || parts[1] == "saved-ssh-keys")
}

func sandboxShelvedMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sandboxproduct.Shelved && isSandboxProductPath(r.URL.Path) {
			apierr.Write(w, r, apierr.New(http.StatusNotFound, "sandbox_feature_shelved", "Sandboxes are unavailable while development is paused."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// TODO(sandbox-reentry): docs/S-sandbox-shelved-main-reentry.md. Keep only the
// sandbox dependencies disconnected, even if an older caller supplies them.
func shelvedSandboxDependencies(d Deps) Deps {
	if !sandboxproduct.Shelved {
		return d
	}
	d.Sandboxes = nil
	d.SandboxRunnerEnrollment = nil
	d.SandboxRunnerQualification = nil
	d.SandboxModuleState = "disabled"
	d.SandboxProvisioningReady = nil
	d.SandboxWake = nil
	d.SandboxSkillsReady = nil
	return d
}
