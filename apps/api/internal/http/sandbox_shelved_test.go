package http

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

type unreadSandboxBody struct{ t *testing.T }

func (b unreadSandboxBody) Read([]byte) (int, error) {
	b.t.Error("shelved route read its request body")
	return 0, io.EOF
}
func (b unreadSandboxBody) Close() error { return nil }

func TestSandboxShelvedOpenAPIInventoryBeforeAuthAndBody(t *testing.T) {
	authCalls := 0
	repo := &sandboxStub{}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{
		Orgs: tenancy.NewService(nil), Sandboxes: repo, SandboxModuleState: "enabled",
		SandboxProvisioningReady: func() bool { t.Fatal("consulted sandbox runtime"); return true },
		SandboxSkillsReady:       func() bool { t.Fatal("consulted sandbox skills"); return true },
		SandboxWake:              func() { t.Fatal("woke sandbox worker") },
		AuthFn:                   func(*http.Request) *authctx.Principal { authCalls++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	parameters := regexp.MustCompile(`\{[^}]+\}`)
	checked, savedKeys := 0, 0
	for path, item := range spec.Paths.Map() {
		for method, operation := range item.Operations() {
			sandbox := false
			for _, tag := range operation.Tags {
				sandbox = sandbox || strings.EqualFold(tag, "sandboxes")
			}
			if !sandbox {
				continue
			}
			req := httptest.NewRequest(method, parameters.ReplaceAllString(path, "00000000-0000-4000-8000-000000000001"), nil)
			req.Body = unreadSandboxBody{t}
			req.ContentLength = 1
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "sandbox_feature_shelved") || rr.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s %s remains reachable: %d %s", method, path, rr.Code, rr.Body.String())
			}
			checked++
			if strings.Contains(path, "/saved-ssh-keys") {
				savedKeys++
			}
		}
	}
	if checked == 0 || savedKeys != 4 || authCalls != 0 || repo.calls != 0 {
		t.Fatalf("incomplete shelving census: routes=%d saved_keys=%d auth=%d repository=%d", checked, savedKeys, authCalls, repo.calls)
	}
	t.Logf("verified %d historical sandbox operations return 404 before authentication or body reads", checked)
}

func TestSandboxShelvedKeepsSharedRoutesAndMetadata(t *testing.T) {
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{SandboxModuleState: "enabled"})
	if err != nil {
		t.Fatal(err)
	}
	const org = "/api/v1/organizations/00000000-0000-4000-8000-000000000001"
	for _, path := range []string{org + "/cross-gateway-settings", org + "/app-access/company-apps", org + "/server-access/servers", org + "/devices", org + "/sites"} {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("shared route %s: got %d, want ordinary sessionless 401", path, rr.Code)
		}
	}
	for _, path := range []string{"/healthz", "/api/v1/meta"} {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s failed: %d %s", path, rr.Code, rr.Body.String())
		}
		if path == "/api/v1/meta" {
			var meta api.Meta
			if err := json.Unmarshal(rr.Body.Bytes(), &meta); err != nil || meta.SandboxModuleState == nil || *meta.SandboxModuleState != "disabled" {
				t.Fatalf("stale dependencies reactivated metadata: %s", rr.Body.String())
			}
		}
	}
}
