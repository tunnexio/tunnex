package http

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

func TestAIProviderAuthorizationBeforeValidationAndSecretRedaction(t *testing.T) {
	org := uuid.New()
	srv := aiSocketServer(t, Deps{AuthFn: func(r *http.Request) *authctx.Principal {
		role := r.Header.Get("X-Fixture-Role")
		if role == "" {
			return nil
		}
		return &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: role}}
	}})
	marker := "PROVIDER_SECRET_MUST_NOT_APPEAR"
	body := `{"provider":"openrouter","name":"fixture","models":["openrouter/openai/gpt-4o-mini"],"enabled":true,"api_key":{"value":"` + marker + `"}}`
	for _, tc := range []struct {
		name, role string
		org        uuid.UUID
		want       int
	}{
		{"anonymous", "", org, 401}, {"member", "member", org, 403}, {"foreign", "owner", uuid.New(), 404}, {"owner", "owner", org, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := aiSocketRequest(t, srv, "POST", "/api/v1/organizations/"+tc.org.String()+"/ai-gateway/providers", body, "", tc.role)
			raw, _ := io.ReadAll(res.Body)
			if res.StatusCode != tc.want {
				t.Errorf("status=%d want=%d", res.StatusCode, tc.want)
			}
			if strings.Contains(string(raw), marker) {
				t.Error("provider secret escaped in schema error")
			}
			if tc.want == 400 && !strings.Contains(string(raw), "AI provider request is invalid") {
				t.Error("provider schema error is not sanitized")
			}
		})
	}
}

func TestAIProviderSchemasAcceptSupportedProvidersOnly(t *testing.T) {
	org := uuid.New()
	srv := aiSocketServer(t, Deps{AuthFn: func(r *http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}}
	}})
	base := "/api/v1/organizations/" + org.String() + "/ai-gateway/"
	for _, provider := range []string{"openai", "anthropic", "gemini", "openrouter", "groq", "mistral", "cerebras", "xai", "deepseek", "custom", "unsupported"} {
		t.Run(provider, func(t *testing.T) {
			want := http.StatusServiceUnavailable // Valid input reaches the absent engine.
			if provider == "unsupported" {
				want = http.StatusBadRequest
			}
			body := `{"provider":"` + provider + `","name":"fixture","models":["` + provider + `/exact-model"],"enabled":true,"api_key":"synthetic-only-key"}`
			if provider == "custom" {
				body = `{"provider":"custom","endpoint_url":"http://inference.internal:8080","name":"fixture","models":["exact-model"],"enabled":true,"api_key":"synthetic-only-key"}`
			}
			for _, request := range []struct{ method, path, body string }{
				{"POST", base + "providers", body},
				{"GET", base + "models?provider=" + provider, ""},
			} {
				res := aiSocketRequest(t, srv, request.method, request.path, request.body, "", "owner")
				res.Body.Close()
				if res.StatusCode != want {
					t.Fatalf("%s %s status=%d want=%d", request.method, request.path, res.StatusCode, want)
				}
			}
		})
	}
}
