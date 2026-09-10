package http

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
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

func TestAIProviderProbeCredentialSelectors(t *testing.T) {
	_, pool := testpostgres.New(t)
	org := uuid.New()
	engine, err := aigateway.NewEngine("http://127.0.0.1:1", "fixture", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	policies := aigateway.NewPolicies(pool, nil, engine)
	policies.EnableProviderManagement(true)
	srv := aiSocketServer(t, Deps{AIPolicies: policies, AuthFn: func(r *http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}}
	}})
	id := uuid.NewString()
	for _, tc := range []struct {
		name, fields string
		want         int
	}{
		{"draft", `"api_key":"synthetic-key"`, 503},
		{"saved", `"connection_id":"` + id + `","expected_revision":1`, 503},
		{"missing", `"mode":"chat"`, 400},
		{"missing-revision", `"connection_id":"` + id + `"`, 400},
		{"draft-revision", `"api_key":"synthetic-key","expected_revision":1`, 400},
		{"override-secret", `"connection_id":"` + id + `","expected_revision":1,"api_key":"SAVED_PROBE_SECRET_MARKER"`, 400},
		{"override-endpoint", `"connection_id":"` + id + `","expected_revision":1,"endpoint_url":"https://override.invalid"`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := aiSocketRequest(t, srv, "POST", "/api/v1/organizations/"+org.String()+"/ai-gateway/providers/test-connection", `{"provider":"openai","model":"new-model",`+tc.fields+`}`, "", "owner")
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			if res.StatusCode != tc.want {
				t.Fatalf("status=%d want=%d", res.StatusCode, tc.want)
			}
			if strings.Contains(string(raw), "SAVED_PROBE_SECRET_MARKER") {
				t.Fatal("secret reflected")
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
	for _, provider := range []string{"openai", "anthropic", "gemini", "openrouter", "groq", "mistral", "cerebras", "xai", "deepseek", "custom", "sagemaker", "unsupported"} {
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
				{"POST", base + "providers/test-connection", `{"provider":"` + provider + `","model":"exact-model","api_key":"synthetic-only-key"}`},
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

func TestAIProviderProbeAuthorizationBeforeValidation(t *testing.T) {
	org := uuid.New()
	srv := aiSocketServer(t, Deps{AuthFn: func(r *http.Request) *authctx.Principal {
		role := r.Header.Get("X-Fixture-Role")
		if role == "" {
			return nil
		}
		return &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: role}}
	}})
	for _, tc := range []struct {
		role string
		org  uuid.UUID
		want int
	}{
		{"", org, 401}, {"member", org, 403}, {"owner", uuid.New(), 404}, {"owner", org, 400},
	} {
		for _, endpoint := range []string{"test-connection", "model-catalog"} {
			res := aiSocketRequest(t, srv, "POST", "/api/v1/organizations/"+tc.org.String()+"/ai-gateway/providers/"+endpoint, `{"provider":"custom","model":"demo","api_key":{"secret":"PROBE_SECRET_MARKER"}}`, "", tc.role)
			raw, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != tc.want {
				t.Errorf("role=%s status=%d want=%d", tc.role, res.StatusCode, tc.want)
			}
			if strings.Contains(string(raw), "PROBE_SECRET_MARKER") {
				t.Fatal("probe secret reflected")
			}
		}
	}
}
