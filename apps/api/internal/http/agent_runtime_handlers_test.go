package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestRuntimeAuthMiddlewareUniformlyRefusesNonRuntimeCredentials(t *testing.T) {
	h := runtimeAuthMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	paths := []string{"/api/v1/agent/runtime/poll", "/api/v1/agent/runtime/report", "/api/v1/agent/runtime/credential-candidate", "/api/v1/agent/runtime/wireguard-candidate", "/api/v1/agent/runtime/mcp-tool-policy", "/api/v1/agent/runtime/mcp-oauth-lease", "/api/v1/agent/runtime/workflow-signing-key", "/api/v1/agent/runtime/workflow-provenance"}
	tokens := []string{"", "Bearer tnx_session_like", "Bearer tnx_runtime_unknown", "Basic not-a-bearer"}
	var wantBody string
	for _, path := range paths {
		for _, token := range tokens {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			if token != "" {
				req.Header.Set("Authorization", token)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("%s %q status=%d, want 401", path, token, rr.Code)
			}
			if wantBody == "" {
				wantBody = rr.Body.String()
			} else if rr.Body.String() != wantBody {
				t.Fatalf("%s %q changed no-oracle body: got %q want %q", path, token, rr.Body.String(), wantBody)
			}
		}
	}
}

func TestAgentCredentialRotationPermissionPrecedesState(t *testing.T) {
	org, device, user := uuid.New(), uuid.New(), uuid.New()
	req := api.GetAgentCredentialRotationRequestObject{OrgId: org, DeviceId: device}
	member := authctx.WithPrincipal(context.Background(), &authctx.Principal{
		UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember},
	})
	if _, err := (apiServer{}).GetAgentCredentialRotation(member, req); !hasCode(err, http.StatusForbidden, "forbidden") {
		t.Fatalf("plain member rotation status = %v, want uniform 403 before state/edition", err)
	}
}

func TestAgentRuntimeStatusChecksPermissionBeforeRuntimeState(t *testing.T) {
	_, err := (apiServer{}).GetAgentRuntimeStatus(context.Background(), api.GetAgentRuntimeStatusRequestObject{})
	if !hasCode(err, http.StatusUnauthorized, "unauthenticated") {
		t.Fatalf("status without principal = %v, want permission/auth refusal before state access", err)
	}
}

func TestMCPInventoryValidatorAllowsJSONSchemaPropertyNames(t *testing.T) {
	inventory := map[string]interface{}{
		"servers": []interface{}{map[string]interface{}{
			"tools": []interface{}{map[string]interface{}{
				"input_schema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"content": map[string]interface{}{"type": "string"},
						"repoName": map[string]interface{}{"anyOf": []interface{}{
							map[string]interface{}{"items": map[string]interface{}{"type": "string"}},
						}},
					},
				},
				"output_schema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"result": map[string]interface{}{"type": "string"},
					},
				},
			}},
		}},
	}
	if !validMCPInventoryValue(inventory) {
		t.Fatal("schema property names must not be treated as MCP result/content")
	}
}

func TestMCPInventoryValidatorRejectsResultOutsideSchema(t *testing.T) {
	if validMCPInventoryValue(map[string]interface{}{"result": "tool output"}) {
		t.Fatal("MCP result content outside a schema must remain rejected")
	}
}
