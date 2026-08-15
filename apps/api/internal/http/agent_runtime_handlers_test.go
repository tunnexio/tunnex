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
	paths := []string{"/api/v1/agent/runtime/poll", "/api/v1/agent/runtime/report", "/api/v1/agent/runtime/credential-candidate", "/api/v1/agent/runtime/wireguard-candidate"}
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

func TestAgentCredentialRotationPermissionPrecedesStateAndEdition(t *testing.T) {
	org, device, user := uuid.New(), uuid.New(), uuid.New()
	req := api.GetAgentCredentialRotationRequestObject{OrgId: org, DeviceId: device}
	member := authctx.WithPrincipal(context.Background(), &authctx.Principal{
		UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember},
	})
	if _, err := (apiServer{}).GetAgentCredentialRotation(member, req); !hasCode(err, http.StatusForbidden, "forbidden") {
		t.Fatalf("plain member rotation status = %v, want uniform 403 before state/edition", err)
	}
	owner := authctx.WithPrincipal(context.Background(), &authctx.Principal{
		UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner},
	})
	if _, err := (apiServer{}).GetAgentCredentialRotation(owner, req); !hasCode(err, http.StatusForbidden, "edition_required") {
		t.Fatalf("owner rotation status = %v, want permission pass then edition gate", err)
	}
}

func TestAgentRuntimeStatusChecksPermissionBeforeRuntimeState(t *testing.T) {
	_, err := (apiServer{}).GetAgentRuntimeStatus(context.Background(), api.GetAgentRuntimeStatusRequestObject{})
	if !hasCode(err, http.StatusUnauthorized, "unauthenticated") {
		t.Fatalf("status without principal = %v, want permission/auth refusal before state access", err)
	}
}
