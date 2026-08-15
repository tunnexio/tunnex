package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

func TestRuntimeAuthMiddlewareUniformlyRefusesNonRuntimeCredentials(t *testing.T) {
	h := runtimeAuthMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	paths := []string{"/api/v1/agent/runtime/poll", "/api/v1/agent/runtime/report"}
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

func TestAgentRuntimeStatusChecksPermissionBeforeRuntimeState(t *testing.T) {
	_, err := (apiServer{}).GetAgentRuntimeStatus(context.Background(), api.GetAgentRuntimeStatusRequestObject{})
	if !hasCode(err, http.StatusUnauthorized, "unauthenticated") {
		t.Fatalf("status without principal = %v, want permission/auth refusal before state access", err)
	}
}
