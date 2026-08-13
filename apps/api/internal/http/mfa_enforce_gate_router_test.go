package http

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
)

// TestEnrollmentGateThroughRealRouter drives a GATED local-password member through the FULL
// NewRouter chain (validator -> gate -> chi mount) — the runtime shape the isolated gateAllows
// test skips. The box-walk found a gated member denied on the ALLOWLISTED /auth/me and
// /auth/mfa/enroll (the grandfather path bricked). This reproduces that path locally: the
// allowlisted ops MUST pass the gate; a non-allowlisted op MUST be refused typed.
func TestEnrollmentGateThroughRealRouter(t *testing.T) {
	pool := gateTestPool(t) // skips unless TUNNEX_TEST_DATABASE_URL is set
	org, user := seedGatedUser(t, pool)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}

	// AuthFn injects the gated principal (local-password) for every request — the login seam is
	// out of scope here; we exercise the middleware chain's routing of a gated session.
	authFn := func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: user, AuthMethod: authctx.AuthLocalPassword, EmailVerified: true}
	}
	h, err := NewRouter(slog.Default(), Deps{
		Mfa:               mfa.NewService(pool, sealer, nil, nil),
		MfaEnforceEnabled: true,
		AuthFn:            authFn,
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	fire := func(method, path string) (int, string) {
		req := httptest.NewRequest(method, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// Allowlisted escape ops: the gate MUST let them through (not 403 mfa_enrollment_required).
	for _, tc := range []struct {
		method, path string
	}{
		{"GET", "/api/v1/auth/me"},
		{"POST", "/api/v1/auth/mfa/enroll"},
	} {
		code, body := fire(tc.method, tc.path)
		if code == http.StatusForbidden && strings.Contains(body, "mfa_enrollment_required") {
			t.Errorf("BRICKED: gated user refused on ALLOWLISTED %s %s: %d %s", tc.method, tc.path, code, body)
		}
	}

	// A non-allowlisted op MUST be refused typed (the gate still holds).
	code, body := fire("GET", "/api/v1/organizations/"+org.String()+"/devices")
	if code != http.StatusForbidden || !strings.Contains(body, "mfa_enrollment_required") {
		t.Errorf("gated user on non-allowlisted op: want 403 mfa_enrollment_required, got %d %s", code, body)
	}
}
