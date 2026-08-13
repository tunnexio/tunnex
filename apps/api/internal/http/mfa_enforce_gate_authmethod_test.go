package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
)

func gateTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedGatedUser creates an enforcing org + a member with NO confirmed TOTP → IsEnrollmentGated=true.
func seedGatedUser(t *testing.T, pool *pgxpool.Pool) (org, user uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	org, user = uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3)`, org, "Gate Org", "gate-"+org.String()[:8])
	ex(`INSERT INTO users (id, email) VALUES ($1,$2)`, user, "g-"+user.String()[:8]+"@ex.com")
	ex(`INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'member')`, org, user)
	ex(`INSERT INTO org_mfa (org_id, enforce) VALUES ($1,true)`, org)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, user)
	})
	return org, user
}

// TestEnrollmentGateAuthMethodExemption is the finding-#1/#2 red: the gate applies ONLY to
// local-password principals. An SSO or bearer principal for the SAME gated user is EXEMPT by
// construction (D5), and a legacy (empty-method) session is exempt too (D8-consistent). The positive
// — a local-password unenrolled principal IS gated — must survive the fix.
func TestEnrollmentGateAuthMethodExemption(t *testing.T) {
	pool := gateTestPool(t)
	org, user := seedGatedUser(t, pool)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	srv := apiServer{mfa: mfa.NewService(pool, sealer, nil, nil), mfaEnforceEnabled: true}
	swagger, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	swagger.Servers = nil
	mw, err := srv.mfaEnrollmentGate(swagger)
	if err != nil {
		t.Fatal(err)
	}

	check := func(method string, wantGated bool) {
		nextCalled := false
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { nextCalled = true; w.WriteHeader(http.StatusOK) }))
		// A non-allowlisted route (listDevices) so a GATED local user is refused.
		req := httptest.NewRequest("GET", "http://x/api/v1/organizations/"+org.String()+"/devices", nil)
		req = req.WithContext(authctx.WithPrincipal(req.Context(), &authctx.Principal{UserID: user, AuthMethod: method, EmailVerified: true}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if wantGated {
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "mfa_enrollment_required") {
				t.Fatalf("method %q: want 403 mfa_enrollment_required, got %d %s", method, rec.Code, rec.Body.String())
			}
			if nextCalled {
				t.Fatalf("method %q: next must NOT be called for a gated principal", method)
			}
		} else if !nextCalled {
			t.Fatalf("method %q: EXEMPT principal must pass to next, got %d %s", method, rec.Code, rec.Body.String())
		}
	}

	check(authctx.AuthLocalPassword, true) // positive: local + unenrolled + enforcing -> gated
	check(authctx.AuthSSO, false)          // D5: SSO exempt (IdP owns MFA)
	check(authctx.AuthBearer, false)       // D5: bearer/CLI exempt
	check("", false)                       // legacy session (no marker) -> exempt (D8-consistent)
}
