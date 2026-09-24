package http

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// Run only through the guarded isolated database runner. The test owns a unique
// scratch database and closes its pool before dropping that database.
func TestIPsecSettingsRouterStoreIntegration(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to the isolated fixture database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_ipsec_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("scratch database cleanup: %v", err)
		}
	})
	parsed.Path = "/" + name
	if err = db.MigrateTo(parsed.String(), 160); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, actor := uuid.New(), uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'IPsec HTTP settings',$2,'10.198.0.0/24')`, org, "ipsec-http-"+org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email) VALUES($1,$2)`, actor, actor.String()+"@ipsec-http.test"); err != nil {
		t.Fatal(err)
	}
	role := rbac.RoleOwner
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecSettings: ipsec.NewSettingsStore(pool), AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, body string, want int) ipsec.Settings {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/v1/organizations/"+org.String()+"/ipsec/settings", strings.NewReader(body)).WithContext(ctx)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		router.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s status %d want %d: %s", method, rec.Code, want, rec.Body.String())
		}
		var settings ipsec.Settings
		if want == 200 {
			if err := json.Unmarshal(rec.Body.Bytes(), &settings); err != nil {
				t.Fatal(err)
			}
		}
		return settings
	}
	assertState := func(enabled bool, revision int64) {
		t.Helper()
		got := request(http.MethodGet, "", 200)
		if got.Enabled != enabled || got.Revision != revision {
			t.Fatalf("settings=%+v want enabled=%v revision=%d", got, enabled, revision)
		}
	}
	assertCounts := func(settings, audits int) {
		t.Helper()
		var gotSettings, gotAudits int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_org_settings WHERE org_id=$1),(SELECT count(*) FROM audit_logs WHERE org_id=$1)`, org).Scan(&gotSettings, &gotAudits); err != nil {
			t.Fatal(err)
		}
		if gotSettings != settings || gotAudits != audits {
			t.Fatalf("rows settings=%d audits=%d want %d/%d", gotSettings, gotAudits, settings, audits)
		}
	}
	assertState(false, 0)
	assertCounts(0, 0)
	got := request(http.MethodPut, `{"enabled":true,"expected_revision":0}`, 200)
	if !got.Enabled || got.Revision != 1 {
		t.Fatalf("first write=%+v", got)
	}
	request(http.MethodPut, `{"enabled":false,"expected_revision":0}`, 409)
	assertState(true, 1)
	assertCounts(1, 1)
	role = rbac.RoleMember
	request(http.MethodPut, `{"enabled":false,"expected_revision":1}`, 403)
	assertState(true, 1)
	assertCounts(1, 1)
	role = rbac.RoleOwner
	got = request(http.MethodPut, `{"enabled":false,"expected_revision":1}`, 200)
	if got.Enabled || got.Revision != 2 {
		t.Fatalf("second write=%+v", got)
	}
	assertState(false, 2)
	assertCounts(1, 2)
	var attributed int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND actor_user_id=$2 AND action='ipsec.settings_changed' AND target_type='organization' AND target_id=$3 AND (metadata->>'revision')::bigint IN (1,2) AND (metadata->>'enabled')::boolean=((metadata->>'revision')::bigint=1)`, org, actor, org.String()).Scan(&attributed); err != nil {
		t.Fatal(err)
	}
	if attributed != 2 {
		t.Fatalf("attributed committed audits=%d want 2", attributed)
	}
}
