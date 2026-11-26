package tenancy

import (
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// RBAC-0 migration 0246 is additive and backfills provenance from data that already exists, so an
// upgrade keeps every role and status and reactivation rules apply to pre-upgrade deactivations. It adds
// side tables only: the shape of `users` and `memberships` is unchanged, because their expanded
// `SELECT *` queries also run against pinned older schemas.
func TestRBAC0MigrationBackfillsProvenance(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 245)
	org, bySync, byAdmin, legacy, revoked := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'M',$2)`, []any{org, "rbac0-mig-" + org.String()}},
		{`INSERT INTO users(id,email,name,status) VALUES($1,$2,'S','deactivated')`, []any{bySync, bySync.String() + "@m.test"}},
		{`INSERT INTO users(id,email,name,status) VALUES($1,$2,'A','deactivated')`, []any{byAdmin, byAdmin.String() + "@m.test"}},
		{`INSERT INTO users(id,email,name,status) VALUES($1,$2,'L','deactivated')`, []any{legacy, legacy.String() + "@m.test"}},
		{`INSERT INTO users(id,email,name) VALUES($1,$2,'R')`, []any{revoked, revoked.String() + "@m.test"}},
		{`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, []any{org, bySync}},
		{`INSERT INTO memberships(org_id,user_id,role,access_revoked_at) VALUES($1,$2,'member',now())`, []any{org, revoked}},
		{`INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id) VALUES($1,'idp-sync','user.deactivated','user',$2)`, []any{org, bySync.String()}},
		{`INSERT INTO audit_logs(org_id,action,target_type,target_id) VALUES($1,'user.deactivated','user',$2)`, []any{org, byAdmin.String()}},
	} {
		if _, err := pool.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	u, err := url.Parse(os.Getenv("TUNNEX_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("fixture endpoint")
	}
	u.Path = "/" + pool.Config().ConnConfig.Database
	if err = db.MigrateTo(u.String(), 246); err != nil {
		t.Fatal(err)
	}
	check := func(user uuid.UUID, wantSource string, wantOrg bool) {
		t.Helper()
		var status string
		var source *string
		var hasOrg bool
		if err := pool.QueryRow(ctx, `SELECT u.status, d.source, d.org_id IS NOT NULL FROM users u LEFT JOIN user_deactivations d ON d.user_id=u.id WHERE u.id=$1`, user).Scan(&status, &source, &hasOrg); err != nil {
			t.Fatal(err)
		}
		got := ""
		if source != nil {
			got = *source
		}
		if status != "deactivated" || got != wantSource || hasOrg != wantOrg {
			t.Fatalf("user %s: status=%s source=%q org=%v", user, status, got, hasOrg)
		}
	}
	check(bySync, "idp_sync", true)
	check(byAdmin, "member_admin", true)
	check(legacy, "", false)
	var role string
	var source *string
	if err := pool.QueryRow(ctx, `SELECT m.role, s.source FROM memberships m LEFT JOIN membership_revocation_sources s ON s.org_id=m.org_id AND s.user_id=m.user_id WHERE m.org_id=$1 AND m.user_id=$2`, org, revoked).Scan(&role, &source); err != nil {
		t.Fatal(err)
	}
	if role != "member" || source == nil || *source != "idp_sync" {
		t.Fatalf("revoked membership: role=%s source=%v", role, source)
	}
	if err := pool.QueryRow(ctx, `SELECT role FROM memberships WHERE org_id=$1 AND user_id=$2`, org, bySync).Scan(&role); err != nil || role != "owner" {
		t.Fatalf("role rewritten by migration: %q %v", role, err)
	}
	for _, table := range []string{"users", "memberships"} {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name IN ('deactivation_source','deactivated_by_org_id','access_revoked_source')`, table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s gained provenance columns (%d): %v", table, n, err)
		}
	}
	down, err := db.MigrationsFS.ReadFile("migrations/0246_people_management_provenance.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(down)); err != nil {
		t.Fatal(err)
	}
}
