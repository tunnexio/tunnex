package beam

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestBeamMigrationFreshUpgradeDowngradePreservesParent(t *testing.T) {
	parentDSN := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if parentDSN == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for disposable migration qualification")
	}
	ctx := context.Background()
	parent, e := pgxpool.New(ctx, parentDSN)
	if e != nil {
		t.Fatal("cannot connect test parent")
	}
	t.Cleanup(parent.Close)
	type snapshot struct {
		version       int
		dirty         bool
		organizations int
	}
	readParent := func() snapshot {
		t.Helper()
		var out snapshot
		if e := parent.QueryRow(ctx, `SELECT version,dirty,(SELECT count(*) FROM organizations) FROM schema_migrations`).Scan(&out.version, &out.dirty, &out.organizations); e != nil {
			t.Fatal(e)
		}
		return out
	}
	before := readParent()
	t.Cleanup(func() {
		if after := readParent(); after != before {
			t.Fatal("migration qualification changed its shared parent", before, after)
		}
	})
	t.Run("fresh", func(t *testing.T) {
		freshCtx, fresh := testpostgres.New(t)
		var version int
		var dirty bool
		if e := fresh.QueryRow(freshCtx, `SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty); e != nil || version < 210 || dirty {
			t.Fatal("fresh Beam schema is incomplete", version, dirty, e)
		}
	})
	t.Run("upgrade-drain-down-up", func(t *testing.T) {
		childCtx, child := testpostgres.NewAtVersion(t, 209)
		var ownedName string
		if e := child.QueryRow(childCtx, `SELECT current_database()`).Scan(&ownedName); e != nil || !strings.HasPrefix(ownedName, "tnx_test_") {
			t.Fatal("migration requires an owned disposable database")
		}
		u, e := url.Parse(parentDSN)
		if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
			t.Fatal("migration qualification requires an explicit PostgreSQL URL")
		}
		u.Path, u.RawPath = "/"+ownedName, ""
		params := u.Query()
		params.Del("database")
		params.Del("dbname")
		u.RawQuery = params.Encode()
		ownedDSN := u.String()
		org, user := uuid.New(), uuid.New()
		if _, e = child.Exec(childCtx, `INSERT INTO organizations(id,name,slug)VALUES($1,'Migration fixture',$2)`, org, org.String()); e != nil {
			t.Fatal(e)
		}
		if _, e = child.Exec(childCtx, `INSERT INTO users(id,email,name)VALUES($1,$2,'Migration fixture')`, user, user.String()+"@migration.fixture"); e != nil {
			t.Fatal(e)
		}
		if e = db.MigrateTo(ownedDSN, 210); e != nil {
			t.Fatal("Beam upgrade failed", e)
		}
		share := uuid.New()
		if _, e = child.Exec(childCtx, `INSERT INTO beam_shares(id,org_id,publisher_id,name,hostname,target,digest,idempotency_key,request_digest,expires_at) VALUES($1,$2,$3,'Migration share','p-fixture.beam.example.net','{}',$4,$5,$4,now()+interval '1 hour')`, share, org, user, strings.Repeat("a", 64), uuid.New()); e != nil {
			t.Fatal(e)
		}
		down, e := db.MigrationsFS.ReadFile("migrations/0210_beam.down.sql")
		if e != nil {
			t.Fatal(e)
		}
		// Execute the exact frozen down script to prove its guard without marking
		// a deliberately rejected disposable migrator dirty.
		if _, e = child.Exec(childCtx, string(down)); e == nil || !strings.Contains(e.Error(), "Drain Beam shares") {
			t.Fatal("downgrade did not require live shares to be drained", e)
		}
		if _, e = child.Exec(childCtx, `UPDATE beam_shares SET state='stopped' WHERE id=$1`, share); e != nil {
			t.Fatal(e)
		}
		if e = db.MigrateTo(ownedDSN, 209); e != nil {
			t.Fatal("drained downgrade failed", e)
		}
		if e = db.MigrateTo(ownedDSN, 210); e != nil {
			t.Fatal("Beam re-upgrade failed", e)
		}
		var version, organizations, users, shares int
		var dirty bool
		if e = child.QueryRow(childCtx, `SELECT version,dirty,(SELECT count(*) FROM organizations WHERE id=$1),(SELECT count(*) FROM users WHERE id=$2),(SELECT count(*) FROM beam_shares) FROM schema_migrations`, org, user).Scan(&version, &dirty, &organizations, &users, &shares); e != nil || version != 210 || dirty || organizations != 1 || users != 1 || shares != 0 {
			t.Fatal("re-upgrade lost unrelated data or restored old Beam authority", version, dirty, organizations, users, shares, e)
		}
	})
}

func TestBeamInstallationMigrationUpgradeDefaultOffAndGuardedRollback(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 210)
	var name string
	if e := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&name); e != nil || !strings.HasPrefix(name, "tnx_test_") {
		t.Fatal("requires an owned fixture")
	}
	u, e := url.Parse(os.Getenv("TUNNEX_TEST_DATABASE_URL"))
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("requires an explicit PostgreSQL URL")
	}
	u.Path, u.RawPath = "/"+name, ""
	query := u.Query()
	query.Del("database")
	query.Del("dbname")
	u.RawQuery = query.Encode()
	owned := u.String()
	if e = db.MigrateTo(owned, 211); e != nil {
		t.Fatal(e)
	}
	var enabled, configured, passed bool
	if e = pool.QueryRow(ctx, `SELECT operator_enabled,configured,readiness_passed FROM beam_installation_settings WHERE singleton`).Scan(&enabled, &configured, &passed); e != nil || enabled || configured || passed {
		t.Fatal("installation upgrade did not default off", e)
	}
	if _, e = pool.Exec(ctx, `UPDATE beam_installation_settings SET operator_enabled=true WHERE singleton`); e != nil {
		t.Fatal(e)
	}
	down, e := db.MigrationsFS.ReadFile("migrations/0211_beam_installation_settings.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, string(down)); e == nil || !strings.Contains(e.Error(), "Disable installation authority") {
		t.Fatal("rollback did not require installation disable", e)
	}
	if _, e = pool.Exec(ctx, `UPDATE beam_installation_settings SET operator_enabled=false WHERE singleton`); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(owned, 210); e != nil {
		t.Fatal(e)
	}
	var preserved bool
	if e = pool.QueryRow(ctx, `SELECT to_regclass('public.beam_shares') IS NOT NULL AND to_regclass('public.beam_installation_settings') IS NULL`).Scan(&preserved); e != nil || !preserved {
		t.Fatal("registry rollback altered independent Beam resources", e)
	}
	if e = db.MigrateTo(owned, 211); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT operator_enabled,configured,readiness_passed FROM beam_installation_settings WHERE singleton`).Scan(&enabled, &configured, &passed); e != nil || enabled || configured || passed {
		t.Fatal("registry re-upgrade resurrected old readiness", e)
	}
}

func TestBeamOpenModeMigrationPreservesPoliciesAndRequiresRestrictedRollback(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 211)
	var name string
	if e := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&name); e != nil || !strings.HasPrefix(name, "tnx_test_") {
		t.Fatal("requires owned database", e)
	}
	u, e := url.Parse(os.Getenv("TUNNEX_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	u.Path, u.RawPath = "/"+name, ""
	params := u.Query()
	params.Del("database")
	params.Del("dbname")
	u.RawQuery = params.Encode()
	org := uuid.New()
	group := uuid.New()
	if _, e = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug)VALUES($1,'Open-mode migration',$2)`, org, org.String()); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, `INSERT INTO beam_policies(org_id,enabled,version,publisher_group_ids,max_shares)VALUES($1,true,7,ARRAY[$2::uuid],3)`, org, group); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(u.String(), 212); e != nil {
		t.Fatal(e)
	}
	var open, enabled bool
	var version int
	var groups []uuid.UUID
	var max int
	if e = pool.QueryRow(ctx, `SELECT open_for_all_users,enabled,version,publisher_group_ids,max_shares FROM beam_policies WHERE org_id=$1`, org).Scan(&open, &enabled, &version, &groups, &max); e != nil || open || !enabled || version != 7 || len(groups) != 1 || groups[0] != group || max != 3 {
		t.Fatal("existing policy changed", e, open, enabled, version, groups, max)
	}
	if _, e = pool.Exec(ctx, `UPDATE beam_policies SET open_for_all_users=true WHERE org_id=$1`, org); e != nil {
		t.Fatal(e)
	}
	down, e := db.MigrationsFS.ReadFile("migrations/0212_beam_open_for_all_users.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, string(down)); e == nil || !strings.Contains(e.Error(), "restricted mode") {
		t.Fatal("open policy downgraded silently", e)
	}
	if _, e = pool.Exec(ctx, `UPDATE beam_policies SET open_for_all_users=false WHERE org_id=$1`, org); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(u.String(), 211); e != nil {
		t.Fatal("restricted downgrade", e)
	}
	if e = db.MigrateTo(u.String(), 212); e != nil {
		t.Fatal("re-upgrade", e)
	}
	if e = pool.QueryRow(ctx, `SELECT open_for_all_users,version,publisher_group_ids,max_shares FROM beam_policies WHERE org_id=$1`, org).Scan(&open, &version, &groups, &max); e != nil || open || version != 7 || len(groups) != 1 || groups[0] != group || max != 3 {
		t.Fatal("re-upgrade lost saved restrictions", e)
	}
}
