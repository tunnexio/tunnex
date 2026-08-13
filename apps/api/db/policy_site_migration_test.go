package db_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// seedSiteDstRule inserts org + group + site + a policy_rule targeting the site (dst_kind='site').
func seedSiteDstRule(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (org, group, site uuid.UUID) {
	t.Helper()
	org, group, site = uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug) VALUES ($1,'S',$2)`, org, "sd-"+org.String()[:8])
	ex(`INSERT INTO user_groups (id,org_id,name) VALUES ($1,$2,'admins')`, group, org)
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'hq')`, site, org)
	ex(`INSERT INTO policy_rules (org_id,src_kind,src_group_id,dst_kind,dst_site_id) VALUES ($1,'group',$2,'site',$3)`, org, group, site)
	return org, group, site
}

// TestPolicyRuleSiteDstCascade is the S8.1 Slice-3 cascade red (D3): deleting a SITE must
// CASCADE-delete its dependent policy rules (dst_kind='site'), so no grant dangles against a vanished
// site — mirroring the S7.1 resource/group dst cascade discipline.
func TestPolicyRuleSiteDstCascade(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	org, _, site := seedSiteDstRule(t, ctx, pool)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	var before int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE dst_site_id=$1`, site).Scan(&before); err != nil || before != 1 {
		t.Fatalf("expected 1 site-dst rule before delete, got %d (%v)", before, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM sites WHERE id=$1`, site); err != nil {
		t.Fatalf("delete site: %v", err)
	}
	var after int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE org_id=$1 AND dst_kind='site'`, org).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != 0 {
		t.Fatalf("deleting a site must CASCADE-delete its dependent policy rules (no dangling grant), %d remain", after)
	}
}

// TestPolicyRuleDstCheckAdditiveOnly proves 0033's CHECK widening is ADDITIVE ONLY: `site` joined the
// allowed dst kinds, and every OLD rejection still rejects (nothing previously invalid became valid
// besides `site`). CHECK-widening is exactly where an accidental loosening hides.
func TestPolicyRuleDstCheckAdditiveOnly(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	org, group, site := seedSiteDstRule(t, ctx, pool) // valid site rule already inserted (site IS now allowed)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	rejects := func(name, sql string, args ...any) {
		if _, e := pool.Exec(ctx, sql, args...); e == nil {
			t.Fatalf("%s: expected a CHECK rejection (23514), got success — the widening LEAKED", name)
		}
	}
	// dst_kind CHECK: an unknown kind is STILL rejected (only 'site' was added).
	rejects("unknown dst_kind", `INSERT INTO policy_rules (org_id,src_kind,src_group_id,dst_kind,dst_site_id) VALUES ($1,'group',$2,'bogus',$3)`, org, group, site)
	// exactly-one CHECK: dst_kind='site' with a NULL dst_site_id is STILL rejected.
	rejects("site kind, null site id", `INSERT INTO policy_rules (org_id,src_kind,src_group_id,dst_kind,dst_site_id) VALUES ($1,'group',$2,'site',NULL)`, org, group)
	// exactly-one CHECK: dst_kind='site' with ALSO a group id set is STILL rejected (no cross-contamination).
	rejects("site kind + group id", `INSERT INTO policy_rules (org_id,src_kind,src_group_id,dst_kind,dst_site_id,dst_group_id) VALUES ($1,'group',$2,'site',$3,$2)`, org, group, site)
}

// TestPolicyRuleSiteDstMigrationUpDownUp is the 0033 [7] red: the down-migration must survive a
// POPULATED dst_kind='site' rule (which has dst_resource_id/dst_group_id NULL — the restored 2-kind
// exactly-one CHECK would abort on it unless the down purges site rows first). Isolated throwaway DB.
func TestPolicyRuleSiteDstMigrationUpDownUp(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dbName := fmt.Sprintf("tnx_migtest_%d", time.Now().UnixNano())
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer adminPool.Close()
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)") }()

	u, _ := url.Parse(admin)
	u.Path = "/" + dbName
	dsn := u.String()

	colExists := func(col string) bool {
		p, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer p.Close()
		var ok bool
		_ = p.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='policy_rules' AND column_name=$1)`, col).Scan(&ok)
		return ok
	}

	if err := db.MigrateTo(dsn, 33); err != nil {
		t.Fatalf("up: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect isolated: %v", err)
	}
	seedSiteDstRule(t, ctx, pool)
	pool.Close()

	// DOWN: must NOT abort on the populated site-dst rule (the [7] purge).
	if err := db.DownOne(dsn); err != nil {
		t.Fatalf("down 0033 with a populated site-dst rule FAILED (the [7] class): %v", err)
	}
	if colExists("dst_site_id") {
		t.Fatal("dst_site_id must be gone after down")
	}
	// UP again to 0033 (up -> down -> up).
	if err := db.MigrateTo(dsn, 33); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	if !colExists("dst_site_id") {
		t.Fatal("dst_site_id must be back after re-up")
	}
}
