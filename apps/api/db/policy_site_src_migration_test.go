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

// seedSiteSrcRule inserts org + two sites + a policy_rule whose SOURCE is a site (src_kind='site',
// dst_kind='site') — the S8.2 site-to-site shape.
func seedSiteSrcRule(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (org, srcSite, dstSite uuid.UUID) {
	t.Helper()
	org, srcSite, dstSite = uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug) VALUES ($1,'S',$2)`, org, "ss-"+org.String()[:8])
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'siteA')`, srcSite, org)
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'siteB')`, dstSite, org)
	ex(`INSERT INTO policy_rules (org_id,src_kind,src_site_id,dst_kind,dst_site_id) VALUES ($1,'site',$2,'site',$3)`, org, srcSite, dstSite)
	return org, srcSite, dstSite
}

// TestPolicyRuleSiteSrcCascade — S8.2 cascade red: deleting the SOURCE site CASCADE-deletes its
// dependent src_kind='site' rules (no grant dangling against a vanished source site), mirroring the dst
// cascade discipline.
func TestPolicyRuleSiteSrcCascade(t *testing.T) {
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

	org, srcSite, _ := seedSiteSrcRule(t, ctx, pool)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	var before int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE src_site_id=$1`, srcSite).Scan(&before); err != nil || before != 1 {
		t.Fatalf("expected 1 site-src rule before delete, got %d (%v)", before, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM sites WHERE id=$1`, srcSite); err != nil {
		t.Fatalf("delete src site: %v", err)
	}
	var after int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE org_id=$1 AND src_kind='site'`, org).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != 0 {
		t.Fatalf("deleting the source site must CASCADE-delete its dependent rules, %d remain", after)
	}
}

// TestPolicyRuleSrcCheckAdditiveOnly — 0035's src_kind + src exactly-one CHECK widening is ADDITIVE
// ONLY: 'site' joined the allowed src kinds, and every OLD rejection still rejects.
func TestPolicyRuleSrcCheckAdditiveOnly(t *testing.T) {
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
	org, srcSite, dstSite := seedSiteSrcRule(t, ctx, pool) // valid site-src rule (site IS now an allowed source)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	rejects := func(name, sql string, args ...any) {
		if _, e := pool.Exec(ctx, sql, args...); e == nil {
			t.Fatalf("%s: expected a CHECK rejection (23514), got success — the widening LEAKED", name)
		}
	}
	// src_kind CHECK: an unknown source kind is STILL rejected (only 'site' was added).
	rejects("unknown src_kind", `INSERT INTO policy_rules (org_id,src_kind,src_site_id,dst_kind,dst_site_id) VALUES ($1,'bogus',$2,'site',$3)`, org, srcSite, dstSite)
	// exactly-one src CHECK: src_kind='site' with a NULL src_site_id is STILL rejected.
	rejects("site src, null site id", `INSERT INTO policy_rules (org_id,src_kind,src_site_id,dst_kind,dst_site_id) VALUES ($1,'site',NULL,'site',$2)`, org, dstSite)
	// exactly-one src CHECK: src_kind='site' with ALSO a group id set is STILL rejected (no contamination).
	rejects("site src + group id", `INSERT INTO policy_rules (org_id,src_kind,src_site_id,src_group_id,dst_kind,dst_site_id) VALUES ($1,'site',$2,$2,'site',$3)`, org, srcSite, dstSite)
}

// TestPolicyRuleSiteSrcMigrationUpDownUp — 0035 [7] red: the down-migration must survive a POPULATED
// src_kind='site' rule (whose src_group_id/src_user_id are NULL — the restored 2-kind src CHECK would
// abort on it unless the down purges site-src rows first). Migrates to EXACTLY 35 (the pins-version
// convention), isolated throwaway DB.
func TestPolicyRuleSiteSrcMigrationUpDownUp(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dbName := fmt.Sprintf("tnx_migtest_src_%d", time.Now().UnixNano())
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

	if err := db.MigrateTo(dsn, 35); err != nil {
		t.Fatalf("up: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect isolated: %v", err)
	}
	seedSiteSrcRule(t, ctx, pool)
	pool.Close()

	// DOWN: must NOT abort on the populated site-src rule (the [7] purge).
	if err := db.DownOne(dsn); err != nil {
		t.Fatalf("down 0035 with a populated site-src rule FAILED (the [7] class): %v", err)
	}
	if colExists("src_site_id") {
		t.Fatal("src_site_id must be gone after down")
	}
	// UP again to 0035 (up -> down -> up).
	if err := db.MigrateTo(dsn, 35); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	if !colExists("src_site_id") {
		t.Fatal("src_site_id must be back after re-up")
	}
}
