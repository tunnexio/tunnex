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

// TestSitesMigrationUpDownUpWithPopulatedRows is the S8.1 Slice-2 Condition-2 red: the sites
// down-migration must survive a POPULATED schema — a registered site + subnet + a node bound to it
// — instead of aborting on a live FK (the S7.5.4 [7] class: down-migrations fail on populated edge
// rows). It runs up -> insert -> down -> up on an ISOLATED throwaway database so it never mutates
// the shared test DB.
func TestSitesMigrationUpDownUpWithPopulatedRows(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// An isolated database — schema mutation (down/up) must never touch the shared test DB.
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

	tableExists := func(name string) bool {
		p, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer p.Close()
		var ok bool
		if err := p.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`, name).Scan(&ok); err != nil {
			t.Fatalf("exists %q: %v", name, err)
		}
		return ok
	}

	// UP to EXACTLY 0032 (not "latest" — a later migration must not change what DownOne rolls back).
	if err := db.MigrateTo(dsn, 32); err != nil {
		t.Fatalf("up: %v", err)
	}
	if !tableExists("sites") {
		t.Fatal("sites table must exist after up")
	}

	// POPULATE: org + site + subnet + a node BOUND to the site.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect isolated: %v", err)
	}
	org, site := uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug) VALUES ($1,'S','s-mig')`, org)
	ex(`INSERT INTO sites (id, org_id, name) VALUES ($1,$2,'hq')`, site, org)
	ex(`INSERT INTO site_subnets (id, site_id, cidr) VALUES ($1,$2,'10.10.0.0/24')`, uuid.New(), site)
	ex(`INSERT INTO nodes (id, org_id, name, cert_serial, site_id) VALUES ($1,$2,'gw','serial-mig',$3)`, uuid.New(), org, site)
	pool.Close()

	// DOWN: must NOT error on the populated site + subnet + bound node (the [7] class).
	if err := db.DownOne(dsn); err != nil {
		t.Fatalf("down with populated rows FAILED (the [7] class this test exists to catch): %v", err)
	}
	if tableExists("sites") {
		t.Fatal("sites table must be gone after down")
	}
	// nodes.site_id must be dropped too.
	p2, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	var col bool
	_ = p2.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='nodes' AND column_name='site_id')`).Scan(&col)
	p2.Close()
	if col {
		t.Fatal("nodes.site_id column must be dropped after down")
	}

	// UP again to 0032 (up -> down -> up).
	if err := db.MigrateTo(dsn, 32); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	if !tableExists("sites") {
		t.Fatal("sites table must be back after re-up")
	}
}
