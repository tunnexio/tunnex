package db_test

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// TestAIUserGroupCostLimitsMigrationPostgres proves 0257 up, down and up again:
// a limit belongs to a group of the same organization, goes with the group,
// accepts NULL (no limit) and only values in (0, 100000].
func TestAIUserGroupCostLimitsMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(adminPool.Close)
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse admin DSN: %v", err)
	}
	name := "tnx_aicat1_limit_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop test database %s: %v", name, err)
		}
	})
	branchURL := *u
	branchURL.Path = "/" + name
	dsn := branchURL.String()
	if err := db.MigrateTo(dsn, 255); err != nil {
		t.Fatalf("migrate to 0255: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	refuse := func(what, q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err == nil {
			t.Fatalf("%s was accepted", what)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	table := `SELECT count(*) FROM information_schema.tables WHERE table_name='ai_user_group_cost_limits'`

	org, other, group, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'A',$2),($3,'B',$4)`, org, "a-"+org.String(), other, "b-"+other.String())
	exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Engineering'),($3,$4,'Elsewhere')`, group, org, foreign, other)

	if err := db.MigrateTo(dsn, 257); err != nil {
		t.Fatalf("migrate to 0257: %v", err)
	}
	insert := `INSERT INTO ai_user_group_cost_limits(org_id,group_id,daily_usd_threshold) VALUES($1,$2,$3)`
	refuse("a zero limit", insert, org, group, 0.0)
	refuse("a limit above 100000", insert, org, group, 100000.01)
	refuse("another organization's group", insert, org, foreign, 5.0)
	exec(insert, org, group, 100000.0)
	exec(`UPDATE ai_user_group_cost_limits SET daily_usd_threshold=NULL,revision=revision+1 WHERE org_id=$1 AND group_id=$2`, org, group)
	refuse("a second limit for one group", insert, org, group, 5.0)
	exec(`DELETE FROM user_groups WHERE org_id=$1 AND id=$2`, org, group)
	if n := count(`SELECT count(*) FROM ai_user_group_cost_limits WHERE org_id=$1`, org); n != 0 {
		t.Fatal("a deleted group kept its limit")
	}
	exec(insert, other, foreign, 5.0)

	if err := db.MigrateTo(dsn, 255); err != nil {
		t.Fatalf("migrate down to 0255: %v", err)
	}
	if n := count(table); n != 0 {
		t.Fatal("rolling back left the table")
	}
	if err := db.MigrateTo(dsn, 257); err != nil {
		t.Fatalf("migrate to 0257 again: %v", err)
	}
	if n := count(table); n != 1 {
		t.Fatal("migrating again did not create the table")
	}
}
