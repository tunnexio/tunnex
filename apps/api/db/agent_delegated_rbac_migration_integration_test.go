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

func TestAgentDelegatedRBACMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run 0095 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	base, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}

	newDB := func(label string) (string, *pgxpool.Pool) {
		t.Helper()
		name := "tnx_f06_" + label + "_" + uuid.NewString()[:8]
		if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
		u := *base
		u.Path = "/" + name
		pool, err := pgxpool.New(ctx, u.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return u.String(), pool
	}

	successDSN, successPool := newDB("success")
	if err := db.MigrateTo(successDSN, 95); err != nil {
		t.Fatal(err)
	}
	org := uuid.New()
	if _, err := successPool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,'F06 rollback success',$2)`, org, "f06-ok-"+org.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(successDSN); err != nil {
		t.Fatalf("0095 empty rollback: %v", err)
	}
	var columnExists bool
	if err := successPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_profiles' AND column_name='managing_group_id')`).Scan(&columnExists); err != nil || columnExists {
		t.Fatalf("0095 down column exists=%v err=%v", columnExists, err)
	}
	if err := db.MigrateTo(successDSN, 95); err != nil {
		t.Fatalf("0095 reapply: %v", err)
	}
	if err := successPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_profiles' AND column_name='managing_group_id')`).Scan(&columnExists); err != nil || !columnExists {
		t.Fatalf("0095 reapplied column exists=%v err=%v", columnExists, err)
	}

	refuseDSN, refusePool := newDB("refuse")
	if err := db.MigrateTo(refuseDSN, 95); err != nil {
		t.Fatal(err)
	}
	owner, node, device, group := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	steps := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'F06 rollback refusal',$2,'10.118.0.0/24')`, []any{org, "f06-refuse-" + org.String()[:8]}},
		{`INSERT INTO users (id,email) VALUES ($1,$2)`, []any{owner, "f06-" + owner.String()[:8] + "@example.com"}},
		{`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, []any{org, owner}},
		{`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'f06-gw',$3)`, []any{node, org, "f06-" + node.String()}},
		{`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'f06-agent',$5,'10.118.0.2','active','agent')`, []any{device, org, owner, node, "f06-key-" + device.String()}},
		{`INSERT INTO agent_profiles (device_id) VALUES ($1)`, []any{device}},
		{`INSERT INTO user_groups (id,org_id,name) VALUES ($1,$2,'F06 managers')`, []any{group, org}},
		{`UPDATE agent_profiles SET managing_group_id=$2 WHERE device_id=$1`, []any{device, group}},
	}
	for _, step := range steps {
		if _, err := refusePool.Exec(ctx, step.sql, step.args...); err != nil {
			t.Fatalf("seed refusal: %v", err)
		}
	}
	var assignedGroup uuid.UUID
	if err := refusePool.QueryRow(ctx, `SELECT managing_group_id FROM agent_profiles WHERE device_id=$1`, device).Scan(&assignedGroup); err != nil || assignedGroup != group {
		t.Fatalf("refusal precondition assignment=%s err=%v", assignedGroup, err)
	}
	if err := db.DownOne(refuseDSN); err == nil {
		t.Fatal("0095 rollback must refuse while a managing-group assignment exists")
	}
	var preservedGroup uuid.UUID
	if err := refusePool.QueryRow(ctx, `SELECT managing_group_id FROM agent_profiles WHERE device_id=$1`, device).Scan(&preservedGroup); err != nil || preservedGroup != group {
		t.Fatalf("refused rollback assignment=%s err=%v", preservedGroup, err)
	}
	var deviceCount int
	if err := refusePool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE id=$1 AND deleted_at IS NULL`, device).Scan(&deviceCount); err != nil || deviceCount != 1 {
		t.Fatalf("refused rollback device count=%d err=%v", deviceCount, err)
	}
}
