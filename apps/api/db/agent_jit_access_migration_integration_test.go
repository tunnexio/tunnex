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

func TestAgentJITAccessMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run 0098 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
		name := "tnx_f10_migration_" + label + "_" + uuid.NewString()[:8]
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

	seedLegacyRule := func(pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) {
		t.Helper()
		org, actor, node, agent, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode) VALUES ($1,'F10 legacy',$2,'10.120.0.0/24','enforcing')`, []any{org, "f10-legacy-" + org.String()[:8]}},
			{`INSERT INTO users (id,email,name) VALUES ($1,$2,'F10 owner')`, []any{actor, "f10-" + actor.String()[:8] + "@example.test"}},
			{`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, []any{org, actor}},
			{`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'f10-gw',$3)`, []any{node, org, "f10-" + node.String()}},
			{`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent',$5,'10.120.0.2','active','agent')`, []any{agent, org, actor, node, "f10-agent-" + agent.String()}},
			{`INSERT INTO resources (id,org_id,name,cidr,protocol,port_low,port_high) VALUES ($1,$2,'db','10.50.0.0/24','tcp',5432,5432)`, []any{resource, org}},
		}
		for _, statement := range statements {
			if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
				t.Fatal(err)
			}
		}
		var rule uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO policy_rules (org_id,src_kind,src_device_id,dst_kind,dst_resource_id,expires_at) VALUES ($1,'agent',$2,'resource',$3,now()+interval '2 hours') RETURNING id`, org, agent, resource).Scan(&rule); err != nil {
			t.Fatal(err)
		}
		return org, actor, agent, resource, rule
	}

	successDSN, successPool := newDB("success")
	if err := db.MigrateTo(successDSN, 97); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, legacyRule := seedLegacyRule(successPool)
	var beforeExpiry time.Time
	if err := successPool.QueryRow(ctx, `SELECT expires_at FROM policy_rules WHERE id=$1`, legacyRule).Scan(&beforeExpiry); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateTo(successDSN, 98); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(successDSN); err != nil {
		t.Fatalf("0098 empty rollback: %v", err)
	}
	var afterExpiry time.Time
	if err := successPool.QueryRow(ctx, `SELECT expires_at FROM policy_rules WHERE id=$1`, legacyRule).Scan(&afterExpiry); err != nil || !afterExpiry.Equal(beforeExpiry) {
		t.Fatalf("empty rollback changed legacy expiry before=%s after=%s err=%v", beforeExpiry, afterExpiry, err)
	}
	if err := db.MigrateTo(successDSN, 98); err != nil {
		t.Fatalf("0098 reapply: %v", err)
	}

	refuseDSN, refusePool := newDB("refuse")
	if err := db.MigrateTo(refuseDSN, 98); err != nil {
		t.Fatal(err)
	}
	org, actor, agent, resource, existingRule := seedLegacyRule(refusePool)
	request := uuid.New()
	if _, err := refusePool.Exec(ctx, `INSERT INTO agent_access_requests (id,org_id,device_id,dst_kind,dst_resource_id,reason,requested_duration_seconds,requested_by_user_id) VALUES ($1,$2,$3,'resource',$4,'temporary deploy',3600,$5)`, request, org, agent, resource, actor); err != nil {
		t.Fatal(err)
	}
	var snapshot string
	if err := refusePool.QueryRow(ctx, `SELECT dst_name FROM agent_access_requests WHERE id=$1`, request).Scan(&snapshot); err != nil || snapshot != "db" {
		t.Fatalf("destination snapshot=%q err=%v", snapshot, err)
	}
	if _, err := refusePool.Exec(ctx, `UPDATE agent_access_requests SET dst_name='tampered' WHERE id=$1`, request); err == nil {
		t.Fatal("destination snapshot mutation must fail")
	}
	if _, err := refusePool.Exec(ctx, `INSERT INTO agent_access_request_events (org_id,request_id,state,actor_user_id) VALUES ($1,$2,'pending',$3)`, org, request, actor); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(refuseDSN); err == nil {
		t.Fatal("0098 rollback must refuse while F10 state exists")
	}
	var requests, events, rules int
	if err := refusePool.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_access_requests WHERE id=$1),(SELECT count(*) FROM agent_access_request_events WHERE request_id=$1),(SELECT count(*) FROM policy_rules WHERE id=$2)`, request, existingRule).Scan(&requests, &events, &rules); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || events != 1 || rules != 1 {
		t.Fatalf("refused rollback changed state requests=%d events=%d legacy_rules=%d", requests, events, rules)
	}
}
