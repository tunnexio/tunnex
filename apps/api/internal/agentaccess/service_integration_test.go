package agentaccess

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

type testPusher struct{ orgs []uuid.UUID }

func (p *testPusher) PushOrgNodes(_ context.Context, org uuid.UUID) { p.orgs = append(p.orgs, org) }

func TestAgentAccessRequestApprovalAndExpiryPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for F10 service proof")
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
	name := "tnx_f10_service_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	dsn := *base
	dsn.Path = "/" + name
	if err := db.MigrateTo(dsn.String(), 98); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	org, actor, node, agent, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode,agent_jit_access_enabled) VALUES ($1,'F10',$2,'10.120.0.0/24','enforcing',true)`, org, "f10-"+org.String()[:8])
	exec(`INSERT INTO users (id,email,name) VALUES ($1,$2,'F10 owner')`, actor, "f10-"+actor.String()[:8]+"@example.test")
	exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, org, actor)
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'f10-gw',$3)`, node, org, "f10-"+node.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent',$5,'10.120.0.2','active','agent')`, agent, org, actor, node, "f10-agent-"+agent.String())
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol,port_low,port_high) VALUES ($1,$2,'db','10.50.0.0/24','tcp',5432,5432)`, resource, org)

	push := &testPusher{}
	svc := New(pool, push)
	in := CreateInput{DeviceID: agent, Destination: Destination{Kind: "resource", ID: resource}, Reason: "deploy migration", Duration: MinDuration, IdempotencyKey: "create-1"}
	request, replay, err := svc.Create(ctx, org, actor, in)
	if err != nil || replay || request.State != "pending" {
		t.Fatalf("create state=%s replay=%v err=%v", request.State, replay, err)
	}
	var policyCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE org_id=$1`, org).Scan(&policyCount); err != nil || policyCount != 0 {
		t.Fatalf("pending changed policy count=%d err=%v", policyCount, err)
	}
	replayed, replay, err := svc.Create(ctx, org, actor, in)
	if err != nil || !replay || replayed.ID != request.ID {
		t.Fatalf("create replay id=%s replay=%v err=%v", replayed.ID, replay, err)
	}
	conflict := in
	conflict.Reason = "different"
	if _, _, err := svc.Create(ctx, org, actor, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting replay err=%v", err)
	}

	approved, replay, err := svc.Approve(ctx, org, request.ID, actor, "approve-1")
	if err != nil || replay || approved.State != "approved" || !approved.PolicyRuleID.Valid {
		t.Fatalf("approve state=%s replay=%v err=%v", approved.State, replay, err)
	}
	if len(push.orgs) != 1 || push.orgs[0] != org {
		t.Fatalf("approval pushes=%v", push.orgs)
	}
	var srcKind string
	var expires time.Time
	if err := pool.QueryRow(ctx, `SELECT src_kind,expires_at FROM policy_rules WHERE id=$1 AND org_id=$2`, approved.PolicyRuleID.Bytes, org).Scan(&srcKind, &expires); err != nil {
		t.Fatal(err)
	}
	if srcKind != "agent" || !expires.Equal(approved.ApprovedExpiresAt.Time) {
		t.Fatalf("rule src=%s expires=%s request=%s", srcKind, expires, approved.ApprovedExpiresAt.Time)
	}

	// Make the approved window due without waiting. Preserve the CHECK by moving
	// both approval and expiry into the past in their original order.
	exec(`UPDATE agent_access_requests SET approved_at=now()-interval '10 minutes',approved_expires_at=now()-interval '1 minute' WHERE id=$1`, request.ID)
	exec(`UPDATE policy_rules SET expires_at=now()-interval '1 minute' WHERE id=$1`, approved.PolicyRuleID.Bytes)
	deleted, err := sqlc.New(pool).DeleteExpiredGrants(ctx)
	if err != nil || len(deleted) != 0 {
		t.Fatalf("generic sweeper stole F10 rule rows=%d err=%v", len(deleted), err)
	}
	n, err := svc.SweepExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("F10 sweep rows=%d err=%v", n, err)
	}
	final, events, err := svc.Get(ctx, org, request.ID)
	if err != nil || final.State != "expired" || len(events) != 3 {
		t.Fatalf("final state=%s events=%d err=%v", final.State, len(events), err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE id=$1`, approved.PolicyRuleID.Bytes).Scan(&policyCount); err != nil || policyCount != 0 {
		t.Fatalf("expired rule count=%d err=%v", policyCount, err)
	}
	var eventCount, auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_access_request_events WHERE request_id=$1`, request.ID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action IN ('agent_access.requested','agent_access.approved','agent_access.expired')`, org).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 3 || auditCount != 3 {
		t.Fatalf("provenance events=%d audits=%d", eventCount, auditCount)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_access_request_events SET metadata='{"tampered":true}' WHERE request_id=$1`, request.ID); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("event ledger mutation err=%v", err)
	}
}
