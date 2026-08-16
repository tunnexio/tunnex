package agentaccess

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
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
	type createResult struct {
		row    sqlc.AgentAccessRequest
		replay bool
		err    error
	}
	results := make(chan createResult, 2)
	var start sync.WaitGroup
	start.Add(2)
	for range 2 {
		go func() {
			start.Done()
			start.Wait()
			row, replay, err := svc.Create(ctx, org, actor, in)
			results <- createResult{row: row, replay: replay, err: err}
		}()
	}
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.row.ID != second.row.ID || first.replay == second.replay {
		t.Fatalf("concurrent replay first=%s/%v/%v second=%s/%v/%v", first.row.ID, first.replay, first.err, second.row.ID, second.replay, second.err)
	}
	request := first.row
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
	policySvc := policy.NewService(pool)
	assertDestinationConflict := func(err error) {
		t.Helper()
		var domain *apierr.Error
		if !errors.As(err, &domain) || domain.Status != 409 || domain.Code != "agent_access_destination_in_use" {
			t.Fatalf("live destination delete err=%v", err)
		}
	}
	assertDestinationConflict(policySvc.DeleteResource(ctx, org, resource))
	assertManagedConflict := func(operation string, err error) {
		t.Helper()
		var domain *apierr.Error
		if !errors.As(err, &domain) || domain.Status != 409 || domain.Code != "agent_access_managed_rule" {
			t.Fatalf("%s managed-rule guard err=%v", operation, err)
		}
	}
	assertManagedConflict("delete", policySvc.DeletePolicyRule(ctx, org, approved.PolicyRuleID.Bytes, actor, "", ""))
	_, err = policySvc.SetPolicyRuleEnabled(ctx, org, approved.PolicyRuleID.Bytes, false)
	assertManagedConflict("disable", err)
	_, err = policySvc.ExtendGrant(ctx, org, approved.PolicyRuleID.Bytes, approved.ApprovedExpiresAt.Time.Add(time.Minute))
	assertManagedConflict("extend", err)
	var requestID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM agent_access_requests WHERE policy_rule_id=$1`, approved.PolicyRuleID.Bytes).Scan(&requestID); err != nil || requestID != request.ID {
		t.Fatalf("managed-rule request link=%s want=%s err=%v", requestID, request.ID, err)
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
	if err := policySvc.DeleteResource(ctx, org, resource); err != nil {
		t.Fatalf("terminal history blocked destination delete: %v", err)
	}
	if _, destinationName, err := svc.Describe(ctx, final); err != nil || destinationName != "db" {
		t.Fatalf("destination snapshot name=%q err=%v", destinationName, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_access_request_events SET metadata='{"tampered":true}' WHERE request_id=$1`, request.ID); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("event ledger mutation err=%v", err)
	}

	// Disable must lock the org before counting. A concurrent creator that
	// already holds the opt-in share lock commits first; disable then observes
	// the new pending row and refuses instead of leaving live state while off.
	resource2 := uuid.New()
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol,port_low,port_high) VALUES ($1,$2,'db-2','10.51.0.0/24','tcp',5432,5432)`, resource2, org)
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(ctx, `SELECT id FROM organizations WHERE id=$1 FOR SHARE`, org); err != nil {
		t.Fatal(err)
	}
	disableResult := make(chan error, 1)
	go func() { _, err := svc.SetEnabled(ctx, org, actor, false); disableResult <- err }()
	time.Sleep(100 * time.Millisecond)
	if _, err := blocker.Exec(ctx, `INSERT INTO agent_access_requests (org_id,device_id,dst_kind,dst_resource_id,reason,requested_duration_seconds,requested_by_user_id) VALUES ($1,$2,'resource',$3,'race proof',3600,$4)`, org, agent, resource2, actor); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-disableResult; !errors.Is(err, ErrConflict) {
		t.Fatalf("disable/create race err=%v", err)
	}

	resource3 := uuid.New()
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol,port_low,port_high) VALUES ($1,$2,'db-3','10.52.0.0/24','tcp',5432,5432)`, resource3, org)
	destinationCreator, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := destinationCreator.Exec(ctx, `SELECT id FROM resources WHERE id=$1 AND org_id=$2 FOR KEY SHARE`, resource3, org); err != nil {
		t.Fatal(err)
	}
	deleteResult := make(chan error, 1)
	go func() { deleteResult <- policySvc.DeleteResource(ctx, org, resource3) }()
	time.Sleep(100 * time.Millisecond)
	if _, err := destinationCreator.Exec(ctx, `INSERT INTO agent_access_requests (org_id,device_id,dst_kind,dst_resource_id,reason,requested_duration_seconds,requested_by_user_id) VALUES ($1,$2,'resource',$3,'delete race proof',3600,$4)`, org, agent, resource3, actor); err != nil {
		t.Fatal(err)
	}
	if err := destinationCreator.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertDestinationConflict(<-deleteResult)
	var destinationStillExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM resources WHERE id=$1 AND org_id=$2)`, resource3, org).Scan(&destinationStillExists); err != nil || !destinationStillExists {
		t.Fatalf("raced destination preserved=%v err=%v", destinationStillExists, err)
	}
}
