package agenttemplates

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

type testPusher struct{ calls int }

func (p *testPusher) PushOrgNodes(context.Context, uuid.UUID) { p.calls++ }

func TestObservableTemplateApplyPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for F09 service proof")
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
	name := "tnx_f09_service_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	dsn := *base
	dsn.Path = "/" + name
	if err := db.MigrateTo(dsn.String(), 100); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	org, actor, node := uuid.New(), uuid.New(), uuid.New()
	agentA, agentB, agentC, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode,agent_policy_templates_enabled) VALUES ($1,'F09 service',$2,'10.119.0.0/24','enforcing',true)`, org, "f09-service-"+org.String()[:8])
	exec(`INSERT INTO users (id,email,name) VALUES ($1,$2,'F09 owner')`, actor, "f09-service-"+actor.String()[:8]+"@example.test")
	exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, org, actor)
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'f09-gw',$3)`, node, org, "f09-"+node.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES
		($1,$2,$3,$4,'agent-a',$5,'10.119.0.2','active','agent'),
		($6,$2,$3,$4,'agent-b',$7,'10.119.0.3','active','agent'),
		($8,$2,$3,$4,'agent-c',$9,'10.119.0.4','active','agent')`, agentA, org, actor, node, "f09-a-"+agentA.String(), agentB, "f09-b-"+agentB.String(), agentC, "f09-c-"+agentC.String())
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol,port_low,port_high) VALUES ($1,$2,'db','10.50.0.0/24','tcp',5432,5432)`, resource, org)

	push := &testPusher{}
	svc := New(pool, push)
	group, err := svc.CreateGroup(ctx, org, actor, "workers", "managed workers")
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range []uuid.UUID{agentA, agentB} {
		changed, err := svc.AddMember(ctx, org, group.ID, device, actor)
		if err != nil || !changed {
			t.Fatalf("add %s changed=%v err=%v", device, changed, err)
		}
	}
	template, err := svc.CreateTemplate(ctx, org, actor, "database", "database access")
	if err != nil {
		t.Fatal(err)
	}
	version, err := svc.CreateVersion(ctx, org, template.ID, actor, []ItemInput{{DestinationKind: "resource", DestinationID: resource}})
	if err != nil {
		t.Fatal(err)
	}
	resourceRefs, err := sqlc.New(pool).CountAgentPolicyTemplateResourceReferences(ctx, sqlc.CountAgentPolicyTemplateResourceReferencesParams{OrgID: org, DstResourceID: pgtype.UUID{Bytes: resource, Valid: true}})
	if err != nil || resourceRefs != 1 {
		t.Fatalf("immutable destination references=%d err=%v", resourceRefs, err)
	}
	var writesBefore int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_policy_template_assignments`).Scan(&writesBefore); err != nil {
		t.Fatal(err)
	}
	preview, err := svc.Preview(ctx, org, group.ID, version.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.AffectedAgents != 2 || preview.CreatedRules != 1 || preview.ReusedRules != 0 || preview.ChangedGateways != 1 || len(preview.Added) != 2 || preview.Digest == "" {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	var writesAfter int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_policy_template_assignments`).Scan(&writesAfter); err != nil || writesAfter != writesBefore {
		t.Fatalf("preview mutated assignments before=%d after=%d err=%v", writesBefore, writesAfter, err)
	}
	result, err := svc.Apply(ctx, org, group.ID, version.ID, actor, preview.Digest, "f09-first-apply")
	if err != nil || result.AssignmentID == uuid.Nil || result.NoOp {
		t.Fatalf("apply result=%+v err=%v", result, err)
	}
	if push.calls != 1 {
		t.Fatalf("apply must wake policy once, got %d", push.calls)
	}
	q := sqlc.New(pool)
	snapshot, err := policy.BuildSnapshotWithQueries(ctx, q, org)
	if err != nil {
		t.Fatal(err)
	}
	compiled := policy.Compile(snapshot)
	if len(compiled[node].Allow) != 2 {
		t.Fatalf("two-agent group must compile two ordinary tuples: %+v", compiled[node].Allow)
	}
	for _, allow := range compiled[node].Allow {
		if allow.DstCIDR != "10.50.0.0/24" || allow.Protocol != "tcp" || allow.PortLow != 5432 || allow.PortHigh != 5432 {
			t.Fatalf("template must inherit destination-owned L4 scope: %+v", allow)
		}
	}
	replay, err := svc.Apply(ctx, org, group.ID, version.ID, actor, preview.Digest, "f09-first-apply")
	if err != nil || !replay.NoOp || replay.AssignmentID != result.AssignmentID || push.calls != 1 {
		t.Fatalf("idempotent replay=%+v pushes=%d err=%v", replay, push.calls, err)
	}
	if _, err := svc.AddMember(ctx, org, group.ID, agentC, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Apply(ctx, org, group.ID, version.ID, actor, preview.Digest, "f09-stale-apply"); !errors.Is(err, ErrStalePreview) {
		t.Fatalf("membership-changing stale preview must refuse, got %v", err)
	}
	var assignments, rules, bindings, audits int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM agent_policy_template_assignments),
		(SELECT count(*) FROM policy_rules WHERE src_kind='agent_group'),
		(SELECT count(*) FROM agent_policy_template_rule_bindings),
		(SELECT count(*) FROM audit_logs WHERE action='agent_policy_template.applied')`).Scan(&assignments, &rules, &bindings, &audits); err != nil {
		t.Fatal(err)
	}
	if assignments != 1 || rules != 1 || bindings != 1 || audits != 1 {
		t.Fatalf("failed/replayed apply changed state assignments=%d rules=%d bindings=%d audits=%d", assignments, rules, bindings, audits)
	}
	var managedRuleID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM policy_rules WHERE src_kind='agent_group'`).Scan(&managedRuleID); err != nil {
		t.Fatal(err)
	}
	policySvc := policy.NewService(pool)
	if err := policySvc.DeleteResource(ctx, org, resource); err == nil {
		t.Fatal("resource delete must refuse while an immutable template version references it")
	}
	if err := policySvc.DeletePolicyRule(ctx, org, managedRuleID, actor, "", ""); err == nil {
		t.Fatal("assignment-owned policy rule must refuse ordinary delete")
	}
	if _, err := policySvc.SetPolicyRuleEnabled(ctx, org, managedRuleID, false); err == nil {
		t.Fatal("assignment-owned policy rule must refuse ordinary disable")
	}
	if _, err := policySvc.ExtendGrant(ctx, org, managedRuleID, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("assignment-owned policy rule must refuse ordinary extension")
	}
	if _, err := svc.SetEnabled(ctx, org, actor, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("disable with live assignment must refuse, got %v", err)
	}
	updatedGroup, err := svc.UpdateGroup(ctx, org, group.ID, actor, "workers-renamed", "managed workers")
	if err != nil || updatedGroup.Name != "workers-renamed" {
		t.Fatalf("update group=%+v err=%v", updatedGroup, err)
	}
	updatedTemplate, err := svc.UpdateTemplate(ctx, org, template.ID, actor, "database-renamed", "database access")
	if err != nil || updatedTemplate.Name != "database-renamed" {
		t.Fatalf("update template=%+v err=%v", updatedTemplate, err)
	}
	impact, err := svc.RemoveMember(ctx, org, group.ID, agentC, actor)
	if err != nil || impact.Assignments != 1 || impact.GeneratedRules != 1 || impact.WithdrawnTuples != 1 || impact.ChangedGateways != 1 {
		t.Fatalf("remove member impact=%+v err=%v", impact, err)
	}
	if push.calls != 3 { // apply + member add + member remove
		t.Fatalf("member convergence pushes=%d", push.calls)
	}
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM policy_rules WHERE src_kind='agent_group'),(SELECT count(*) FROM agent_policy_template_rule_bindings)`).Scan(&rules, &bindings); err != nil || rules != 1 || bindings != 1 {
		t.Fatalf("member removal must not churn rules=%d bindings=%d err=%v", rules, bindings, err)
	}
	sharedTemplate, err := svc.CreateTemplate(ctx, org, actor, "database-shared", "same destination through another template")
	if err != nil {
		t.Fatal(err)
	}
	sharedVersion, err := svc.CreateVersion(ctx, org, sharedTemplate.ID, actor, []ItemInput{{DestinationKind: "resource", DestinationID: resource}})
	if err != nil {
		t.Fatal(err)
	}
	sharedPreview, err := svc.Preview(ctx, org, group.ID, sharedVersion.ID)
	if err != nil || sharedPreview.CreatedRules != 0 || sharedPreview.ReusedRules != 1 || sharedPreview.ChangedGateways != 0 {
		t.Fatalf("shared preview=%+v err=%v", sharedPreview, err)
	}
	sharedResult, err := svc.Apply(ctx, org, group.ID, sharedVersion.ID, actor, sharedPreview.Digest, "f09-shared-apply")
	if err != nil || sharedResult.AssignmentID == uuid.Nil || push.calls != 3 {
		t.Fatalf("shared apply=%+v pushes=%d err=%v", sharedResult, push.calls, err)
	}
	listed, err := svc.ListAssignments(ctx, org)
	if err != nil || len(listed) != 2 || listed[0].RuleCount != 1 || listed[1].RuleCount != 1 {
		t.Fatalf("assignment refetch=%+v err=%v", listed, err)
	}
	removed, err := svc.RemoveAssignment(ctx, org, result.AssignmentID, actor)
	if err != nil || removed.Assignments != 1 || removed.GeneratedRules != 0 || removed.WithdrawnTuples != 0 || removed.ChangedGateways != 0 {
		t.Fatalf("remove shared assignment impact=%+v err=%v", removed, err)
	}
	if push.calls != 3 {
		t.Fatalf("no-op shared assignment removal must not wake policy, pushes=%d", push.calls)
	}
	listed, err = svc.ListAssignments(ctx, org)
	if err != nil || len(listed) != 1 || listed[0].ID != sharedResult.AssignmentID {
		t.Fatalf("shared assignment must remain=%+v err=%v", listed, err)
	}
	removed, err = svc.RemoveAssignment(ctx, org, sharedResult.AssignmentID, actor)
	if err != nil || removed.GeneratedRules != 1 || removed.WithdrawnTuples != 2 || removed.ChangedGateways != 1 || push.calls != 4 {
		t.Fatalf("last assignment removal impact=%+v pushes=%d err=%v", removed, push.calls, err)
	}
	listed, err = svc.ListAssignments(ctx, org)
	if err != nil || len(listed) != 0 {
		t.Fatalf("final assignment removal refetch=%+v err=%v", listed, err)
	}
	if err := svc.ArchiveTemplate(ctx, org, template.ID, actor); err != nil {
		t.Fatalf("archive template after assignment removal: %v", err)
	}
	if err := svc.ArchiveTemplate(ctx, org, sharedTemplate.ID, actor); err != nil {
		t.Fatalf("archive shared template after assignment removal: %v", err)
	}
	if impact, err := svc.ArchiveGroup(ctx, org, group.ID, actor); !errors.Is(err, ErrConflict) || impact.Members != 2 || impact.Assignments != 0 {
		t.Fatalf("non-empty group archive impact=%+v err=%v", impact, err)
	}
	for _, device := range []uuid.UUID{agentA, agentB} {
		if _, err := svc.RemoveMember(ctx, org, group.ID, device, actor); err != nil {
			t.Fatalf("remove final member %s: %v", device, err)
		}
	}
	if _, err := svc.ArchiveGroup(ctx, org, group.ID, actor); err != nil {
		t.Fatalf("archive empty group: %v", err)
	}
	if _, err := svc.SetEnabled(ctx, org, actor, false); err != nil {
		t.Fatalf("disable after assignment removal: %v", err)
	}
	if _, err := svc.CreateGroup(ctx, org, actor, "disabled", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("transactional opt-in recheck must refuse mutation after disable, got %v", err)
	}
}
