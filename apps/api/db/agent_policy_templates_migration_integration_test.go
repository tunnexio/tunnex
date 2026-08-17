package db_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestAgentPolicyTemplatesMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run 0097 PostgreSQL proof")
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
		name := "tnx_f09_" + label + "_" + uuid.NewString()[:8]
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
	if err := db.MigrateTo(successDSN, 96); err != nil {
		t.Fatal(err)
	}
	legacyOrg, legacyUser, legacyNode := uuid.New(), uuid.New(), uuid.New()
	legacyDevice, legacyGroup, legacyResource := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode) VALUES ($1,'F09 legacy',$2,'10.118.0.0/24','enforcing')`, []any{legacyOrg, "f09-legacy-" + legacyOrg.String()[:8]}},
		{`INSERT INTO users (id,email,name) VALUES ($1,$2,'Legacy owner')`, []any{legacyUser, "f09-legacy-" + legacyUser.String()[:8] + "@example.test"}},
		{`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, []any{legacyOrg, legacyUser}},
		{`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'legacy-gw',$3)`, []any{legacyNode, legacyOrg, "f09-legacy-" + legacyNode.String()}},
		{`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'legacy-device',$5,'10.118.0.2','active','human')`, []any{legacyDevice, legacyOrg, legacyUser, legacyNode, "f09-device-" + legacyDevice.String()}},
		{`INSERT INTO user_groups (id,org_id,name) VALUES ($1,$2,'legacy-users')`, []any{legacyGroup, legacyOrg}},
		{`INSERT INTO group_members (org_id,group_id,user_id) VALUES ($1,$2,$3)`, []any{legacyOrg, legacyGroup, legacyUser}},
		{`INSERT INTO resources (id,org_id,name,cidr,protocol) VALUES ($1,$2,'legacy-db','10.60.0.0/24','tcp')`, []any{legacyResource, legacyOrg}},
		{`INSERT INTO policy_rules (org_id,src_kind,src_group_id,dst_kind,dst_resource_id) VALUES ($1,'group',$2,'resource',$3)`, []any{legacyOrg, legacyGroup, legacyResource}},
	} {
		if _, err := successPool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	legacyHash := func() string {
		t.Helper()
		snapshot, err := policy.BuildSnapshotWithQueries(ctx, sqlc.New(successPool), legacyOrg)
		if err != nil {
			t.Fatal(err)
		}
		return policyspec.CanonicalHash(policy.Compile(snapshot)[legacyNode])
	}
	if err := db.MigrateTo(successDSN, 98); err != nil {
		t.Fatal(err)
	}
	beforeHash := legacyHash()
	if err := db.DownOne(successDSN); err != nil {
		t.Fatalf("0098 empty rollback before 0097 proof: %v", err)
	}
	if err := db.DownOne(successDSN); err != nil {
		t.Fatalf("0097 empty rollback: %v", err)
	}
	var groupsExist, sourceColumnExists bool
	if err := successPool.QueryRow(ctx, `SELECT to_regclass('agent_groups') IS NOT NULL`).Scan(&groupsExist); err != nil || groupsExist {
		t.Fatalf("agent_groups after down exists=%v err=%v", groupsExist, err)
	}
	if err := successPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='policy_rules' AND column_name='src_agent_group_id')`).Scan(&sourceColumnExists); err != nil || sourceColumnExists {
		t.Fatalf("agent-group source after down exists=%v err=%v", sourceColumnExists, err)
	}
	var legacyRules int
	if err := successPool.QueryRow(ctx, `SELECT count(*) FROM policy_rules
		WHERE org_id=$1 AND src_kind='group' AND src_group_id=$2 AND dst_kind='resource' AND dst_resource_id=$3`,
		legacyOrg, legacyGroup, legacyResource).Scan(&legacyRules); err != nil || legacyRules != 1 {
		t.Fatalf("empty 0097 down changed the legacy rule row count=%d err=%v", legacyRules, err)
	}
	if err := db.MigrateTo(successDSN, 98); err != nil {
		t.Fatalf("0097 reapply: %v", err)
	}
	if afterUp := legacyHash(); afterUp != beforeHash {
		t.Fatalf("0097 reapply changed legacy compiled hash before=%s after=%s", beforeHash, afterUp)
	}
	proveAgentPolicyTemplateTenantInvariants(t, ctx, successPool)

	refuseDSN, refusePool := newDB("refuse")
	if err := db.MigrateTo(refuseDSN, 98); err != nil {
		t.Fatal(err)
	}
	proveAgentPolicyTemplateTenantInvariants(t, ctx, refusePool)
	var beforeGroups, beforeMembers, beforeTemplates, beforeVersions, beforeAssignments, beforeRules, beforeBindings int
	if err := refusePool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM agent_groups),
		(SELECT count(*) FROM agent_group_members),
		(SELECT count(*) FROM agent_policy_templates),
		(SELECT count(*) FROM agent_policy_template_versions),
		(SELECT count(*) FROM agent_policy_template_assignments),
		(SELECT count(*) FROM policy_rules WHERE src_kind='agent_group'),
		(SELECT count(*) FROM agent_policy_template_rule_bindings)`).Scan(
		&beforeGroups, &beforeMembers, &beforeTemplates, &beforeVersions,
		&beforeAssignments, &beforeRules, &beforeBindings,
	); err != nil {
		t.Fatal(err)
	}
	var beforeDigest, beforeIdempotency string
	if err := refusePool.QueryRow(ctx, `SELECT preview_digest,idempotency_key FROM agent_policy_template_assignments ORDER BY id LIMIT 1`).Scan(&beforeDigest, &beforeIdempotency); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(refuseDSN); err != nil {
		t.Fatalf("0098 empty rollback before 0097 refusal: %v", err)
	}
	if err := db.DownOne(refuseDSN); err == nil {
		t.Fatal("0097 rollback must refuse while F09 state exists")
	}
	var afterGroups, afterMembers, afterTemplates, afterVersions, afterAssignments, afterRules, afterBindings int
	if err := refusePool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM agent_groups),
		(SELECT count(*) FROM agent_group_members),
		(SELECT count(*) FROM agent_policy_templates),
		(SELECT count(*) FROM agent_policy_template_versions),
		(SELECT count(*) FROM agent_policy_template_assignments),
		(SELECT count(*) FROM policy_rules WHERE src_kind='agent_group'),
		(SELECT count(*) FROM agent_policy_template_rule_bindings)`).Scan(
		&afterGroups, &afterMembers, &afterTemplates, &afterVersions,
		&afterAssignments, &afterRules, &afterBindings,
	); err != nil {
		t.Fatal(err)
	}
	if beforeGroups != afterGroups || beforeMembers != afterMembers || beforeTemplates != afterTemplates ||
		beforeVersions != afterVersions || beforeAssignments != afterAssignments || beforeRules != afterRules || beforeBindings != afterBindings {
		t.Fatalf("refused rollback changed F09 rows before=%v after=%v",
			[]int{beforeGroups, beforeMembers, beforeTemplates, beforeVersions, beforeAssignments, beforeRules, beforeBindings},
			[]int{afterGroups, afterMembers, afterTemplates, afterVersions, afterAssignments, afterRules, afterBindings})
	}
	var afterDigest, afterIdempotency string
	if err := refusePool.QueryRow(ctx, `SELECT preview_digest,idempotency_key FROM agent_policy_template_assignments ORDER BY id LIMIT 1`).Scan(&afterDigest, &afterIdempotency); err != nil || afterDigest != beforeDigest || afterIdempotency != beforeIdempotency {
		t.Fatalf("refused rollback changed assignment proof digest=%q/%q idempotency=%q/%q err=%v", beforeDigest, afterDigest, beforeIdempotency, afterIdempotency, err)
	}
	if err := refusePool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='policy_rules' AND column_name='src_agent_group_id')`).Scan(&sourceColumnExists); err != nil || !sourceColumnExists {
		t.Fatalf("refused rollback lost source column=%v err=%v", sourceColumnExists, err)
	}
}

func proveAgentPolicyTemplateTenantInvariants(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	orgA, orgB := uuid.New(), uuid.New()
	userA, userB := uuid.New(), uuid.New()
	nodeA, nodeB := uuid.New(), uuid.New()
	agentA, humanA := uuid.New(), uuid.New()
	groupA, groupA2, groupB := uuid.New(), uuid.New(), uuid.New()
	templateA, templateA2, templateB := uuid.New(), uuid.New(), uuid.New()
	versionA, versionA2, versionB := uuid.New(), uuid.New(), uuid.New()
	resourceA, resourceB := uuid.New(), uuid.New()

	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	reject := func(label, query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err == nil {
			t.Fatalf("%s: expected database refusal", label)
		}
	}

	exec(`INSERT INTO organizations (id,name,slug) VALUES ($1,'F09 A',$2),($3,'F09 B',$4)`, orgA, "f09-a-"+orgA.String()[:8], orgB, "f09-b-"+orgB.String()[:8])
	exec(`INSERT INTO users (id,email,name) VALUES ($1,$2,'F09 A'),($3,$4,'F09 B')`, userA, "f09-a-"+userA.String()[:8]+"@example.test", userB, "f09-b-"+userB.String()[:8]+"@example.test")
	exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner'),($3,$4,'owner')`, orgA, userA, orgB, userB)
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'f09-a',$3),($4,$5,'f09-b',$6)`, nodeA, orgA, "f09-a-"+nodeA.String(), nodeB, orgB, "f09-b-"+nodeB.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES
		($1,$2,$3,$4,'agent-a',$5,'10.119.0.2','active','agent'),
		($6,$2,$3,$4,'human-a',$7,'10.119.0.3','active','human')`, agentA, orgA, userA, nodeA, "f09-agent-"+agentA.String(), humanA, "f09-human-"+humanA.String())
	exec(`INSERT INTO agent_groups (id,org_id,name) VALUES ($1,$2,'A'),($3,$2,'A2'),($4,$5,'B')`, groupA, orgA, groupA2, groupB, orgB)
	exec(`INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$4)`, orgA, groupA, agentA, userA)
	reject("human devices are not agent-group members", `INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$4)`, orgA, groupA2, humanA, userA)
	reject("cross-tenant actors cannot add members", `INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$4)`, orgA, groupA2, agentA, userB)

	exec(`INSERT INTO agent_policy_templates (id,org_id,name) VALUES ($1,$2,'A'),($3,$2,'A2'),($4,$5,'B')`, templateA, orgA, templateA2, templateB, orgB)
	exec(`INSERT INTO agent_policy_template_versions (id,org_id,template_id,version,created_by_user_id) VALUES ($1,$2,$3,1,$4),($5,$2,$6,1,$4),($7,$8,$9,1,$10)`, versionA, orgA, templateA, userA, versionA2, templateA2, versionB, orgB, templateB, userB)
	reject("cross-tenant actors cannot version templates", `INSERT INTO agent_policy_template_versions (org_id,template_id,version,created_by_user_id) VALUES ($1,$2,2,$3)`, orgA, templateA, userB)
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol) VALUES ($1,$2,'all-a','10.10.0.0/24','tcp'),($3,$4,'all-b','10.20.0.0/24','tcp')`, resourceA, orgA, resourceB, orgB)
	var itemA, itemB uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO agent_policy_template_version_items (org_id,template_version_id,ordinal,dst_kind,dst_resource_id) VALUES ($1,$2,1,'resource',$3) RETURNING id`, orgA, versionA, resourceA).Scan(&itemA); err != nil {
		t.Fatalf("destination-owned L4 template item: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agent_policy_template_version_items (org_id,template_version_id,ordinal,dst_kind,dst_resource_id) VALUES ($1,$2,1,'resource',$3) RETURNING id`, orgB, versionB, resourceB).Scan(&itemB); err != nil {
		t.Fatal(err)
	}

	digest := strings.Repeat("a", 64)
	reject("assignment version must belong to template", `INSERT INTO agent_policy_template_assignments (org_id,agent_group_id,template_id,template_version_id,preview_digest,idempotency_key,applied_by_user_id) VALUES ($1,$2,$3,$4,$5,'bad-version',$6)`, orgA, groupA, templateA, versionA2, digest, userA)
	var assignmentA, assignmentB uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO agent_policy_template_assignments (org_id,agent_group_id,template_id,template_version_id,preview_digest,idempotency_key,applied_by_user_id) VALUES ($1,$2,$3,$4,$5,'assignment-a',$6) RETURNING id`, orgA, groupA, templateA, versionA, digest, userA).Scan(&assignmentA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agent_policy_template_assignments (org_id,agent_group_id,template_id,template_version_id,preview_digest,idempotency_key,applied_by_user_id) VALUES ($1,$2,$3,$4,$5,'assignment-b',$6) RETURNING id`, orgB, groupB, templateB, versionB, digest, userB).Scan(&assignmentB); err != nil {
		t.Fatal(err)
	}
	reject("previous assignment must share organization", `UPDATE agent_policy_template_assignments SET previous_assignment_id=$1 WHERE id=$2`, assignmentA, assignmentB)

	var ruleB uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO policy_rules (org_id,src_kind,src_agent_group_id,dst_kind,dst_resource_id) VALUES ($1,'agent_group',$2,'resource',$3) RETURNING id`, orgB, groupB, resourceB).Scan(&ruleB); err != nil {
		t.Fatal(err)
	}
	reject("binding rule must share organization", `INSERT INTO agent_policy_template_rule_bindings (org_id,assignment_id,template_version_item_id,policy_rule_id) VALUES ($1,$2,$3,$4)`, orgA, assignmentA, itemA, ruleB)
}
