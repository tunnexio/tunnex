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
	if err := db.MigrateTo(successDSN, 97); err != nil {
		t.Fatal(err)
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
	if err := db.MigrateTo(successDSN, 97); err != nil {
		t.Fatalf("0097 reapply: %v", err)
	}
	proveAgentPolicyTemplateTenantInvariants(t, ctx, successPool)

	refuseDSN, refusePool := newDB("refuse")
	if err := db.MigrateTo(refuseDSN, 97); err != nil {
		t.Fatal(err)
	}
	org, group := uuid.New(), uuid.New()
	if _, err := refusePool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,'F09 rollback',$2)`, org, "f09-"+org.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := refusePool.Exec(ctx, `INSERT INTO agent_groups (id,org_id,name) VALUES ($1,$2,'preserve-me')`, group, org); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(refuseDSN); err == nil {
		t.Fatal("0097 rollback must refuse while agent-group state exists")
	}
	var name string
	if err := refusePool.QueryRow(ctx, `SELECT name FROM agent_groups WHERE id=$1 AND org_id=$2`, group, org).Scan(&name); err != nil || name != "preserve-me" {
		t.Fatalf("refused rollback lost group name=%q err=%v", name, err)
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
	if err := pool.QueryRow(ctx, `INSERT INTO agent_policy_template_version_items (org_id,template_version_id,ordinal,dst_kind,dst_resource_id,protocol) VALUES ($1,$2,1,'resource',$3,'tcp') RETURNING id`, orgA, versionA, resourceA).Scan(&itemA); err != nil {
		t.Fatalf("tcp all-ports template item: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agent_policy_template_version_items (org_id,template_version_id,ordinal,dst_kind,dst_resource_id,protocol) VALUES ($1,$2,1,'resource',$3,'tcp') RETURNING id`, orgB, versionB, resourceB).Scan(&itemB); err != nil {
		t.Fatal(err)
	}

	digest := strings.Repeat("a", 64)
	reject("assignment version must belong to template", `INSERT INTO agent_policy_template_assignments (org_id,agent_group_id,template_id,template_version_id,preview_digest,applied_by_user_id) VALUES ($1,$2,$3,$4,$5,$6)`, orgA, groupA, templateA, versionA2, digest, userA)
	var assignmentA, assignmentB uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO agent_policy_template_assignments (org_id,agent_group_id,template_id,template_version_id,preview_digest,applied_by_user_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`, orgA, groupA, templateA, versionA, digest, userA).Scan(&assignmentA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agent_policy_template_assignments (org_id,agent_group_id,template_id,template_version_id,preview_digest,applied_by_user_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`, orgB, groupB, templateB, versionB, digest, userB).Scan(&assignmentB); err != nil {
		t.Fatal(err)
	}
	reject("previous assignment must share organization", `UPDATE agent_policy_template_assignments SET previous_assignment_id=$1 WHERE id=$2`, assignmentA, assignmentB)

	var ruleB uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO policy_rules (org_id,src_kind,src_agent_group_id,dst_kind,dst_resource_id) VALUES ($1,'agent_group',$2,'resource',$3) RETURNING id`, orgB, groupB, resourceB).Scan(&ruleB); err != nil {
		t.Fatal(err)
	}
	reject("binding rule must share organization", `INSERT INTO agent_policy_template_rule_bindings (org_id,assignment_id,template_version_item_id,policy_rule_id) VALUES ($1,$2,$3,$4)`, orgA, assignmentA, itemA, ruleB)
}
