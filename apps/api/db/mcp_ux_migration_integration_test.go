package db_test

import (
	"context"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// TestMCPUXMigrationsPostgres proves 0251 to 0255 against real PostgreSQL:
//
//   - 0251: MCP is turned on for every organization that had agent groups and policy templates on, and for
//     no other;
//   - 0252: every profile gets a unique server name, an older control plane that sends none still creates a
//     usable profile, an agent may have several servers, and rolling back refuses while one does;
//   - 0253: the latest per-agent policy keeps deciding for the endpoints it covers, step-up requests and
//     activity record which policy decided, and the new tables hold their invariants;
//   - 0254: a pending approval is an alert event;
//   - 0255: an existing runtime has declared nothing.
func TestMCPUXMigrationsPostgres(t *testing.T) {
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
	// Registered first so it runs last: the database drop below still needs this pool.
	t.Cleanup(adminPool.Close)
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse admin DSN: %v", err)
	}
	name := "tnx_aiux1_mcp_" + uuid.NewString()[:8]
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
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := db.MigrateTo(dsn, 250); err != nil {
		t.Fatalf("migrate to 0250: %v", err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	refuse := func(why, query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err == nil {
			t.Fatalf("%s: the write was accepted", why)
		}
	}
	text := func(query string, args ...any) string {
		t.Helper()
		var out string
		if err := pool.QueryRow(ctx, query, args...).Scan(&out); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return out
	}
	count := func(query string, args ...any) int {
		t.Helper()
		var out int
		if err := pool.QueryRow(ctx, query, args...).Scan(&out); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return out
	}
	endpoints := func(deviceID uuid.UUID, version int) []string {
		t.Helper()
		var out []string
		if err := pool.QueryRow(ctx, `SELECT override_endpoints FROM agent_mcp_tool_policy_versions WHERE device_id=$1 AND version=$2`, deviceID, version).Scan(&out); err != nil {
			t.Fatalf("override_endpoints of %s v%d: %v", deviceID, version, err)
		}
		return out
	}

	const (
		assignedEndpoint = "http://172.30.0.10:9000/mcp"
		formerEndpoint   = "http://172.30.0.11:9000/mcp"
		secondEndpoint   = "http://172.30.0.12:9000/mcp"
	)

	// Two organizations: one had agent groups and policy templates on, one did not.
	templatesOn, templatesOff := uuid.New(), uuid.New()
	user, node := uuid.New(), uuid.New()
	assigned, emptyPolicy, unassigned := uuid.New(), uuid.New(), uuid.New()
	group, otherGroup := uuid.New(), uuid.New()
	acme, acmeTwin, reserved, symbols, archived := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,agent_policy_templates_enabled) VALUES ($1,'0251-on',$2,'10.97.0.0/24',true)`, templatesOn, "u0251a-"+templatesOn.String()[:8])
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'0251-off',$2,'10.98.0.0/24')`, templatesOff, "u0251b-"+templatesOff.String()[:8])
	exec(`INSERT INTO users (id,email) VALUES ($1,$2)`, user, "u0251-"+user.String()[:8]+"@example.com")
	exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, templatesOn, user)
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES ($1,$2,'u0251-gw',$3,'c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=','gw.example:51820','active')`, node, templatesOn, "serial-"+node.String())
	for i, device := range []uuid.UUID{assigned, emptyPolicy, unassigned} {
		exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,$5,$6,$7::inet,'active','agent')`,
			device, templatesOn, user, node, "u0251-agent-"+device.String()[:8], "u0251-key-"+device.String(), "10.97.0."+string(rune('2'+i)))
	}
	exec(`INSERT INTO agent_groups (id,org_id,name) VALUES ($1,$2,'u0251-group'),($3,$2,'u0251-other')`, group, templatesOn, otherGroup)
	exec(`INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$5),($1,$2,$4,$5)`, templatesOn, group, assigned, emptyPolicy, user)
	// Display names that collapse to the same server name, the reserved one, one with no usable character,
	// and an archived profile.
	exec(`INSERT INTO agent_mcp_profiles (id,org_id,name,endpoint,created_at) VALUES ($1,$2,'Acme MCP',$3,now()-interval '5 minutes')`, acme, templatesOn, assignedEndpoint)
	exec(`INSERT INTO agent_mcp_profiles (id,org_id,name,endpoint,created_at) VALUES ($1,$2,'acme_mcp',$3,now()-interval '4 minutes')`, acmeTwin, templatesOn, secondEndpoint)
	exec(`INSERT INTO agent_mcp_profiles (id,org_id,name,endpoint,created_at) VALUES ($1,$2,'MCP','http://172.30.0.13:9000/mcp',now()-interval '3 minutes')`, reserved, templatesOn)
	exec(`INSERT INTO agent_mcp_profiles (id,org_id,name,endpoint,created_at) VALUES ($1,$2,'***','http://172.30.0.14:9000/mcp',now()-interval '2 minutes')`, symbols, templatesOn)
	exec(`INSERT INTO agent_mcp_profiles (id,org_id,name,endpoint,created_at,archived_at) VALUES ($1,$2,'Acme.MCP','http://172.30.0.15:9000/mcp',now()-interval '1 minute',now())`, archived, templatesOn)
	exec(`INSERT INTO agent_mcp_profile_assignments (org_id,profile_id,agent_group_id) VALUES ($1,$2,$3)`, templatesOn, acme, group)

	// Per-agent policies as they exist today. `assigned` has an older version and a latest one whose rules
	// name an endpoint it is no longer assigned; `emptyPolicy` has a deny-all policy; `unassigned` is in no
	// group and has a deny-all policy.
	rule := func(endpoint string) string {
		return `[{"endpoint":"` + endpoint + `","server_name":"acme","tool_name":"list_customers","input_schema_hash":"h"}]`
	}
	exec(`INSERT INTO agent_mcp_tool_policy_versions (org_id,device_id,version,rules,inventory_observed_at,created_by_user_id) VALUES ($1,$2,1,$3::jsonb,now(),$4)`, templatesOn, assigned, rule(assignedEndpoint), user)
	exec(`INSERT INTO agent_mcp_tool_policy_versions (org_id,device_id,version,rules,inventory_observed_at,created_by_user_id) VALUES ($1,$2,2,$3::jsonb,now(),$4)`, templatesOn, assigned, rule(formerEndpoint), user)
	exec(`INSERT INTO agent_mcp_tool_policy_versions (org_id,device_id,version,rules,inventory_observed_at,created_by_user_id) VALUES ($1,$2,1,'[]',now(),$3)`, templatesOn, emptyPolicy, user)
	exec(`INSERT INTO agent_mcp_tool_policy_versions (org_id,device_id,version,rules,inventory_observed_at,created_by_user_id) VALUES ($1,$2,1,'[]',now(),$3)`, templatesOn, unassigned, user)

	const approvalColumns = `org_id,device_id,policy_version,endpoint,server_name,tool_name,input_schema_hash,request_digest,expires_at`
	const approvalValues = `$1,$2,2,'` + assignedEndpoint + `','acme','refund_order','h',repeat('a',64),now()+interval '5 minutes'`
	exec(`INSERT INTO agent_mcp_tool_approval_requests (`+approvalColumns+`) VALUES (`+approvalValues+`)`, templatesOn, assigned)
	exec(`INSERT INTO agent_mcp_tool_activity (org_id,device_id,node_id,endpoint,server_name,method,tool_name,decision,policy_version)
		VALUES ($1,$2,$3,$4,'acme','tools/call','list_customers','allow',2)`, templatesOn, assigned, node, assignedEndpoint)
	exec(`INSERT INTO agent_mcp_tool_activity (org_id,device_id,endpoint,method,tool_name,decision,reason,result_status)
		VALUES ($1,$2,$3,'tools/call','run_sql','deny','no_profile','not_forwarded')`, templatesOn, unassigned, assignedEndpoint)
	exec(`INSERT INTO agent_runtime_state (device_id) VALUES ($1) ON CONFLICT DO NOTHING`, assigned)

	if err := db.MigrateTo(dsn, 255); err != nil {
		t.Fatalf("migrate to 0255: %v", err)
	}

	// 0251: MCP follows the switch it used to depend on.
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM organization_mcp_settings WHERE org_id=$1`, templatesOn).Scan(&enabled); err != nil || !enabled {
		t.Fatalf("an organization with agent policy templates on must get MCP on (enabled=%v, err=%v)", enabled, err)
	}
	if n := count(`SELECT count(*) FROM organization_mcp_settings WHERE org_id=$1`, templatesOff); n != 0 {
		t.Fatal("an organization with agent policy templates off must not get MCP turned on")
	}

	// 0252: server names. The oldest profile keeps the plain name.
	for id, want := range map[uuid.UUID]string{acme: "acme-mcp", acmeTwin: "acme-mcp-2", reserved: "mcp-server", symbols: "server", archived: "acme-mcp"} {
		if got := text(`SELECT server_name FROM agent_mcp_profiles WHERE id=$1`, id); got != want {
			t.Fatalf("server name of profile %s = %q, want %q", id, got, want)
		}
	}
	// A control plane that sends no name (the previous version) still creates a usable profile.
	if got := text(`INSERT INTO agent_mcp_profiles (org_id,name,endpoint) VALUES ($1,'Billing Tools','http://172.30.0.16:9000/mcp') RETURNING server_name`, templatesOn); got != "billing-tools" {
		t.Fatalf("derived server name = %q, want billing-tools", got)
	}
	if got := text(`INSERT INTO agent_mcp_profiles (org_id,name,endpoint) VALUES ($1,'ACME-MCP!','http://172.30.0.17:9000/mcp') RETURNING server_name`, templatesOn); got != "acme-mcp-3" {
		t.Fatalf("derived server name for a taken slug = %q, want acme-mcp-3", got)
	}
	// The same name in another organization is free.
	if got := text(`INSERT INTO agent_mcp_profiles (org_id,name,endpoint) VALUES ($1,'Acme MCP','http://172.30.0.18:9000/mcp') RETURNING server_name`, templatesOff); got != "acme-mcp" {
		t.Fatalf("server name in another organization = %q, want acme-mcp", got)
	}
	refuse("a server name another active profile has", `INSERT INTO agent_mcp_profiles (org_id,name,endpoint,server_name) VALUES ($1,'duplicate','http://172.30.0.19:9000/mcp','acme-mcp')`, templatesOn)
	refuse("the reserved server name", `INSERT INTO agent_mcp_profiles (org_id,name,endpoint,server_name) VALUES ($1,'reserved','http://172.30.0.19:9000/mcp','mcp')`, templatesOn)
	refuse("a server name with characters a path cannot carry", `INSERT INTO agent_mcp_profiles (org_id,name,endpoint,server_name) VALUES ($1,'shouting','http://172.30.0.19:9000/mcp','Acme/Tools')`, templatesOn)

	// 0253: the latest per-agent policy keeps deciding for what it covers; older versions are untouched.
	if got := endpoints(assigned, 2); !reflect.DeepEqual(got, []string{assignedEndpoint, formerEndpoint}) {
		t.Fatalf("latest policy of an assigned agent overrides %v, want its assigned endpoint and the endpoint its rules name", got)
	}
	if got := endpoints(assigned, 1); len(got) != 0 {
		t.Fatalf("an older policy version overrides %v, want nothing", got)
	}
	if got := endpoints(emptyPolicy, 1); !reflect.DeepEqual(got, []string{assignedEndpoint}) {
		t.Fatalf("a deny-all policy of an assigned agent overrides %v, want its assigned endpoint so it keeps denying", got)
	}
	if got := endpoints(unassigned, 1); len(got) != 0 {
		t.Fatalf("a deny-all policy of an agent with no server overrides %v, want nothing", got)
	}
	// A policy written by the previous control plane names no override.
	exec(`INSERT INTO agent_mcp_tool_policy_versions (org_id,device_id,version,rules,inventory_observed_at,created_by_user_id) VALUES ($1,$2,3,'[]',now(),$3)`, templatesOn, assigned, user)
	if got := endpoints(assigned, 3); len(got) != 0 {
		t.Fatalf("a new version with no stated override overrides %v, want nothing", got)
	}

	// Existing step-up requests and activity were decided under the per-agent policy.
	if got := text(`SELECT policy_source FROM agent_mcp_tool_approval_requests WHERE device_id=$1`, assigned); got != "agent" {
		t.Fatalf("existing approval policy_source = %q, want agent", got)
	}
	if got := text(`SELECT policy_source FROM agent_mcp_tool_activity WHERE device_id=$1`, assigned); got != "agent" {
		t.Fatalf("existing activity policy_source = %q, want agent", got)
	}
	if n := count(`SELECT count(*) FROM agent_mcp_tool_activity WHERE device_id=$1 AND policy_source IS NULL`, unassigned); n != 1 {
		t.Fatal("activity with no policy version must name no policy source")
	}
	// The same call identity is still one live request, but a group policy's version 2 is a different one.
	refuse("a second live request for the same call under the same policy", `INSERT INTO agent_mcp_tool_approval_requests (`+approvalColumns+`) VALUES (`+approvalValues+`)`, templatesOn, assigned)
	exec(`INSERT INTO agent_mcp_tool_approval_requests (`+approvalColumns+`,policy_source,policy_group_id) VALUES (`+approvalValues+`,'group',$3)`, templatesOn, assigned, group)
	refuse("a second live request for the same call under the same group policy", `INSERT INTO agent_mcp_tool_approval_requests (`+approvalColumns+`,policy_source,policy_group_id) VALUES (`+approvalValues+`,'group',$3)`, templatesOn, assigned, group)
	exec(`INSERT INTO agent_mcp_tool_approval_requests (`+approvalColumns+`,policy_source,policy_group_id) VALUES (`+approvalValues+`,'group',$3)`, templatesOn, assigned, otherGroup)
	refuse("a per-agent request that names a group", `INSERT INTO agent_mcp_tool_approval_requests (`+approvalColumns+`,policy_source,policy_group_id) VALUES ($1,$2,9,'e','s','t','h',repeat('b',64),now()+interval '5 minutes','agent',$3)`, templatesOn, assigned, group)
	refuse("an unknown policy source", `UPDATE agent_mcp_tool_approval_requests SET policy_source='elsewhere' WHERE device_id=$1`, assigned)
	refuse("activity that names a group without a group policy", `UPDATE agent_mcp_tool_activity SET policy_group_id=$2 WHERE device_id=$1`, unassigned, group)
	exec(`UPDATE agent_mcp_tool_activity SET policy_source='group', policy_group_id=$2 WHERE device_id=$1`, assigned, group)

	// Group policy versions and tool markers.
	exec(`INSERT INTO agent_group_mcp_tool_policy_versions (org_id,agent_group_id,profile_id,version,rules,inventory_observed_at,created_by_user_id) VALUES ($1,$2,$3,1,$4::jsonb,now(),$5)`, templatesOn, group, acme, rule(assignedEndpoint), user)
	refuse("a repeated group policy version", `INSERT INTO agent_group_mcp_tool_policy_versions (org_id,agent_group_id,profile_id,version,rules,inventory_observed_at,created_by_user_id) VALUES ($1,$2,$3,1,'[]',now(),$4)`, templatesOn, group, acme, user)
	refuse("group policy rules that are not a list", `INSERT INTO agent_group_mcp_tool_policy_versions (org_id,agent_group_id,profile_id,version,rules,inventory_observed_at,created_by_user_id) VALUES ($1,$2,$3,2,'{}',now(),$4)`, templatesOn, group, acme, user)
	refuse("a group policy for another organization's group", `INSERT INTO agent_group_mcp_tool_policy_versions (org_id,agent_group_id,profile_id,version,rules,inventory_observed_at,created_by_user_id) VALUES ($1,$2,$3,1,'[]',now(),$4)`, templatesOff, group, acme, user)
	exec(`INSERT INTO agent_mcp_tool_markers (org_id,profile_id,tool_name,effect,set_by_user_id) VALUES ($1,$2,'refund_order','destructive',$3)`, templatesOn, acme, user)
	refuse("an unknown tool effect", `INSERT INTO agent_mcp_tool_markers (org_id,profile_id,tool_name,effect) VALUES ($1,$2,'list_customers','harmless')`, templatesOn, acme)
	refuse("a second marker for one tool", `INSERT INTO agent_mcp_tool_markers (org_id,profile_id,tool_name,effect) VALUES ($1,$2,'refund_order','reads')`, templatesOn, acme)

	// Connection previews: read through exactly one of an agent or a group.
	exec(`INSERT INTO agent_mcp_connection_previews (org_id,endpoint,via_device_id,node_id,expires_at) VALUES ($1,$2,$3,$4,now()+interval '2 minutes')`, templatesOn, secondEndpoint, assigned, node)
	exec(`INSERT INTO agent_mcp_connection_previews (org_id,endpoint,via_group_id,expires_at) VALUES ($1,$2,$3,now()+interval '2 minutes')`, templatesOn, secondEndpoint, group)
	refuse("a preview through both an agent and a group", `INSERT INTO agent_mcp_connection_previews (org_id,endpoint,via_device_id,via_group_id,expires_at) VALUES ($1,$2,$3,$4,now()+interval '2 minutes')`, templatesOn, secondEndpoint, assigned, group)
	refuse("a preview through neither", `INSERT INTO agent_mcp_connection_previews (org_id,endpoint,expires_at) VALUES ($1,$2,now()+interval '2 minutes')`, templatesOn, secondEndpoint)
	refuse("an unknown preview state", `UPDATE agent_mcp_connection_previews SET state='done'`)
	refuse("preview tools that are not a list", `UPDATE agent_mcp_connection_previews SET tools='{}'`)

	// 0254: the new event key is accepted by all four alert tables; the inbox has its index.
	for _, table := range []string{"alert_subscriptions", "alert_deliveries", "alert_delivery_cooldowns", "alert_occurrences"} {
		def := text(`SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid WHERE r.relname=$1 AND c.conname=$2`, table, table+"_event_key_check")
		if !strings.Contains(def, "agent.mcp_approval_pending") || !strings.Contains(def, "ipsec.status_unavailable") {
			t.Fatalf("%s must accept agent.mcp_approval_pending and keep every earlier key: %s", table, def)
		}
	}
	if n := count(`SELECT count(*) FROM pg_indexes WHERE indexname='agent_mcp_tool_approval_requests_org_pending_idx'`); n != 1 {
		t.Fatal("the organization-wide pending approvals index is missing")
	}

	// 0255: an existing runtime has declared nothing.
	if n := count(`SELECT count(*) FROM agent_runtime_state WHERE device_id=$1 AND mcp_hold_capable_at IS NULL AND tunnel_dns_applied IS NULL`, assigned); n != 1 {
		t.Fatal("an existing runtime must not be marked as holding calls or as having reported its DNS")
	}

	// Several servers: a second server on the same group, and one agent in two groups with different servers.
	var secondAssignment uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO agent_mcp_profile_assignments (org_id,profile_id,agent_group_id) VALUES ($1,$2,$3) RETURNING id`, templatesOn, acmeTwin, group).Scan(&secondAssignment); err != nil {
		t.Fatalf("a group must accept a second MCP server: %v", err)
	}
	refuse("the same server assigned to the same group twice", `INSERT INTO agent_mcp_profile_assignments (org_id,profile_id,agent_group_id) VALUES ($1,$2,$3)`, templatesOn, acmeTwin, group)
	exec(`INSERT INTO agent_mcp_profile_assignments (org_id,profile_id,agent_group_id) VALUES ($1,$2,$3)`, templatesOn, reserved, otherGroup)
	exec(`INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$4)`, templatesOn, otherGroup, assigned, user)

	// Rolling back 0252 refuses while an agent has more than one server, and changes nothing.
	down, err := os.ReadFile("migrations/0252_mcp_multi_server.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tryDown := func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, string(down))
		return err
	}
	if err := tryDown(); err == nil || !strings.Contains(err.Error(), "cannot roll back 0252: an agent has more than one MCP server") {
		t.Fatalf("0252 down with an agent on several servers: %v, want a refusal", err)
	}
	// One agent, one server each, but a group that still holds two servers and has no members.
	exec(`DELETE FROM agent_group_members WHERE agent_group_id=$1`, group)
	if err := tryDown(); err == nil || !strings.Contains(err.Error(), "cannot roll back 0252: an agent group has more than one MCP server") {
		t.Fatalf("0252 down with a group on several servers: %v, want a refusal", err)
	}
	if n := count(`SELECT count(*) FROM information_schema.columns WHERE table_name='agent_mcp_profiles' AND column_name='server_name'`); n != 1 {
		t.Fatal("a refused rollback must leave the schema as it was")
	}

	// With one server per group and per agent the rollback goes through and restores the old rules.
	exec(`UPDATE agent_mcp_profile_assignments SET state='unassigned', ended_at=now() WHERE id=$1`, secondAssignment)
	if err := db.MigrateTo(dsn, 250); err != nil {
		t.Fatalf("roll back to 0250: %v", err)
	}
	version, dirty, ok, err := db.Version(dsn)
	if err != nil || !ok || dirty || version != 250 {
		t.Fatalf("clean down must return to 0250, version=%d dirty=%v ok=%v err=%v", version, dirty, ok, err)
	}
	if n := count(`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('organization_mcp_settings','agent_group_mcp_tool_policy_versions','agent_mcp_tool_markers','agent_mcp_connection_previews')`); n != 0 {
		t.Fatalf("rolling back left %d table(s)", n)
	}
	if n := count(`SELECT count(*) FROM information_schema.columns WHERE
		(table_name='agent_mcp_profiles' AND column_name='server_name') OR
		(table_name='agent_mcp_tool_policy_versions' AND column_name='override_endpoints') OR
		(table_name IN ('agent_mcp_tool_approval_requests','agent_mcp_tool_activity') AND column_name IN ('policy_source','policy_group_id')) OR
		(table_name='agent_runtime_state' AND column_name IN ('mcp_hold_capable_at','tunnel_dns_applied'))`); n != 0 {
		t.Fatalf("rolling back left %d column(s)", n)
	}
	if n := count(`SELECT count(*) FROM pg_proc WHERE proname IN ('agent_mcp_server_slug','agent_mcp_free_server_name','agent_mcp_profile_default_server_name')`); n != 0 {
		t.Fatalf("rolling back left %d function(s)", n)
	}
	// Requests decided under a group policy end at the rollback; the per-agent one is still live.
	if n := count(`SELECT count(*) FROM agent_mcp_tool_approval_requests WHERE device_id=$1 AND state='pending'`, assigned); n != 1 {
		t.Fatalf("after rollback %d request(s) are pending, want only the per-agent one", n)
	}
	// One server per agent is a rule again.
	refuse("a second server for one group after rollback", `INSERT INTO agent_mcp_profile_assignments (org_id,profile_id,agent_group_id) VALUES ($1,$2,$3)`, templatesOn, symbols, group)
	refuse("a second server for one agent after rollback", `INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$4)`, templatesOn, group, assigned, user)

	if err := db.MigrateTo(dsn, 255); err != nil {
		t.Fatalf("migrate to 0255 again: %v", err)
	}
	if got := text(`SELECT server_name FROM agent_mcp_profiles WHERE id=$1`, acme); got != "acme-mcp" {
		t.Fatalf("server name after migrating again = %q, want acme-mcp", got)
	}
}
