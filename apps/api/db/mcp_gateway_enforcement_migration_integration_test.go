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

// TestMCPGatewayEnforcementMigrationPostgres proves 0249 and 0250 against real
// PostgreSQL: an organization that already uses MCP gets a grace date and one
// that does not starts closed; existing inventory stays agent-reported; an
// approval can carry bounded arguments; activity rows keep their invariants;
// and rolling back removes gateway-observed inventory and the new columns.
func TestMCPGatewayEnforcementMigrationPostgres(t *testing.T) {
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
	name := "tnx_aisec2_mcpgw_" + uuid.NewString()[:8]
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

	if err := db.MigrateTo(dsn, 248); err != nil {
		t.Fatalf("migrate to 0248: %v", err)
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

	// Two organizations: one already uses MCP, one does not.
	withMCP, withoutMCP := uuid.New(), uuid.New()
	user, node, device, group, profile := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'0249-mcp',$2,'10.97.0.0/24')`, withMCP, "m0249a-"+withMCP.String()[:8])
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'0249-plain',$2,'10.98.0.0/24')`, withoutMCP, "m0249b-"+withoutMCP.String()[:8])
	exec(`INSERT INTO users (id,email) VALUES ($1,$2)`, user, "m0249-"+user.String()[:8]+"@example.com")
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES ($1,$2,'m0249-gw',$3,'c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=','gw.example:51820','active')`, node, withMCP, "serial-"+node.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'m0249-agent',$5,'10.97.0.2','active','agent')`, device, withMCP, user, node, "m0249-key-"+device.String())
	exec(`INSERT INTO agent_groups (id,org_id,name) VALUES ($1,$2,'m0249-group')`, group, withMCP)
	exec(`INSERT INTO agent_mcp_profiles (id,org_id,name,endpoint) VALUES ($1,$2,'m0249-profile','http://172.30.0.10:9000/mcp')`, profile, withMCP)
	exec(`INSERT INTO agent_mcp_profile_assignments (org_id,profile_id,agent_group_id) VALUES ($1,$2,$3)`, withMCP, profile, group)
	exec(`INSERT INTO agent_mcp_inventory (device_id,snapshot,observed_at) VALUES ($1,'{"servers":[]}',now())`, device)
	var approval uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO agent_mcp_tool_approval_requests (org_id,device_id,policy_version,endpoint,server_name,tool_name,input_schema_hash,request_digest,expires_at)
		VALUES ($1,$2,1,'http://172.30.0.10:9000/mcp','acme','refund_order','h',repeat('a',64),now()+interval '5 minutes') RETURNING id`, withMCP, device).Scan(&approval); err != nil {
		t.Fatal(err)
	}

	before := time.Now()
	if err := db.MigrateTo(dsn, 250); err != nil {
		t.Fatalf("migrate to 0250: %v", err)
	}

	// Grace: 30 days for the organization that already uses MCP, none for the other.
	var grace time.Time
	if err := pool.QueryRow(ctx, `SELECT grace_until FROM organization_mcp_direct_path_grace WHERE org_id=$1`, withMCP).Scan(&grace); err != nil {
		t.Fatalf("an organization with an active MCP assignment must get a grace date: %v", err)
	}
	if d := grace.Sub(before); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("grace is %s from the upgrade, want about 30 days", d)
	}
	var graceRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_mcp_direct_path_grace WHERE org_id=$1`, withoutMCP).Scan(&graceRows); err != nil {
		t.Fatal(err)
	}
	if graceRows != 0 {
		t.Fatal("an organization with no MCP assignment must start with the direct path closed (no grace)")
	}

	// Existing inventory stays agent-reported; only the two known sources are accepted.
	var source string
	if err := pool.QueryRow(ctx, `SELECT source FROM agent_mcp_inventory WHERE device_id=$1`, device).Scan(&source); err != nil {
		t.Fatal(err)
	}
	if source != "agent" {
		t.Fatalf("existing inventory source = %q, want agent", source)
	}
	refuse("an unknown inventory source", `UPDATE agent_mcp_inventory SET source='elsewhere' WHERE device_id=$1`, device)

	// A runtime that predates the gateway path has not declared the capability.
	exec(`INSERT INTO agent_runtime_state (device_id) VALUES ($1) ON CONFLICT DO NOTHING`, device)
	var capable *time.Time
	if err := pool.QueryRow(ctx, `SELECT mcp_gateway_capable_at FROM agent_runtime_state WHERE device_id=$1`, device).Scan(&capable); err != nil {
		t.Fatal(err)
	}
	if capable != nil {
		t.Fatal("an existing runtime must not be marked gateway-capable by the migration")
	}

	// Approval arguments: an object, bounded, with a 64-character definition hash.
	var truncated bool
	if err := pool.QueryRow(ctx, `SELECT arguments_truncated FROM agent_mcp_tool_approval_requests WHERE id=$1 AND arguments IS NULL AND tool_definition_hash IS NULL`, approval).Scan(&truncated); err != nil {
		t.Fatalf("existing approval must keep NULL arguments and definition hash: %v", err)
	}
	if truncated {
		t.Fatal("existing approval must not be marked truncated")
	}
	exec(`UPDATE agent_mcp_tool_approval_requests SET arguments='{"order_id":3,"amount_cents":2500}', tool_definition_hash=repeat('b',64) WHERE id=$1`, approval)
	refuse("non-object arguments", `UPDATE agent_mcp_tool_approval_requests SET arguments='[1,2]' WHERE id=$1`, approval)
	refuse("oversized arguments", `UPDATE agent_mcp_tool_approval_requests SET arguments=jsonb_build_object('blob', repeat('x', 9000)) WHERE id=$1`, approval)
	refuse("a short definition hash", `UPDATE agent_mcp_tool_approval_requests SET tool_definition_hash='abc' WHERE id=$1`, approval)

	// Activity: an allow starts pending; a deny is never forwarded.
	exec(`INSERT INTO agent_mcp_tool_activity (org_id,device_id,node_id,endpoint,server_name,method,tool_name,arguments_digest,decision,policy_version)
		VALUES ($1,$2,$3,'http://172.30.0.10:9000/mcp','acme','tools/call','list_customers',repeat('c',64),'allow',1)`, withMCP, device, node)
	exec(`INSERT INTO agent_mcp_tool_activity (org_id,device_id,endpoint,method,tool_name,decision,reason,result_status)
		VALUES ($1,$2,'http://172.30.0.10:9000/mcp','tools/call','run_sql','deny','policy','not_forwarded')`, withMCP, device)
	refuse("a deny recorded as forwarded", `INSERT INTO agent_mcp_tool_activity (org_id,device_id,endpoint,method,tool_name,decision,reason,result_status)
		VALUES ($1,$2,'http://172.30.0.10:9000/mcp','tools/call','run_sql','deny','policy','ok')`, withMCP, device)
	refuse("an unknown decision", `INSERT INTO agent_mcp_tool_activity (org_id,device_id,endpoint,method,decision) VALUES ($1,$2,'e','tools/call','maybe')`, withMCP, device)
	refuse("retention outside its range", `INSERT INTO agent_mcp_tool_activity_retention_settings (org_id,retention_days) VALUES ($1,0)`, withMCP)
	exec(`INSERT INTO agent_mcp_tool_activity_retention_settings (org_id,retention_days,updated_by_user_id) VALUES ($1,14,$2)`, withMCP, user)

	// Roll back both. Gateway-observed inventory must not survive as if agent-reported.
	exec(`UPDATE agent_mcp_inventory SET source='gateway' WHERE device_id=$1`, device)
	if err := db.MigrateTo(dsn, 248); err != nil {
		t.Fatalf("roll back to 0248: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_mcp_inventory WHERE device_id=$1`, device).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("rolling back 0249 must remove gateway-observed inventory")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE
		(table_name='agent_mcp_inventory' AND column_name='source') OR
		(table_name='agent_runtime_state' AND column_name='mcp_gateway_capable_at') OR
		(table_name='agent_mcp_tool_approval_requests' AND column_name IN ('arguments','arguments_truncated','tool_definition_hash'))`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("0249 down left %d column(s)", n)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('agent_mcp_tool_activity','agent_mcp_tool_activity_retention_settings','organization_mcp_direct_path_grace')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rolling back left %d table(s)", n)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_mcp_tool_approval_requests WHERE id=$1`, approval).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rolling back must keep the approval request itself (n=%d, err=%v)", n, err)
	}
	if err := db.MigrateTo(dsn, 250); err != nil {
		t.Fatalf("migrate to 0250 again: %v", err)
	}
}
