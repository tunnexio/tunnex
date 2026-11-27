// Package mcpfixture seeds the smallest organization that can make an MCP decision: a gateway, one agent
// device with an assigned MCP profile, and one human device on the same gateway. Tests only.
package mcpfixture

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Endpoint is the MCP endpoint the fixture profile assigns.
const Endpoint = "http://10.123.0.50:9000/mcp"

type Fixture struct {
	T                     testing.TB
	Ctx                   context.Context
	Pool                  *pgxpool.Pool
	Org, Owner, Node      uuid.UUID
	Agent, Human, Group   uuid.UUID
	Profile               uuid.UUID
	AgentIP, AgentKey     string
	HumanIP, HumanKey     string
	OtherNode, OtherAgent uuid.UUID
}

func key(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// New creates a disposable database (skipping the test when none is configured) and seeds the fixture.
func New(t testing.TB) *Fixture {
	t.Helper()
	ctx, pool := testpostgres.New(t)
	f := &Fixture{T: t, Ctx: ctx, Pool: pool, Org: uuid.New(), Owner: uuid.New(), Node: uuid.New(), Agent: uuid.New(), Human: uuid.New(), Group: uuid.New(), Profile: uuid.New(),
		AgentIP: "10.123.0.2", AgentKey: key(1), HumanIP: "10.123.0.3", HumanKey: key(2), OtherNode: uuid.New(), OtherAgent: uuid.New()}
	f.Exec(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'MCP',$2,'10.123.0.0/24')`, f.Org, "mcp-"+f.Org.String()[:8])
	f.Exec(`INSERT INTO users (id,email) VALUES ($1,$2)`, f.Owner, "mcp-"+f.Owner.String()[:8]+"@example.com")
	f.Exec(`INSERT INTO memberships (org_id,user_id,role,roles) VALUES ($1,$2,'owner',ARRAY['owner'])`, f.Org, f.Owner)
	f.Exec(`INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,$4,'gateway.example:51820'),($5,$2,'gw2',$6,$7,'gateway2.example:51820')`,
		f.Node, f.Org, "mcp-cert-"+f.Node.String(), "mcp-gw-key-"+f.Node.String(), f.OtherNode, "mcp-cert-"+f.OtherNode.String(), "mcp-gw-key-"+f.OtherNode.String())
	f.Exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES
 ($1,$2,$3,$4,'agent',$5,$6,'active','agent'),
 ($7,$2,$3,$4,'human',$8,$9,'active','human'),
 ($10,$2,$3,$11,'other-agent',$12,'10.123.0.4','active','agent')`,
		f.Agent, f.Org, f.Owner, f.Node, f.AgentKey, f.AgentIP, f.Human, f.HumanKey, f.HumanIP, f.OtherAgent, f.OtherNode, key(3))
	f.Exec(`INSERT INTO organization_mcp_settings (org_id,enabled) VALUES ($1,true)`, f.Org)
	f.Exec(`INSERT INTO agent_groups (id,org_id,name) VALUES ($1,$2,'mcp agents')`, f.Group, f.Org)
	f.Exec(`INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$4)`, f.Org, f.Group, f.Agent, f.Owner)
	f.Exec(`INSERT INTO agent_mcp_profiles (id,org_id,name,endpoint) VALUES ($1,$2,'billing',$3)`, f.Profile, f.Org, Endpoint)
	f.Exec(`INSERT INTO agent_mcp_profile_assignments (org_id,profile_id,agent_group_id) VALUES ($1,$2,$3)`, f.Org, f.Profile, f.Group)
	return f
}

// Exec runs one statement and fails the test on error.
func (f *Fixture) Exec(sql string, args ...any) {
	f.T.Helper()
	if _, err := f.Pool.Exec(f.Ctx, sql, args...); err != nil {
		f.T.Fatalf("fixture: %v", err)
	}
}

// Count returns the result of a single-integer query.
func (f *Fixture) Count(sql string, args ...any) int {
	f.T.Helper()
	var n int
	if err := f.Pool.QueryRow(f.Ctx, sql, args...).Scan(&n); err != nil {
		f.T.Fatalf("fixture count: %v", err)
	}
	return n
}

// AuditCount counts audit rows of one action for the fixture agent.
func (f *Fixture) AuditCount(action string) int {
	f.T.Helper()
	return f.Count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2 AND target_id=$3`, f.Org, action, f.Agent.String())
}

// AddServer assigns a second MCP server to the fixture agent through a new group of its own, later than
// the fixture's first assignment, and returns the new profile and group.
func (f *Fixture) AddServer(name, endpoint string) (profile, group uuid.UUID) {
	f.T.Helper()
	profile, group = uuid.New(), uuid.New()
	f.Exec(`INSERT INTO agent_groups (id,org_id,name) VALUES ($1,$2,$3)`, group, f.Org, name+" agents")
	f.Exec(`INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$4)`, f.Org, group, f.Agent, f.Owner)
	f.Exec(`INSERT INTO agent_mcp_profiles (id,org_id,name,endpoint) VALUES ($1,$2,$3,$4)`, profile, f.Org, name, endpoint)
	f.Exec(`INSERT INTO agent_mcp_profile_assignments (org_id,profile_id,agent_group_id,assigned_at) VALUES ($1,$2,$3,now()+interval '1 second')`, f.Org, profile, group)
	return profile, group
}
