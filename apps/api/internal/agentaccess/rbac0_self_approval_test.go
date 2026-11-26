package agentaccess

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// RBAC-0 D8: the person who asked for temporary agent access cannot approve it.
func TestRBAC0RequesterCannotApproveOwnRequest(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	org, requester, approver, node, agent, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode,agent_jit_access_enabled) VALUES ($1,'RBAC0',$2,'10.121.0.0/24','enforcing',true)`, org, "rbac0-jit-"+org.String()[:8])
	exec(`INSERT INTO users (id,email,name) VALUES ($1,$2,'Requester')`, requester, "rbac0-req-"+requester.String()[:8]+"@example.test")
	exec(`INSERT INTO users (id,email,name) VALUES ($1,$2,'Approver')`, approver, "rbac0-apr-"+approver.String()[:8]+"@example.test")
	exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, org, requester)
	exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'admin')`, org, approver)
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'rbac0-gw',$3)`, node, org, "rbac0-"+node.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent',$5,'10.121.0.2','active','agent')`, agent, org, requester, node, "rbac0-agent-"+agent.String())
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol,port_low,port_high) VALUES ($1,$2,'db','10.51.0.0/24','tcp',5432,5432)`, resource, org)

	svc := New(pool, &testPusher{})
	row, _, err := svc.Create(ctx, org, requester, CreateInput{DeviceID: agent, Destination: Destination{Kind: "resource", ID: resource}, Reason: "self approval probe", Duration: MinDuration, IdempotencyKey: "rbac0-create"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Approve(ctx, org, row.ID, requester, "rbac0-self"); err == nil {
		t.Fatal("the requester approved their own temporary access")
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM agent_access_requests WHERE id=$1`, row.ID).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("state=%q err=%v", state, err)
	}
	if approved, _, err := svc.Approve(ctx, org, row.ID, approver, "rbac0-other"); err != nil || approved.State != "approved" {
		t.Fatalf("another administrator must be able to approve: %v", err)
	}
}
