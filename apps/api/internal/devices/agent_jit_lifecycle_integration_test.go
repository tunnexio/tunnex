package devices

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/agentaccess"
)

func TestAgentLifecycleClosesJITAccessPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for F10 lifecycle proof")
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
	dbName := "tnx_f10_lifecycle_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)") })
	dsn := *base
	dsn.Path = "/" + dbName
	if err := db.MigrateTo(dsn.String(), 98); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	org, owner, node, agent := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode,agent_jit_access_enabled) VALUES ($1,'F10 lifecycle',$2,'10.121.0.0/24','enforcing',true)`, org, "f10-life-"+org.String()[:8])
	exec(`INSERT INTO users (id,email,name) VALUES ($1,$2,'F10 owner')`, owner, "f10-life-"+owner.String()[:8]+"@example.test")
	exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, org, owner)
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'f10-gw',$3)`, node, org, "f10-life-"+node.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent',$5,'10.121.0.2','active','agent')`, agent, org, owner, node, "f10-life-agent-"+agent.String())
	exec(`INSERT INTO agent_profiles (device_id,environment,runtime,labels) VALUES ($1,'dev','linux','{}')`, agent)

	jit := agentaccess.New(pool, nil)
	deviceSvc := NewService(pool, nil, nil)
	resourceIndex := 0
	resource := func(name string) uuid.UUID {
		resourceIndex++
		id := uuid.New()
		exec(`INSERT INTO resources (id,org_id,name,cidr,protocol) VALUES ($1,$2,$3,$4,'any')`, id, org, name, fmt.Sprintf("10.%d.0.0/24", 60+resourceIndex))
		return id
	}
	request := func(name string, approve bool) uuid.UUID {
		r, replay, err := jit.Create(ctx, org, owner, agentaccess.CreateInput{
			DeviceID: agent, Destination: agentaccess.Destination{Kind: "resource", ID: resource(name)},
			Reason: name, Duration: agentaccess.MinDuration, IdempotencyKey: "create-" + name,
		})
		if err != nil || replay {
			t.Fatalf("create %s replay=%v err=%v", name, replay, err)
		}
		if approve {
			r, replay, err = jit.Approve(ctx, org, r.ID, owner, "approve-"+name)
			if err != nil || replay || !r.PolicyRuleID.Valid {
				t.Fatalf("approve %s replay=%v err=%v", name, replay, err)
			}
		}
		return r.ID
	}
	assertClosed := func(cause string, approved, pending uuid.UUID) {
		t.Helper()
		var approvedState, pendingState string
		if err := pool.QueryRow(ctx, `SELECT state FROM agent_access_requests WHERE id=$1`, approved).Scan(&approvedState); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT state FROM agent_access_requests WHERE id=$1`, pending).Scan(&pendingState); err != nil {
			t.Fatal(err)
		}
		if approvedState != "revoked" || pendingState != "cancelled" {
			t.Fatalf("%s states approved=%s pending=%s", cause, approvedState, pendingState)
		}
		var rules int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE org_id=$1`, org).Scan(&rules); err != nil || rules != 0 {
			t.Fatalf("%s rule count=%d err=%v", cause, rules, err)
		}
		var events int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_access_request_events WHERE request_id IN ($1,$2) AND metadata->>'cause'=$3`, approved, pending, cause).Scan(&events); err != nil || events != 2 {
			t.Fatalf("%s lifecycle events=%d err=%v", cause, events, err)
		}
	}

	approvedSuspend, pendingSuspend := request("suspend-approved", true), request("suspend-pending", false)
	suspended := "suspended"
	if _, err := deviceSvc.UpdateAgentProfileWithLifecycle(ctx, owner, org, agent, "dev", "linux", []byte(`{}`), &suspended); err != nil {
		t.Fatal(err)
	}
	assertClosed("agent_suspended", approvedSuspend, pendingSuspend)

	active := "active"
	if _, err := deviceSvc.UpdateAgentProfileWithLifecycle(ctx, owner, org, agent, "dev", "linux", []byte(`{}`), &active); err != nil {
		t.Fatal(err)
	}
	approvedRevoke, pendingRevoke := request("revoke-approved", true), request("revoke-pending", false)
	if err := deviceSvc.Revoke(ctx, org, owner, agent); err != nil {
		t.Fatal(err)
	}
	assertClosed("agent_revoked", approvedRevoke, pendingRevoke)
	if err := deviceSvc.RemoveRevoked(ctx, org, owner, agent); err != nil {
		t.Fatal(err)
	}
}
