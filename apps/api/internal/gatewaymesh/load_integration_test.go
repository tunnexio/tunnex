package gatewaymesh

import (
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestCrossGatewayDatabaseSubjectLifecycle(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, other := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, other} {
		if _, err := pool.Exec(ctx, "INSERT INTO organizations(id,name,slug) VALUES($1,'mesh',$2)", id, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	key := func(n byte) string { b := make([]byte, 32); b[0] = n; return base64.StdEncoding.EncodeToString(b) }
	a, b, foreign := uuid.New(), uuid.New(), uuid.New()
	for i, node := range []uuid.UUID{a, b, foreign} {
		tenant := org
		if node == foreign {
			tenant = other
		}
		if _, err := pool.Exec(ctx, "INSERT INTO nodes(id,org_id,name,cert_serial,wg_public_key,endpoint,enrolled_kind) VALUES($1,$2,$3,$3,$4,'gateway.example:51820','gateway')", node, tenant, node.String(), key(byte(i+1))); err != nil {
			t.Fatal(err)
		}
	}
	foreignUser := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO users(id,email,name) VALUES($1,$2,'foreign subject')", foreignUser, foreignUser.String()+"@test.local"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')", other, foreignUser); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO devices(org_id,user_id,node_id,name,public_key,assigned_ip) VALUES($1,$2,$3,'foreign subject',$4,'10.99.0.9')", other, foreignUser, foreign, key(11)); err != nil {
		t.Fatal(err)
	}
	q := sqlc.New(pool)
	for _, kind := range []string{"human", "agent"} {
		t.Run(kind, func(t *testing.T) {
			user, device := uuid.New(), uuid.New()
			if _, err := pool.Exec(ctx, "INSERT INTO users(id,email,name) VALUES($1,$2,'subject');", user, user.String()+"@test.local"); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, "INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')", org, user); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, "INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind) VALUES($1,$2,$3,$4,'subject',$5,'10.99.0.2',$6)", device, org, user, a, key(10), kind); err != nil {
				t.Fatal(err)
			}
			assertOwner := func(want uuid.UUID) {
				t.Helper()
				graph, err := Load(ctx, q, org, true)
				if err != nil || graph.Owner("10.99.0.2") != want {
					t.Fatalf("owner wanted %v: %+v %v", want, graph, err)
				}
				if graph.Owner("10.99.0.9") != uuid.Nil {
					t.Fatal("cross-tenant subject leaked")
				}
			}
			assertOwner(a)
			if _, err := pool.Exec(ctx, "UPDATE devices SET node_id=$2 WHERE id=$1", device, b); err != nil {
				t.Fatal(err)
			}
			assertOwner(b)
			for _, change := range []struct{ disable, restore string }{
				{"UPDATE devices SET health_blocked=true WHERE id=$1", "UPDATE devices SET health_blocked=false WHERE id=$1"},
				{"UPDATE devices SET status='revoked' WHERE id=$1", "UPDATE devices SET status='active' WHERE id=$1"},
				{"UPDATE users SET status='deactivated' WHERE id=$1", "UPDATE users SET status='active' WHERE id=$1"},
			} {
				id := device
				if change.disable[7:12] == "users" {
					id = user
				}
				if _, err := pool.Exec(ctx, change.disable, id); err != nil {
					t.Fatal(err)
				}
				assertOwner(uuid.Nil)
				if _, err := pool.Exec(ctx, change.restore, id); err != nil {
					t.Fatal(err)
				}
				assertOwner(b)
			}
			if kind == "agent" {
				if _, err := pool.Exec(ctx, "UPDATE devices SET status='suspended' WHERE id=$1", device); err != nil {
					t.Fatal(err)
				}
				assertOwner(uuid.Nil)
				if _, err := pool.Exec(ctx, "UPDATE devices SET status='active' WHERE id=$1", device); err != nil {
					t.Fatal(err)
				}
				assertOwner(b)
			}
			if _, err := pool.Exec(ctx, "UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2", org, user); err != nil {
				t.Fatal(err)
			}
			assertOwner(uuid.Nil)
			peers, err := q.ListActiveWireGuardPeersForNode(ctx, b)
			if err != nil || len(peers) != 0 {
				t.Fatalf("revoked membership retained local WireGuard peer: %+v %v", peers, err)
			}
			subjects, err := q.ListActiveDevicesForOrg(ctx, org)
			if err != nil || len(subjects) != 0 {
				t.Fatalf("revoked membership retained policy subject: %+v %v", subjects, err)
			}
			if _, err := pool.Exec(ctx, "UPDATE devices SET transport='openvpn',public_key='' WHERE id=$1", device); err != nil {
				t.Fatal(err)
			}
			roster, err := q.ListActiveOVPNDevicesForNode(ctx, b)
			if err != nil || len(roster) != 0 {
				t.Fatalf("revoked membership retained OpenVPN roster: %+v %v", roster, err)
			}
			if _, err := pool.Exec(ctx, "UPDATE memberships SET access_revoked_at=NULL WHERE org_id=$1 AND user_id=$2", org, user); err != nil {
				t.Fatal(err)
			}
			assertOwner(b)
			roster, err = q.ListActiveOVPNDevicesForNode(ctx, b)
			if err != nil || len(roster) != 1 {
				t.Fatalf("active OpenVPN client missing: %+v %v", roster, err)
			}
			if _, err := pool.Exec(ctx, "DELETE FROM memberships WHERE org_id=$1 AND user_id=$2", org, user); err != nil {
				t.Fatal(err)
			}
			assertOwner(uuid.Nil)
			if _, err := pool.Exec(ctx, "UPDATE devices SET status='revoked',deleted_at=now() WHERE id=$1", device); err != nil {
				t.Fatal(err)
			}
		})
	}
}
