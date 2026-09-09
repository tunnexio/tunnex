package connectivity

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Run only against an isolated migrated DB, never the active CP database:
// background HA reconciliation legitimately changes these synthetic fixtures.
func TestGatewayMoveOwnershipPostgres(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated PostgreSQL")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	org, owner, nextOwner, device := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	a, b, siteA, siteB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'NAT isolated HA',$2)`, org, "nat-ha-"+org.String())
	defer func() {
		if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org); err != nil {
			t.Error(err)
			return
		}
		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1 OR id=$2`, owner, nextOwner); err != nil {
			t.Error(err)
		}
	}()
	exec(`INSERT INTO users(id,email) VALUES($1,$2),($3,$4)`, owner, owner.String()+"@example.invalid", nextOwner, nextOwner.String()+"@example.invalid")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member'),($1,$3,'member')`, org, owner, nextOwner)
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$3,'a'),($2,$3,'b')`, siteA, siteB, org)
	keyA, keyB := strings.Repeat("A", 43)+"=", strings.Repeat("B", 43)+"="
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,wg_public_key,endpoint) VALUES($1,$2,'a',$3,$4,$5,'192.0.2.1:51820')`, a, org, a.String(), siteA, keyA)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,wg_public_key,endpoint) VALUES($1,$2,'b',$3,$4,$5,'192.0.2.2:51820')`, b, org, b.String(), siteB, keyB)
	exec(`INSERT INTO org_hub_set(org_id,configured) VALUES($1,$2)`, org, []uuid.UUID{a, b})
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES($1,$2,$3,$4,'device',$5,'10.99.0.2')`, device, org, owner, a, keyA)
	exec(`INSERT INTO connectivity_profiles(org_id,enabled) VALUES($1,true)`, org)
	s := NewStore(pool)
	p := Principal{DeviceSide, org, owner}
	first, err := s.Create(ctx, p, device)
	if err != nil {
		t.Fatal("initial session", err)
	}
	bound := first.Session.Binding
	if bound.GatewayID != a {
		t.Fatal("initial gateway differs")
	}
	exec(`UPDATE org_hub_set SET demoted=$2 WHERE org_id=$1`, org, []uuid.UUID{a})
	if _, err := s.Read(ctx, p, device, bound.SessionID, bound.Generation); err != ErrGatewayChanged {
		t.Fatal("same owner must recover gateway move", err)
	}
	exec(`UPDATE devices SET user_id=$2 WHERE id=$1`, device, nextOwner)
	for _, principal := range []Principal{p, {DeviceSide, org, nextOwner}} {
		if _, err := s.Read(ctx, principal, device, bound.SessionID, bound.Generation); err != ErrDenied {
			t.Fatal("transferred read must deny", err)
		}
		if _, err := s.Publish(ctx, principal, device, bound.SessionID, bound.Generation, 1, json.RawMessage(`{}`)); err != ErrDenied {
			t.Fatal("transferred publish must deny", err)
		}
		if err := s.Close(ctx, principal, device, bound.SessionID, bound.Generation); err != ErrDenied {
			t.Fatal("transferred close must deny", err)
		}
	}
	newPrincipal := Principal{DeviceSide, org, nextOwner}
	next, err := s.Create(ctx, newPrincipal, device)
	if err != nil || next.Session.Binding.GatewayID != b || next.Session.Binding.OwnerID != nextOwner {
		t.Fatal("new owner must receive fresh active-gateway binding", err)
	}
	if _, err := s.Read(ctx, Principal{GatewaySide, org, b}, device, next.Session.Binding.SessionID, next.Session.Binding.Generation); err != nil {
		t.Fatal("new gateway must read fresh session", err)
	}
}
