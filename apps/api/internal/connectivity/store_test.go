package connectivity

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSnapshotPayloadBounds(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", `"x"`, "{} trailing", "{\"x\":\"\xff\"}", `{"x":"` + strings.Repeat("a", MaxPayloadBytes) + `"}`} {
		if validPayload(json.RawMessage(raw)) {
			t.Fatal("accepted invalid or excessive snapshot")
		}
	}
	if !validPayload(json.RawMessage(`{"candidates":[],"complete":true}`)) {
		t.Fatal("rejected snapshot")
	}
}

func TestDurableMailbox(t *testing.T) {
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
	org, owner, gateway, device := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'NAT test',$2)`, org, "nat-"+org.String())
	exec(`INSERT INTO users(id,email) VALUES($1,$2)`, owner, owner.String()+"@example.invalid")
	t.Cleanup(func() {
		// A new pool is needed because the primary pool closes before Cleanup.
		p, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Error(err)
			return
		}
		defer p.Close()
		if _, err := p.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org); err != nil {
			t.Error(err)
		}
		if _, err := p.Exec(ctx, `DELETE FROM users WHERE id=$1`, owner); err != nil {
			t.Error(err)
		}
	})
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, owner)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'nat-gateway',$3)`, gateway, org, gateway.String())
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES($1,$2,$3,$4,'nat-device',$5,'10.99.0.2')`, device, org, owner, gateway, strings.Repeat("A", 43)+"=")
	s := NewStore(pool)
	p := Principal{DeviceSide, org, owner}
	g := Principal{GatewaySide, org, gateway}
	if _, err := s.Create(ctx, p, device); err != ErrDenied {
		t.Fatal("missing profile did not deny", err)
	}
	exec(`INSERT INTO connectivity_profiles(org_id) VALUES($1)`, org)
	if _, err := s.Create(ctx, p, device); err != ErrDenied {
		t.Fatal("default off did not deny", err)
	}
	exec(`UPDATE connectivity_profiles SET enabled=true WHERE org_id=$1`, org)
	if _, err := s.Create(ctx, g, device); err != ErrDenied {
		t.Fatal("gateway created session", err)
	}
	first, err := s.Create(ctx, p, device)
	if err != nil {
		t.Fatal(err)
	}
	b := first.Session.Binding
	if b.OwnerID != owner || b.GatewayID != gateway || b.Generation != 1 {
		t.Fatal("binding not canonical")
	}
	read := func(principal Principal) error {
		_, err := NewStore(pool).Read(ctx, principal, device, b.SessionID, b.Generation)
		return err
	}
	if err := read(g); err != nil {
		t.Fatal("gateway read", err)
	}
	for _, bad := range []Principal{{DeviceSide, uuid.New(), owner}, {DeviceSide, org, uuid.New()}, {GatewaySide, org, uuid.New()}} {
		if err := read(bad); err != ErrDenied {
			t.Fatal("principal mismatch allowed", err)
		}
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := NewStore(pool).Publish(ctx, p, device, b.SessionID, b.Generation, 1, json.RawMessage(`{"complete":true}`))
			if err == nil {
				accepted.Add(1)
			} else if err != ErrDenied {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("concurrent replay not serialized", accepted.Load())
	}
	got, err := s.Read(ctx, g, device, b.SessionID, b.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if got.Session.DeviceSequence != 1 || !strings.Contains(string(got.DevicePayload), "complete") {
		t.Fatal("write not persisted")
	}
	if _, err := s.Publish(ctx, g, device, b.SessionID, b.Generation, 1, json.RawMessage(`{"answer":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, p, device, b.SessionID, b.Generation, MaxMessages+1, json.RawMessage(`{}`)); err != ErrDenied {
		t.Fatal("cap bypass", err)
	}
	if _, err := s.Publish(ctx, p, device, b.SessionID, b.Generation, 2, json.RawMessage(`[]`)); err != ErrPayload {
		t.Fatal("payload bypass", err)
	}
	second, err := s.Create(ctx, p, device)
	if err != nil {
		t.Fatal(err)
	}
	if second.Session.Binding.Generation != 2 || second.Session.Binding.SessionID == b.SessionID {
		t.Fatal("generation not advanced")
	}
	if err := read(p); err != ErrDenied {
		t.Fatal("superseded read", err)
	}
	b = second.Session.Binding
	// Exactly the byte limit survives persistence without JSONB reformatting.
	boundary := json.RawMessage(`{"x":"` + strings.Repeat("a", MaxPayloadBytes-8) + `"}`)
	if len(boundary) != MaxPayloadBytes {
		t.Fatal("bad boundary fixture")
	}
	if _, err := s.Publish(ctx, p, device, b.SessionID, b.Generation, 1, boundary); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ name, block, restore string }{
		{"posture", `UPDATE devices SET health_blocked=true WHERE id=$1`, `UPDATE devices SET health_blocked=false WHERE id=$1`},
		{"key", `UPDATE devices SET public_key='invalid' WHERE id=$1`, `UPDATE devices SET public_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' WHERE id=$1`},
		{"device", `UPDATE devices SET status='revoked' WHERE id=$1`, `UPDATE devices SET status='active' WHERE id=$1`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			exec(mutation.block, device)
			if err := read(p); err != ErrDenied {
				t.Fatal("stale eligibility", err)
			}
			exec(mutation.restore, device)
		})
	}
	exec(`DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, org, owner)
	if err := read(p); err != ErrDenied {
		t.Fatal("offboarded owner allowed", err)
	}
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, owner)
	exec(`UPDATE nodes SET status='revoked' WHERE id=$1`, gateway)
	if err := read(g); err != ErrDenied {
		t.Fatal("revoked gateway allowed", err)
	}
	exec(`UPDATE nodes SET status='active' WHERE id=$1`, gateway)
	if err := s.Close(ctx, p, device, b.SessionID, b.Generation); err != nil {
		t.Fatal(err)
	}
	if err := read(g); err != ErrDenied {
		t.Fatal("closed session reopened", err)
	}
	third, err := s.Create(ctx, p, device)
	if err != nil {
		t.Fatal(err)
	}
	b = third.Session.Binding
	exec(`UPDATE connectivity_sessions SET created_at=now()-interval '11 minutes',expires_at=now()-interval '1 minute' WHERE device_id=$1`, device)
	if err := read(p); err != ErrDenied {
		t.Fatal("expired session allowed", err)
	}
}
