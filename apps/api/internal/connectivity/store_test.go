package connectivity

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
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
	sealer, err := crypto.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore(pool, sealer)
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
	// Concurrent readers must coexist, while mutation remains fenced. This
	// reproduces the gateway poll + device heartbeat contention on a slow DB.
	t.Run("shared heartbeat locks preserve mutation fencing", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SELECT id FROM devices WHERE id=$1 FOR SHARE`, device); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT device_id FROM connectivity_sessions WHERE device_id=$1 FOR SHARE`, device); err != nil {
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if _, err := s.Read(bounded, g, device, b.SessionID, b.Generation); err != nil {
			t.Fatal("heartbeat blocked by another reader", err)
		}
		blocked, stop := context.WithTimeout(ctx, 150*time.Millisecond)
		defer stop()
		if err := s.Close(blocked, p, device, b.SessionID, b.Generation); err == nil {
			t.Fatal("writer bypassed shared eligibility lock")
		}
	})
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
	secret := strings.Repeat("test-only-", 4)
	profile, err := s.Configure(ctx, org, RelayConfig{Enabled: true, URL: "turns:relay.example.com:5349?transport=tcp", Secret: secret, ExpectedRevision: 0})
	if err != nil || !profile.SecretConfigured || profile.Revision != 1 {
		t.Fatal("profile configure", err)
	}
	var ciphertext string
	if err := pool.QueryRow(ctx, `SELECT secret_sealed FROM connectivity_profiles WHERE org_id=$1`, org).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ciphertext, secret) {
		t.Fatal("shared secret stored unsealed")
	}
	configured, err := s.Create(ctx, p, device)
	if err != nil {
		t.Fatal(err)
	}
	if configured.Relay == nil || configured.Relay.Password == secret || configured.Relay.Username == "" {
		t.Fatal("session credential missing or shared key leaked")
	}
	b = configured.Session.Binding
	remote, err := s.Read(ctx, g, device, b.SessionID, b.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if remote.Relay == nil || remote.Relay.Username == configured.Relay.Username {
		t.Fatal("gateway credential not independently scoped")
	}
	limited := s.WithIssuanceLimits(IssuanceLimits{1, 30, 300})
	if _, err := limited.Create(ctx, p, device); err != ErrIssuanceLimited {
		t.Fatal("missing creation throttle", err)
	}
	unchanged, err := s.Read(ctx, p, device, b.SessionID, b.Generation)
	if err != nil || unchanged.Session.Binding != b {
		t.Fatal("refused issuance changed live session", err)
	}
	if _, err := s.Configure(ctx, org, RelayConfig{ExpectedRevision: 0}); err != ErrProfileConflict {
		t.Fatal("stale profile overwrite", err)
	}
	t.Run("HA promotion follows canonical active dial without moving device identity", func(t *testing.T) {
		s := s.WithIssuanceLimits(IssuanceLimits{30, 60, 300})
		standby, siteA, siteB := uuid.New(), uuid.New(), uuid.New()
		keyA, keyB := strings.Repeat("A", 43)+"=", strings.Repeat("B", 43)+"="
		exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$3,'relay-a'),($2,$3,'relay-b')`, siteA, siteB, org)
		exec(`UPDATE nodes SET site_id=$2,wg_public_key=$3,endpoint='192.0.2.1:51820' WHERE id=$1`, gateway, siteA, keyA)
		exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,wg_public_key,endpoint) VALUES($1,$2,'standby',$3,$4,$5,'192.0.2.2:51820')`, standby, org, standby.String(), siteB, keyB)
		exec(`INSERT INTO org_hub_set(org_id,configured) VALUES($1,$2)`, org, []uuid.UUID{gateway, standby})
		a, err := s.Create(ctx, p, device)
		if err != nil {
			t.Fatal(err)
		}
		if a.Session.Binding.GatewayID != gateway || a.GatewayPublicKey != keyA {
			t.Fatal("wrong original active gateway")
		}
		exec(`UPDATE org_hub_set SET demoted=$2 WHERE org_id=$1`, org, []uuid.UUID{gateway})
		if _, err := s.Read(ctx, p, device, a.Session.Binding.SessionID, a.Session.Binding.Generation); err != ErrGatewayChanged {
			t.Fatal("old binding remained authorized", err)
		}
		t.Run("ownership transfer cannot recover former owner's session", func(t *testing.T) {
			newOwner := uuid.New()
			exec(`INSERT INTO users(id,email) VALUES($1,$2)`, newOwner, newOwner.String()+"@example.invalid")
			exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, newOwner)
			defer func() {
				exec(`UPDATE devices SET user_id=$2 WHERE id=$1`, device, owner)
				exec(`DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, org, newOwner)
				exec(`DELETE FROM users WHERE id=$1`, newOwner)
			}()
			exec(`UPDATE devices SET user_id=$2 WHERE id=$1`, device, newOwner)
			for _, principal := range []Principal{p, {DeviceSide, org, newOwner}} {
				binding := a.Session.Binding
				if _, err := s.Read(ctx, principal, device, binding.SessionID, binding.Generation); err != ErrDenied {
					t.Fatalf("transferred session read must deny, got %v", err)
				}
				if _, err := s.Publish(ctx, principal, device, binding.SessionID, binding.Generation, 1, json.RawMessage(`{}`)); err != ErrDenied {
					t.Fatalf("transferred session publish must deny, got %v", err)
				}
				if err := s.Close(ctx, principal, device, binding.SessionID, binding.Generation); err != ErrDenied {
					t.Fatalf("transferred session close must deny, got %v", err)
				}
			}
		})
		exec(`UPDATE connectivity_sessions SET revoked=true WHERE device_id=$1`, device)
		if _, err := s.Read(ctx, p, device, a.Session.Binding.SessionID, a.Session.Binding.Generation); err != ErrDenied {
			t.Fatal("revocation was offered gateway recovery", err)
		}
		next, err := s.Create(ctx, p, device)
		if err != nil {
			t.Fatal(err)
		}
		if next.Session.Binding.GatewayID != standby || next.GatewayPublicKey != keyB {
			t.Fatal("promotion did not update session gateway")
		}
		if _, err := s.Read(ctx, g, device, next.Session.Binding.SessionID, next.Session.Binding.Generation); err != ErrDenied {
			t.Fatal("old gateway accepted", err)
		}
		if _, err := s.Read(ctx, Principal{GatewaySide, org, standby}, device, next.Session.Binding.SessionID, next.Session.Binding.Generation); err != nil {
			t.Fatal("new gateway refused", err)
		}
		var assigned uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT node_id FROM devices WHERE id=$1`, device).Scan(&assigned); err != nil || assigned != gateway {
			t.Fatal("assigned identity changed", err)
		}
		b = next.Session.Binding
	})
	if _, err := s.Configure(ctx, org, RelayConfig{Enabled: false, URL: profile.URL, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := read(p); err != ErrDenied {
		t.Fatal("disabled profile preserved session", err)
	}
}
