package aigateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

type credentialPolicy struct {
	deny        bool
	wrongTenant bool
}

func (p credentialPolicy) CanIssue(context.Context, pgx.Tx, agentruntime.Identity) error {
	if p.deny {
		return aiUnauthorized()
	}
	return nil
}
func (p credentialPolicy) Resolve(_ context.Context, _ pgx.Tx, id agentruntime.Identity, model string) (Grant, error) {
	if p.deny || model != "openrouter/allowed" {
		return Grant{}, aiUnauthorized()
	}
	tenant := id.OrgID.String()
	if p.wrongTenant {
		tenant = uuid.NewString()
	}
	return Grant{Tenant: tenant, Agent: id.DeviceID.String(), VirtualKey: "sk-bf-fixture", Expires: time.Now().Add(time.Hour)}, nil
}

// This resolver exercises real database work on the caller's transaction.
// With MaxConns=1, borrowing a second connection would exhaust the pool.
type transactionCredentialPolicy struct{}

func (transactionCredentialPolicy) CanIssue(ctx context.Context, tx pgx.Tx, id agentruntime.Identity) error {
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT ai_gateway_enabled FROM organizations WHERE id=$1`, id.OrgID).Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return aiUnauthorized()
	}
	return nil
}

func (p transactionCredentialPolicy) Resolve(ctx context.Context, tx pgx.Tx, id agentruntime.Identity, model string) (Grant, error) {
	if err := p.CanIssue(ctx, tx, id); err != nil {
		return Grant{}, err
	}
	return (credentialPolicy{}).Resolve(ctx, tx, id, model)
}

type aiCredentialFixture struct {
	t                  *testing.T
	ctx                context.Context
	pool               *pgxpool.Pool
	service            *Credentials
	runtime            *agentruntime.Service
	org, owner, device uuid.UUID
	raw                string
}

func newAICredentialFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *aiCredentialFixture {
	t.Helper()
	f := &aiCredentialFixture{t: t, ctx: ctx, pool: pool, org: uuid.New(), owner: uuid.New(), device: uuid.New()}
	node := uuid.New()
	f.exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'AI credentials',$2)`, f.org, "ai-"+f.org.String())
	f.exec(`INSERT INTO users(id,email) VALUES($1,$2)`, f.owner, f.owner.String()+"@ai.test")
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, f.org, f.owner)
	f.exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'AI gateway',$3)`, node, f.org, node.String())
	f.exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,status,kind) VALUES($1,$2,$3,$4,'AI agent',$5,'active','agent')`, f.device, f.org, f.owner, node, f.device.String())
	f.raw = agentruntime.RuntimeCredentialPrefix + uuid.NewString()
	h := sha256.Sum256([]byte(f.raw))
	f.exec(`INSERT INTO agent_runtime_credentials(org_id,device_id,token_hash,revision,state) VALUES($1,$2,$3,1,'current')`, f.org, f.device, h[:])
	f.runtime = agentruntime.New(pool, func(context.Context, uuid.UUID) (agentruntime.OptInState, error) {
		return agentruntime.OptInUnavailable, nil
	})
	f.service = NewCredentials(pool, f.runtime, credentialPolicy{})
	f.service.SetAvailable(true)
	return f
}
func (f *aiCredentialFixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(f.ctx, q, args...); err != nil {
		f.t.Fatalf("AI fixture: %v", err)
	}
}
func (f *aiCredentialFixture) enable() {
	f.t.Helper()
	if _, err := f.service.SetEnabled(f.ctx, f.org, f.owner, true); err != nil {
		f.t.Fatal(err)
	}
}
func (f *aiCredentialFixture) mint() Credential {
	f.t.Helper()
	c, err := f.service.Issue(f.ctx, f.raw)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func TestAICredentialsPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	t.Run("refresh_purges_only_unusable_device_rows", func(t *testing.T) {
		f := newAICredentialFixture(t, ctx, pool)
		f.enable()
		other := newAICredentialFixture(t, ctx, pool)
		other.enable()
		otherCredential := other.mint()
		for i := 0; i < 12; i++ {
			f.mint()
			f.exec(`UPDATE ai_gateway_credentials SET created_at=now()-interval '6 minutes',expires_at=now()-interval '1 minute' WHERE org_id=$1 AND device_id=$2`, f.org, f.device)
		}
		live := f.mint()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM ai_gateway_credentials WHERE org_id=$1 AND device_id=$2`, f.org, f.device).Scan(&count); err != nil || count != 1 {
			t.Fatalf("expiry refresh retained %d rows: %v", count, err)
		}
		// Revoked cleanup must leave the other current bearer usable.
		revoked := f.mint()
		revokedHash := sha256.Sum256([]byte(revoked.Token))
		f.exec(`UPDATE ai_gateway_credentials SET revoked_at=now() WHERE token_hash=$1`, revokedHash[:])
		f.mint()
		if _, err := f.service.Authorize(ctx, live.Token, "openrouter/allowed"); err != nil {
			t.Fatalf("refresh evicted live bearer: %v", err)
		}
		for revision := 2; revision < 10; revision++ {
			f.exec(`UPDATE agent_runtime_credentials SET revision=$1 WHERE org_id=$2 AND device_id=$3`, revision, f.org, f.device)
			f.mint()
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM ai_gateway_credentials WHERE org_id=$1 AND device_id=$2`, f.org, f.device).Scan(&count); err != nil || count != 1 {
				t.Fatalf("rotation refresh retained %d rows: %v", count, err)
			}
		}
		if _, err := other.service.Authorize(ctx, otherCredential.Token, "openrouter/allowed"); err != nil {
			t.Fatalf("cleanup crossed tenant/device boundary: %v", err)
		}
	})
	for _, operation := range []string{"issue", "authorize"} {
		t.Run("revocation_commit_precedes_waiting_"+operation, func(t *testing.T) {
			f := newAICredentialFixture(t, ctx, pool)
			f.enable()
			credential := f.mint()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackAI(tx)
			if _, err := tx.Exec(ctx, `SELECT id FROM devices WHERE org_id=$1 AND id=$2 FOR UPDATE`, f.org, f.device); err != nil {
				t.Fatal(err)
			}
			pid := int64(tx.Conn().PgConn().PID())
			result := make(chan error, 1)
			go func() {
				if operation == "issue" {
					_, e := f.service.Issue(ctx, f.raw)
					result <- e
				} else {
					_, e := f.service.Authorize(ctx, credential.Token, "openrouter/allowed")
					result <- e
				}
			}()
			wait, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				var blocked bool
				if err := pool.QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1::int=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case <-wait.Done():
					t.Fatal("contender never waited for device lock")
				case <-tick.C:
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE agent_runtime_credentials SET revoked_at=statement_timestamp() WHERE org_id=$1 AND device_id=$2`, f.org, f.device); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("waiting request ignored committed revocation")
				}
			case <-wait.Done():
				t.Fatal("request did not finish after revocation")
			}
		})
	}
	t.Run("resolver_uses_single_connection_transaction", func(t *testing.T) {
		limitedConfig := pool.Config().Copy()
		limitedConfig.MaxConns = 1
		limitedConfig.MinConns = 0
		limited, err := pgxpool.NewWithConfig(ctx, limitedConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer limited.Close()
		f := newAICredentialFixture(t, ctx, limited)
		f.service.resolver = transactionCredentialPolicy{}
		f.enable()
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		credential, err := f.service.Issue(bounded, f.raw)
		if err != nil {
			t.Fatalf("single-connection issuance: %v", err)
		}
		if _, err := f.service.Authorize(bounded, credential.Token, "openrouter/allowed"); err != nil {
			t.Fatalf("single-connection authorization: %v", err)
		}
		if limited.Stat().AcquiredConns() != 0 {
			t.Fatal("authorization leaked its transaction connection")
		}
	})
	t.Run("community_default_off_and_hash_only", func(t *testing.T) {
		f := newAICredentialFixture(t, ctx, pool)
		if _, err := f.service.Issue(ctx, f.raw); err == nil {
			t.Fatal("default-off issued credential")
		}
		f.enable()
		c := f.mint()
		if c.Audience != AIAudience || len(c.Token) != 50 {
			t.Fatal("invalid credential envelope")
		}
		var ttlSeconds float64
		if err := pool.QueryRow(ctx, `SELECT extract(epoch from (expires_at-created_at))::float8 FROM ai_gateway_credentials WHERE org_id=$1`, f.org).Scan(&ttlSeconds); err != nil || ttlSeconds != 300 {
			t.Fatal("credential TTL is not exactly five minutes")
		}
		var hash []byte
		var count int
		if err := pool.QueryRow(ctx, `SELECT token_hash FROM ai_gateway_credentials WHERE org_id=$1`, f.org).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		want := sha256.Sum256([]byte(c.Token))
		if string(hash) != string(want[:]) {
			t.Fatal("unexpected persisted hash")
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='ai_gateway_credentials' AND column_name IN ('token','raw_token','value')`).Scan(&count); err != nil || count != 0 {
			t.Fatal("raw credential column")
		}
		g, err := f.service.Authorize(ctx, c.Token, "openrouter/allowed")
		if err != nil || g.Tenant != f.org.String() || !g.Expires.Equal(c.ExpiresAt) {
			t.Fatalf("valid grant failed: %v", err)
		}
		if _, err = f.runtime.Status(ctx, f.org, f.device); err == nil {
			t.Fatal("AI unlocked managed runtime")
		}
		if _, err = f.service.Authorize(ctx, c.Token, "openrouter/denied"); err == nil {
			t.Fatal("unauthorized model")
		}
		if _, err = f.service.Authorize(ctx, f.raw, "openrouter/allowed"); err == nil {
			t.Fatal("runtime bearer accepted as AI bearer")
		}
		if _, err = f.service.Issue(ctx, c.Token); err == nil {
			t.Fatal("AI bearer accepted as runtime bearer")
		}
	})
	t.Run("concurrent_mint_cap", func(t *testing.T) {
		f := newAICredentialFixture(t, ctx, pool)
		f.enable()
		var success atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := f.service.Issue(ctx, f.raw)
				if err == nil {
					success.Add(1)
					return
				}
				var ae *apierr.Error
				if !errors.As(err, &ae) || ae.Status != 429 {
					t.Errorf("unexpected issuance error %v", err)
				}
			}()
		}
		wg.Wait()
		if success.Load() != 4 {
			t.Fatalf("minted %d, want 4", success.Load())
		}
	})
	t.Run("candidate_cannot_promote_by_minting", func(t *testing.T) {
		f := newAICredentialFixture(t, ctx, pool)
		f.enable()
		candidate := agentruntime.RuntimeCredentialPrefix + uuid.NewString()
		hash := sha256.Sum256([]byte(candidate))
		f.exec(`INSERT INTO agent_runtime_credentials(org_id,device_id,token_hash,revision,state,candidate_expires_at) VALUES($1,$2,$3,2,'candidate',now()+interval '1 minute')`, f.org, f.device, hash[:])
		if _, err := f.service.Issue(ctx, candidate); err == nil {
			t.Fatal("candidate minted credential")
		}
		var state string
		if err := pool.QueryRow(ctx, `SELECT state FROM agent_runtime_credentials WHERE org_id=$1 AND device_id=$2 AND revision=2`, f.org, f.device).Scan(&state); err != nil || state != "candidate" {
			t.Fatal("minting promoted runtime candidate")
		}
		f.mint()
	})
	cases := []struct{ name, query string }{
		{"pending", `UPDATE devices SET status='pending' WHERE id=$1`},
		{"suspended", `UPDATE devices SET status='suspended' WHERE id=$1`},
		{"posture", `UPDATE devices SET health_blocked=true WHERE id=$1`},
		{"deleted", `UPDATE devices SET deleted_at=now() WHERE id=$1`},
		{"revoked", `UPDATE ai_gateway_credentials SET revoked_at=now() WHERE device_id=$1`},
		{"expired", `UPDATE ai_gateway_credentials SET created_at=now()-interval '6 minutes',expires_at=now()-interval '1 minute' WHERE device_id=$1`},
		{"runtime_revoked", `UPDATE agent_runtime_credentials SET revoked_at=now() WHERE device_id=$1`},
		{"runtime_rotated", `UPDATE agent_runtime_credentials SET revision=2 WHERE device_id=$1`},
		{"owner_deactivated", `UPDATE users SET status='deactivated' WHERE id=(SELECT user_id FROM devices WHERE id=$1)`},
		{"owner_deleted", `UPDATE users SET deleted_at=now() WHERE id=(SELECT user_id FROM devices WHERE id=$1)`},
		{"org_deleted", `UPDATE organizations SET deleted_at=now() WHERE id=(SELECT org_id FROM devices WHERE id=$1)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAICredentialFixture(t, ctx, pool)
			f.enable()
			c := f.mint()
			if tc.name == "deleted" {
				// Existing runtime lifecycle trigger rejects updating a bearer
				// after soft deletion; remove its row before this fixture mutation.
				f.exec(`DELETE FROM agent_runtime_credentials WHERE device_id=$1`, f.device)
			}
			f.exec(tc.query, f.device)
			if _, err := f.service.Authorize(ctx, c.Token, "openrouter/allowed"); err == nil {
				t.Fatal("invalid lifecycle authorized")
			}
			if tc.name != "expired" && tc.name != "revoked" && tc.name != "runtime_rotated" {
				if _, err := f.service.Issue(ctx, f.raw); err == nil {
					t.Fatal("invalid lifecycle minted credential")
				}
			}
		})
	}
	t.Run("membership_removal", func(t *testing.T) {
		f := newAICredentialFixture(t, ctx, pool)
		f.enable()
		c := f.mint()
		f.exec(`DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org, f.owner)
		if _, err := f.service.Authorize(ctx, c.Token, "openrouter/allowed"); err == nil {
			t.Fatal("removed owner authorized")
		}
	})
	t.Run("tenant_fk_audience_and_resolver", func(t *testing.T) {
		f := newAICredentialFixture(t, ctx, pool)
		f.enable()
		c := f.mint()
		other := newAICredentialFixture(t, ctx, pool)
		if _, err := pool.Exec(ctx, `UPDATE ai_gateway_credentials SET org_id=$1 WHERE device_id=$2`, other.org, f.device); err == nil {
			t.Fatal("cross-tenant FK accepted")
		}
		if _, err := pool.Exec(ctx, `UPDATE ai_gateway_credentials SET audience='other' WHERE device_id=$1`, f.device); err == nil {
			t.Fatal("wrong audience stored")
		}
		f.service.resolver = credentialPolicy{wrongTenant: true}
		if _, err := f.service.Authorize(ctx, c.Token, "openrouter/allowed"); err == nil {
			t.Fatal("resolver cross-tenant grant")
		}
		f.service.resolver = nil
		if _, err := f.service.Issue(ctx, f.raw); err == nil {
			t.Fatal("nil resolver allowed")
		}
	})
	t.Run("optout_and_cancellation", func(t *testing.T) {
		f := newAICredentialFixture(t, ctx, pool)
		f.enable()
		c := f.mint()
		if _, err := f.service.SetEnabled(ctx, f.org, f.owner, false); err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.Authorize(ctx, c.Token, "openrouter/allowed"); err == nil {
			t.Fatal("optout authorized")
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := f.service.Authorize(cancelled, c.Token, "openrouter/allowed"); err == nil {
			t.Fatal("CP loss authorized")
		}
	})
}
