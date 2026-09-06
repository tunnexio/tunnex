package agentruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

type credentialFixture struct {
	t                  *testing.T
	ctx                context.Context
	pool               *pgxpool.Pool
	svc                *Service
	org, owner, device uuid.UUID
	current, candidate uuid.UUID
	old, next          string
}

func newCredentialFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, candidateFirst, withCandidate bool) *credentialFixture {
	t.Helper()
	f := &credentialFixture{t: t, ctx: ctx, pool: pool, org: uuid.New(), owner: uuid.New(), device: uuid.New(), current: uuid.New(), candidate: uuid.New()}
	f.svc = New(pool, func(context.Context, uuid.UUID) (OptInState, error) { return OptInEnabled, nil })
	f.old, f.next = RuntimeCredentialPrefix+f.current.String(), RuntimeCredentialPrefix+f.candidate.String()
	node := uuid.New()
	f.exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'credential transaction',$2)`, f.org, "credential-"+f.org.String())
	f.exec(`INSERT INTO users(id,email) VALUES($1,$2)`, f.owner, f.owner.String()+"@credential.test")
	f.exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'gateway',$3)`, node, f.org, node.String())
	f.exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,status,kind) VALUES($1,$2,$3,$4,'agent',$5,'active','agent')`, f.device, f.org, f.owner, node, f.device.String())
	insertCurrent := func() {
		h := sha256.Sum256([]byte(f.old))
		f.exec(`INSERT INTO agent_runtime_credentials(id,org_id,device_id,token_hash,revision,state,activated_at,rotation_requested_at,rotation_deadline,rotation_requested_by) VALUES($1,$2,$3,$4,1,'current',now(),now(),now()+interval '1 hour',$5)`, f.current, f.org, f.device, h[:], f.owner)
	}
	insertCandidate := func() {
		h := sha256.Sum256([]byte(f.next))
		f.exec(`INSERT INTO agent_runtime_credentials(id,org_id,device_id,token_hash,revision,state,candidate_expires_at) VALUES($1,$2,$3,$4,2,'candidate',now()+interval '1 hour')`, f.candidate, f.org, f.device, h[:])
	}
	if candidateFirst && withCandidate {
		insertCandidate()
	}
	insertCurrent()
	if !candidateFirst && withCandidate {
		insertCandidate()
	}
	return f
}

func (f *credentialFixture) exec(query string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(f.ctx, query, args...); err != nil {
		f.t.Fatalf("credential fixture statement: %v", err)
	}
}

func (f *credentialFixture) snapshot() []byte {
	f.t.Helper()
	var snapshot []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_agg(to_jsonb(c) ORDER BY revision) FROM agent_runtime_credentials c WHERE org_id=$1 AND device_id=$2`, f.org, f.device).Scan(&snapshot); err != nil {
		f.t.Fatal(err)
	}
	return snapshot
}

func (f *credentialFixture) identity() Identity {
	return Identity{OrgID: f.org, DeviceID: f.device, CredentialRevision: 1, CredentialState: "current"}
}

func (f *credentialFixture) assertPromoted() {
	f.t.Helper()
	var current, candidate, superseded int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FILTER (WHERE state='current'),count(*) FILTER (WHERE state='candidate'),count(*) FILTER (WHERE state='superseded') FROM agent_runtime_credentials WHERE org_id=$1 AND device_id=$2`, f.org, f.device).Scan(&current, &candidate, &superseded); err != nil {
		f.t.Fatal(err)
	}
	if current != 1 || candidate != 0 || superseded != 1 {
		f.t.Fatalf("credential state counts current/candidate/superseded=%d/%d/%d", current, candidate, superseded)
	}
}

func TestRuntimeCredentialTransactionsPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	for _, candidateFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("candidate_first_%t", candidateFirst), func(t *testing.T) {
			f := newCredentialFixture(t, ctx, pool, candidateFirst, true)
			before := f.snapshot()
			if _, err := f.svc.AuthenticateCurrent(ctx, f.next); err != ErrUnauthorized {
				t.Fatalf("current-only candidate auth=%v", err)
			}
			if _, err := f.svc.Authenticate(ctx, f.old); err != nil {
				t.Fatalf("pre-promotion predecessor=%v", err)
			}
			if !bytes.Equal(before, f.snapshot()) {
				t.Fatal("read-only authentication changed stored credentials")
			}
			id, err := f.svc.Authenticate(ctx, f.next)
			if err != nil || id.OrgID != f.org || id.DeviceID != f.device || id.CredentialRevision != 2 || id.CredentialState != "current" {
				t.Fatalf("promotion identity=%+v error=%v", id, err)
			}
			f.assertPromoted()
			promoted := f.snapshot()
			if _, err := f.svc.Authenticate(ctx, f.old); err != ErrUnauthorized {
				t.Fatalf("superseded predecessor=%v", err)
			}
			if _, err := f.svc.Authenticate(ctx, f.next); err != nil {
				t.Fatalf("successor retry=%v", err)
			}
			if !bytes.Equal(promoted, f.snapshot()) {
				t.Fatal("successor replay changed activation or credential history")
			}
		})
	}
	t.Run("promotion_failure_rolls_back_demotion", func(t *testing.T) {
		f := newCredentialFixture(t, ctx, pool, true, true)
		// The extra test-owned constraint rejects ONLY this promotion. Production
		// uniqueness, lifecycle and audit triggers remain enabled and unchanged.
		constraint := pgx.Identifier{"test_promotion_" + f.candidate.String()[:8]}.Sanitize()
		f.exec(fmt.Sprintf(`ALTER TABLE agent_runtime_credentials ADD CONSTRAINT %s CHECK (id <> '%s'::uuid OR state <> 'current')`, constraint, f.candidate))
		before := f.snapshot()
		if _, err := f.svc.Authenticate(ctx, f.next); err != ErrUnauthorized {
			t.Fatalf("rejected promotion=%v", err)
		}
		if !bytes.Equal(before, f.snapshot()) {
			t.Fatal("failed promotion committed a partial demotion")
		}
		if _, err := f.svc.Authenticate(ctx, f.old); err != nil {
			t.Fatalf("predecessor after rollback=%v", err)
		}
	})
	t.Run("missing_predecessor_is_not_repaired", func(t *testing.T) {
		f := newCredentialFixture(t, ctx, pool, false, true)
		f.exec(`UPDATE agent_runtime_credentials SET state='revoked',revoked_at=now(),terminal_at=now() WHERE id=$1`, f.current)
		before := f.snapshot()
		if _, err := f.svc.Authenticate(ctx, f.next); err != ErrUnauthorized {
			t.Fatalf("candidate without current predecessor=%v", err)
		}
		if !bytes.Equal(before, f.snapshot()) {
			t.Fatal("unexpected credential history was repaired")
		}
	})
	t.Run("concurrent_successor_authentication", func(t *testing.T) {
		f := newCredentialFixture(t, ctx, pool, true, true)
		start := make(chan struct{})
		results := make(chan error, 8)
		var wg sync.WaitGroup
		for i := 0; i < cap(results); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				id, err := f.svc.Authenticate(ctx, f.next)
				if err == nil && (id.DeviceID != f.device || id.CredentialRevision != 2) {
					err = fmt.Errorf("wrong successor identity")
				}
				results <- err
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Fatalf("concurrent successor auth=%v", err)
			}
		}
		f.assertPromoted()
	})
	t.Run("preparation_replay_and_stale_identity", func(t *testing.T) {
		f := newCredentialFixture(t, ctx, pool, false, false)
		h := sha256.Sum256([]byte(f.next))
		for i := 0; i < 2; i++ {
			if err := f.svc.PrepareCredentialCandidate(ctx, f.identity(), 2, fmt.Sprintf("%x", h)); err != nil {
				t.Fatalf("prepare retry=%v", err)
			}
		}
		before := f.snapshot()
		otherHash := sha256.Sum256([]byte("different-" + f.next))
		if err := f.svc.PrepareCredentialCandidate(ctx, f.identity(), 2, fmt.Sprintf("%x", otherHash)); err != ErrRuntimeStateMissing {
			t.Fatalf("different candidate hash=%v", err)
		}
		foreign := f.identity()
		foreign.OrgID = uuid.New()
		if err := f.svc.PrepareCredentialCandidate(ctx, foreign, 2, fmt.Sprintf("%x", h)); err != ErrRuntimeStateMissing {
			t.Fatalf("foreign binding preparation=%v", err)
		}
		if !bytes.Equal(before, f.snapshot()) {
			t.Fatal("refused preparation changed credentials")
		}
		if _, err := f.svc.Authenticate(ctx, f.next); err != nil {
			t.Fatal(err)
		}
		if err := f.svc.PrepareCredentialCandidate(ctx, f.identity(), 2, fmt.Sprintf("%x", h)); err != ErrRuntimeStateMissing {
			t.Fatalf("stale authenticated revision=%v", err)
		}
	})
	t.Run("first_request_has_no_wireguard_row", func(t *testing.T) {
		f := newCredentialFixture(t, ctx, pool, false, false)
		got, err := devices.NewService(pool, nil, nil).RequestAgentCredentialRotation(ctx, f.owner, f.org, f.device)
		if err != nil || got.RequestedRevision == nil || *got.RequestedRevision != 2 || got.WireGuardRequestedRevision == nil || *got.WireGuardRequestedRevision != 2 {
			t.Fatalf("first rotation request=%+v error=%v", got, err)
		}
	})
}

// holdDevice and waitBlocked use actual PostgreSQL lock state, not a delay that
// could pass merely because the contender goroutine had not started yet.
func (f *credentialFixture) holdDevice(t *testing.T) (pgx.Tx, uint32) {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rollbackRuntimeTx(tx) })
	if _, err := sqlc.New(tx).GetDeviceForUpdate(f.ctx, sqlc.GetDeviceForUpdateParams{ID: f.device, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	return tx, tx.Conn().PgConn().PID()
}

func (f *credentialFixture) waitBlocked(t *testing.T, blocker uint32) {
	t.Helper()
	wait, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked bool
		if err := f.pool.QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1::int=ANY(pg_blocking_pids(pid)))`, int64(blocker)).Scan(&blocked); err != nil {
			t.Fatalf("observe transaction lock: %v", err)
		}
		if blocked {
			return
		}
		select {
		case <-wait.Done():
			t.Fatal("contender did not block on the device transaction")
		case <-tick.C:
		}
	}
}

func TestRuntimeCredentialDeviceSerializationPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	for _, status := range []string{"suspended", "revoked"} {
		t.Run("lifecycle_"+status, func(t *testing.T) {
			f := newCredentialFixture(t, ctx, pool, false, true)
			holder, pid := f.holdDevice(t)
			result := make(chan error, 1)
			go func() { _, err := f.svc.Authenticate(ctx, f.next); result <- err }()
			f.waitBlocked(t, pid)
			if _, err := holder.Exec(ctx, `UPDATE devices SET status=$2 WHERE id=$1`, f.device, status); err != nil {
				t.Fatal(err)
			}
			if err := holder.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != ErrUnauthorized {
				t.Fatalf("auth after lifecycle commit=%v", err)
			}
			var candidateState string
			if err := pool.QueryRow(ctx, `SELECT state FROM agent_runtime_credentials WHERE id=$1`, f.candidate).Scan(&candidateState); err != nil || candidateState != "revoked" {
				t.Fatalf("lifecycle candidate state=%s error=%v", candidateState, err)
			}
		})
	}
	t.Run("normal_revoke_then_delete", func(t *testing.T) {
		f := newCredentialFixture(t, ctx, pool, false, true)
		// Native deletion requires revocation first; do not invent a direct active
		// device tombstone or weaken the existing credential lifecycle trigger.
		f.exec(`UPDATE devices SET status='revoked' WHERE id=$1`, f.device)
		holder, pid := f.holdDevice(t)
		result := make(chan error, 1)
		go func() { _, err := f.svc.Authenticate(ctx, f.old); result <- err }()
		f.waitBlocked(t, pid)
		if _, err := holder.Exec(ctx, `UPDATE devices SET deleted_at=now() WHERE id=$1`, f.device); err != nil {
			t.Fatal(err)
		}
		if err := holder.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != ErrUnauthorized {
			t.Fatalf("auth after native deletion=%v", err)
		}
	})
	t.Run("expiry_during_lock_wait", func(t *testing.T) {
		f := newCredentialFixture(t, ctx, pool, false, true)
		f.exec(`UPDATE agent_runtime_credentials SET candidate_expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1`, f.candidate)
		before := f.snapshot()
		holder, pid := f.holdDevice(t)
		result := make(chan error, 1)
		go func() { _, err := f.svc.Authenticate(ctx, f.next); result <- err }()
		f.waitBlocked(t, pid)
		var expires time.Time
		if err := pool.QueryRow(ctx, `SELECT candidate_expires_at FROM agent_runtime_credentials WHERE id=$1`, f.candidate).Scan(&expires); err != nil {
			t.Fatal(err)
		}
		var startedBeforeExpiry bool
		if err := pool.QueryRow(ctx, `SELECT bool_and(xact_start < $2) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1::int=ANY(pg_blocking_pids(pid))`, int64(pid), expires).Scan(&startedBeforeExpiry); err != nil || !startedBeforeExpiry {
			t.Fatalf("authentication did not begin before expiry: %v", err)
		}
		for {
			var expired bool
			if err := pool.QueryRow(ctx, `SELECT clock_timestamp() >= $1`, expires).Scan(&expired); err != nil {
				t.Fatal(err)
			}
			if expired {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := holder.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != ErrUnauthorized {
			t.Fatalf("expired-after-wait candidate=%v", err)
		}
		if !bytes.Equal(before, f.snapshot()) {
			t.Fatal("expired candidate authentication changed credentials")
		}
	})
	for _, operation := range []string{"prepare", "request"} {
		t.Run(operation+"_waits_before_credential_writes", func(t *testing.T) {
			f := newCredentialFixture(t, ctx, pool, false, false)
			holder, pid := f.holdDevice(t)
			result := make(chan error, 1)
			go func() {
				if operation == "prepare" {
					h := sha256.Sum256([]byte(f.next))
					result <- f.svc.PrepareCredentialCandidate(ctx, f.identity(), 2, fmt.Sprintf("%x", h))
				} else {
					_, err := devices.NewService(pool, nil, nil).RequestAgentCredentialRotation(ctx, f.owner, f.org, f.device)
					result <- err
				}
			}()
			f.waitBlocked(t, pid)
			if _, err := holder.Exec(ctx, `UPDATE devices SET status='revoked' WHERE id=$1`, f.device); err != nil {
				t.Fatal(err)
			}
			if err := holder.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err == nil {
				t.Fatal("credential mutation succeeded after revocation won device lock")
			}
			var candidates int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_runtime_credentials WHERE device_id=$1 AND state='candidate'`, f.device).Scan(&candidates); err != nil || candidates != 0 {
				t.Fatalf("candidate count after revocation=%d error=%v", candidates, err)
			}
		})
	}
}

func TestRuntimeCredentialTransactionsHaveNoFallback(t *testing.T) {
	svc := New(nil, nil)
	if _, err := svc.Authenticate(context.Background(), RuntimeCredentialPrefix+"unknown"); err != ErrUnauthorized {
		t.Fatalf("nil transaction pool authentication=%v", err)
	}
	if _, err := svc.AuthenticateCurrent(context.Background(), RuntimeCredentialPrefix+"unknown"); err != ErrUnauthorized {
		t.Fatalf("nil transaction pool current authentication=%v", err)
	}
	if err := svc.PrepareCredentialCandidate(context.Background(), Identity{CredentialRevision: 1, CredentialState: "current"}, 2, ""); err != ErrUnauthorized {
		t.Fatalf("nil transaction pool preparation=%v", err)
	}
	if _, err := devices.NewService(nil, nil, nil).RequestAgentCredentialRotation(context.Background(), uuid.New(), uuid.New(), uuid.New()); err == nil {
		t.Fatal("rotation request accepted missing transaction pool")
	}
}

func TestRuntimeCredentialRotationReportContentionPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newCredentialFixture(t, ctx, pool, false, true)
	if _, err := f.svc.Authenticate(ctx, f.next); err != nil {
		t.Fatal(err)
	}
	q := sqlc.New(pool)
	dev, err := q.GetDevice(ctx, sqlc.GetDeviceParams{ID: f.device, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	const candidate = "WlEiCXJIkuDu09Ji0dvI1RwdkbLwkZ+qdR/M0r6/I94="
	f.exec(`INSERT INTO agent_wireguard_rotations(device_id,org_id,current_revision,requested_revision,state,candidate_public_key,requested_at,deadline,requested_by) VALUES($1,$2,1,2,'prepared',$3,now(),now()+interval '1 hour',$4)`, f.device, f.org, candidate, f.owner)
	before := f.snapshot()
	reportTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackRuntimeTx(reportTx)
	reportQueries := sqlc.New(reportTx)
	publicKey := candidate
	// Hold the actual first statement of ReportStatus, before its device-key
	// commit. The operator must not wait holding the device for this WG row.
	if _, err := reportQueries.StageAgentWireGuardCandidate(ctx, sqlc.StageAgentWireGuardCandidateParams{NodeID: dev.NodeID, PublicKey: &publicKey}); err != nil {
		t.Fatal(err)
	}
	requestCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err = devices.NewService(pool, nil, nil).RequestAgentCredentialRotation(requestCtx, f.owner, f.org, f.device)
	var conflict *apierr.Error
	if !errors.As(err, &conflict) || conflict.Status != 409 || conflict.Code != "agent_credential_rotation_unavailable" {
		t.Fatalf("contended request must promptly return existing conflict, got %v", err)
	}
	if requestCtx.Err() != nil {
		t.Fatal("request waited for context expiry instead of refusing NOWAIT contention")
	}
	if !bytes.Equal(before, f.snapshot()) {
		t.Fatal("WireGuard contention partially changed runtime credentials")
	}
	// Continue the exact real report transaction through nonzero-handshake
	// cutover; the rejected operator request must have released its device lock.
	if _, err := reportQueries.CommitAgentWireGuardCandidate(ctx, sqlc.CommitAgentWireGuardCandidateParams{
		NodeID: dev.NodeID, PublicKey: &publicKey, LastHandshakeAt: time.Now().UTC(), RxBytes: 11, TxBytes: 12,
	}); err != nil {
		t.Fatalf("gateway handshake commit after contention refusal: %v", err)
	}
	if err := reportTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rotation, err := q.GetAgentWireGuardRotation(ctx, sqlc.GetAgentWireGuardRotationParams{OrgID: f.org, DeviceID: f.device})
	if err != nil || rotation.State != "current" || rotation.CurrentRevision != 2 {
		t.Fatalf("gateway cutover state=%s revision=%d error=%v", rotation.State, rotation.CurrentRevision, err)
	}
	dev, err = q.GetDevice(ctx, sqlc.GetDeviceParams{ID: f.device, OrgID: f.org})
	if err != nil || dev.PublicKey != candidate {
		t.Fatalf("canonical gateway key did not advance: %v", err)
	}
	node, err := q.GetOrgNode(ctx, sqlc.GetOrgNodeParams{ID: dev.NodeID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodes.NewService(pool, nil, nil).ReportStatus(ctx, node, []nodes.PeerStatus{{PublicKey: candidate, LastHandshake: time.Now().Unix(), RxBytes: 13, TxBytes: 14}}); err != nil {
		t.Fatalf("ordinary gateway report after cutover: %v", err)
	}
	if _, err := devices.NewService(pool, nil, nil).RequestAgentCredentialRotation(ctx, f.owner, f.org, f.device); err != nil {
		t.Fatalf("normal rotation retry after gateway commit: %v", err)
	}
}
