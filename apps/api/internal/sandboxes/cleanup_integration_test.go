package sandboxes

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

type cleanupProvider struct {
	exists, running bool
	failure         error
	deletes, stops  int
}

func (p *cleanupProvider) Create(context.Context, sandboxruntime.Spec) error { return nil }
func (p *cleanupProvider) Start(context.Context, uuid.UUID) error            { return nil }
func (p *cleanupProvider) Stop(context.Context, uuid.UUID) error {
	p.stops++
	if p.failure != nil {
		return p.failure
	}
	p.running = false
	return nil
}
func (p *cleanupProvider) Delete(context.Context, uuid.UUID) error {
	p.deletes++
	if p.failure != nil {
		return p.failure
	}
	p.exists = false
	return nil
}
func (p *cleanupProvider) Inspect(context.Context, uuid.UUID) (sandboxruntime.Status, error) {
	if !p.exists {
		return sandboxruntime.Status{}, sandboxruntime.ErrMissing
	}
	return sandboxruntime.Status{Exists: true, Running: p.running}, nil
}

type cleanupNetworkFunc func(context.Context, Sandbox) (Withdrawal, error)

func (f cleanupNetworkFunc) Withdraw(ctx context.Context, s Sandbox) (Withdrawal, error) {
	return f(ctx, s)
}
func matchingWithdrawal(s Sandbox) Withdrawal {
	return Withdrawal{s.Identity.ID, *s.PeerID, s.Revision, true}
}
func bindCleanupPeer(t *testing.T, f fixture, s Sandbox) uuid.UUID {
	t.Helper()
	id := uuid.New()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx) //nolint:errcheck
	if _, err = tx.Exec(f.ctx, `INSERT INTO devices(id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,kind,status) VALUES($1,$2,$3,$4,'sandbox','linux',$5,'10.99.0.4','sandbox','active')`, id, f.org, f.user, f.node, strings.Repeat("a", 43)+"="); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, `UPDATE sandboxes SET peer_id=$2 WHERE id=$1`, s.Identity.ID, id); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return id
}
func TestSandboxCleanupPostgresRetainsAddressUntilReceiptAndRecovers(t *testing.T) {
	f := newFixture(t)
	s, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("cleanup"))
	if err != nil {
		t.Fatal(err)
	}
	peer := bindCleanupPeer(t, f, s)
	s, err = f.store.SetDesired(f.ctx, f.org, f.user, s.Identity.ID, s.Revision, "deleted")
	if err != nil {
		t.Fatal(err)
	}
	p := &cleanupProvider{exists: true, running: true}
	networkFailure := errors.New("coordinator unavailable")
	if err = f.store.ReconcileCleanup(f.ctx, s.Identity.ID, p, cleanupNetworkFunc(func(context.Context, Sandbox) (Withdrawal, error) { return Withdrawal{}, networkFailure })); !errors.Is(err, networkFailure) {
		t.Fatal(err)
	}
	var status string
	var address *string
	var blocked bool
	if err = f.pool.QueryRow(f.ctx, `SELECT status,assigned_ip,health_blocked FROM devices WHERE id=$1`, peer).Scan(&status, &address, &blocked); err != nil {
		t.Fatal(err)
	}
	if status != "active" || address == nil || !blocked || p.deletes != 0 {
		t.Fatal("failed withdrawal released allocation or touched provider")
	}
	allocations, err := sqlc.New(f.pool).ListActiveDeviceAllocations(f.ctx, f.org)
	if err != nil || len(allocations) != 1 {
		t.Fatal("cleanup address not reserved", err)
	}
	wrong := cleanupNetworkFunc(func(_ context.Context, s Sandbox) (Withdrawal, error) {
		r := matchingWithdrawal(s)
		r.Generation++
		return r, nil
	})
	if err = f.store.ReconcileCleanup(f.ctx, s.Identity.ID, p, wrong); err != ErrConflict {
		t.Fatal("accepted stale receipt", err)
	}
	good := cleanupNetworkFunc(func(_ context.Context, s Sandbox) (Withdrawal, error) { return matchingWithdrawal(s), nil })
	p.failure = sandboxruntime.ErrUnavailable
	if err = f.store.ReconcileCleanup(f.ctx, s.Identity.ID, p, good); err != sandboxruntime.ErrUnavailable {
		t.Fatal(err)
	}
	p.failure = nil
	if err = f.store.ReconcileCleanup(f.ctx, s.Identity.ID, p, good); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, s.Identity.ID)
	if err != nil || current.State != StateDeleted {
		t.Fatal("cleanup not finalized", err)
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT status,assigned_ip FROM devices WHERE id=$1`, peer).Scan(&status, &address); err != nil {
		t.Fatal(err)
	}
	if status != "revoked" || address != nil {
		t.Fatal("finalized cleanup leaked allocation")
	}
	before := p.deletes
	if err = f.store.ReconcileCleanup(f.ctx, s.Identity.ID, p, nil); err != nil || p.deletes != before {
		t.Fatal("deleted retry repeated work", err)
	}
}
func TestSandboxCleanupPostgresLeaseAndStaleCompletion(t *testing.T) {
	f := newFixture(t)
	s, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("stop"))
	if err != nil {
		t.Fatal(err)
	}
	bindCleanupPeer(t, f, s)
	s, err = f.store.SetDesired(f.ctx, f.org, f.user, s.Identity.ID, s.Revision, "stopped")
	if err != nil {
		t.Fatal(err)
	}
	p := &cleanupProvider{exists: true, running: true}
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	network := cleanupNetworkFunc(func(_ context.Context, target Sandbox) (Withdrawal, error) {
		close(entered)
		<-release
		return matchingWithdrawal(target), nil
	})
	go func() { result <- f.store.ReconcileCleanup(f.ctx, s.Identity.ID, p, network) }()
	<-entered
	if err = f.store.ReconcileCleanup(f.ctx, s.Identity.ID, &cleanupProvider{}, nil); err != ErrConflict {
		t.Fatal("parallel lease admitted", err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, s.Identity.ID, s.Revision, "started"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err = <-result; err != ErrConflict {
		t.Fatal("stale completion acknowledged", err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, s.Identity.ID)
	if err != nil || current.DesiredState != "started" || current.State == StateStopped {
		t.Fatal("new intent overwritten", err)
	}
}
func TestSandboxCleanupPostgresUnboundDeletionAndExpiry(t *testing.T) {
	f := newFixture(t)
	s, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("unbound"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, s.Identity.ID, s.Revision, "deleted"); err != nil {
		t.Fatal(err)
	}
	if err = f.store.ReconcileCleanup(f.ctx, s.Identity.ID, &cleanupProvider{}, nil); err != nil {
		t.Fatal(err)
	}
	expired := uuid.New()
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO sandboxes(id,org_id,creator_id,template_id,name,requested_scope,idempotency_key,request_hash,created_at,expires_at) VALUES($1,$2,$3,$4,'expired','[]','expired',decode(repeat('00',32),'hex'),now()-interval '1 hour',now()-interval '1 minute')`, expired, f.org, f.user, f.template); err != nil {
		t.Fatal(err)
	}
	ids, err := f.store.PendingCleanup(f.ctx, 100)
	if err != nil || len(ids) != 1 || ids[0] != expired {
		t.Fatal("TTL not queued", err)
	}
	if err = f.store.ReconcileCleanup(f.ctx, expired, &cleanupProvider{}, nil); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, expired)
	if err != nil || current.State != StateDeleted || current.DesiredState != "deleted" || current.Revision != 2 {
		t.Fatal("TTL not terminal", err)
	}
}
