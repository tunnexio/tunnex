package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/ownershiplease"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

type emptyAuthorityDomain struct{}

func (emptyAuthorityDomain) ApplyStage(context.Context, ownershiplease.Stage, reconcile.DesiredState) error {
	return nil
}
func (emptyAuthorityDomain) Readback(context.Context) (ownershiplease.AppliedDomainState, error) {
	return ownershiplease.AppliedDomainState{}, nil
}

type laneProbingAuthorityClient struct {
	desired reconcile.DesiredState
	lane    *dataplaneCommandLane
	posted  chan reconcile.KubernetesOwnershipBaseAuthorityAck
}

func (c *laneProbingAuthorityClient) FetchDesired(context.Context) (reconcile.DesiredState, error) {
	return c.desired, nil
}
func (c *laneProbingAuthorityClient) Watch(ctx context.Context, _ uint64) error {
	<-ctx.Done()
	return ctx.Err()
}
func (c *laneProbingAuthorityClient) AcknowledgeKubernetesOwnershipBaseAuthority(ctx context.Context, ack reconcile.KubernetesOwnershipBaseAuthorityAck) error {
	// A transport call made from inside the lane would deadlock here. Success
	// proves the POST phase runs after apply/readback/persistence releases it.
	if err := c.lane.submitAndWait(ctx, "ack_transport_probe", func(context.Context) error { return nil }); err != nil {
		return err
	}
	c.posted <- ack
	return nil
}

func TestDataplaneCommandLaneSerializesAllWriters(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lane := newDataplaneCommandLane(slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() {
		lane.run(ctx)
		close(done)
	}()

	var active atomic.Int32
	var maxActive atomic.Int32
	finished := make(chan struct{}, 12)
	for i := 0; i < cap(finished); i++ {
		if err := lane.submit(ctx, "test", func(context.Context) error {
			current := active.Add(1)
			for {
				previous := maxActive.Load()
				if current <= previous || maxActive.CompareAndSwap(previous, current) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			active.Add(-1)
			finished <- struct{}{}
			return nil
		}); err != nil {
			t.Fatalf("submit command: %v", err)
		}
	}
	for i := 0; i < cap(finished); i++ {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("serialized command did not finish")
		}
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("data-plane writers overlapped: max active=%d", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("command lane did not stop")
	}
}

func TestDataplaneCommandLaneDoesNotRunQueuedWorkAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lane := newDataplaneCommandLane(slog.New(slog.NewTextHandler(io.Discard, nil)))
	var ran atomic.Bool
	if err := lane.submit(ctx, "must_not_run", func(context.Context) error {
		ran.Store(true)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan struct{})
	go func() {
		lane.run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled command lane did not stop")
	}
	if ran.Load() {
		t.Fatal("queued data-plane mutation ran after cancellation")
	}
}

func TestDataplaneCommandLaneRunsUrgentWatchdogBeforeQueuedNormalWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lane := newDataplaneCommandLane(slog.New(slog.NewTextHandler(io.Discard, nil)))
	started := make(chan struct{})
	release := make(chan struct{})
	order := make(chan string, 2)

	if err := lane.submit(ctx, "in_flight", func(context.Context) error {
		close(started)
		<-release
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	go lane.run(ctx)
	<-started

	if err := lane.submit(ctx, "queued_normal", func(context.Context) error {
		order <- "normal"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	urgentDone := make(chan error, 1)
	go func() {
		urgentDone <- lane.submitUrgentAndWait(ctx, "ownership_lease_watchdog", func(context.Context) error {
			order <- "urgent"
			return nil
		})
	}()

	deadline := time.After(time.Second)
	for lane.urgentLen() == 0 {
		select {
		case <-deadline:
			t.Fatal("urgent watchdog was not queued")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(release)

	select {
	case got := <-order:
		if got != "urgent" {
			t.Fatalf("first queued command=%q, want urgent watchdog", got)
		}
	case <-time.After(time.Second):
		t.Fatal("urgent watchdog did not run")
	}
	select {
	case err := <-urgentDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("urgent watchdog submit did not finish")
	}
	select {
	case got := <-order:
		if got != "normal" {
			t.Fatalf("second queued command=%q, want normal", got)
		}
	case <-time.After(time.Second):
		t.Fatal("queued normal command did not run")
	}
}

func TestDataplaneCommandLaneBoundsNormalWorkToLeaseDeadlineAndChecksImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lane := newDataplaneCommandLane(slog.New(slog.NewTextHandler(io.Discard, nil)))
	deadline := time.Now().Add(25 * time.Millisecond)
	checked := make(chan struct{}, 1)
	lane.setLeaseGuard(func() (time.Time, bool) { return deadline, true }, func(context.Context) error {
		checked <- struct{}{}
		return nil
	})
	go lane.run(ctx)

	err := lane.submitAndWait(ctx, "bounded_normal", func(commandCtx context.Context) error {
		<-commandCtx.Done()
		return commandCtx.Err()
	})
	if err != context.DeadlineExceeded {
		t.Fatalf("bounded normal command error=%v, want deadline exceeded", err)
	}
	select {
	case <-checked:
	case <-time.After(time.Second):
		t.Fatal("lease expiry check did not run immediately after bounded command")
	}
}

func TestDesiredStateAuthorityAckTransportRunsOutsideLane(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	lane := newDataplaneCommandLane(logger)
	laneDone := make(chan struct{})
	go func() {
		lane.run(ctx)
		close(laneDone)
	}()

	desired := reconcile.DesiredState{ProtocolVersion: 1, Version: 1, NodeID: "99999999-9999-9999-9999-999999999999"}
	hash, err := ownershiplease.BaseStateHash(desired)
	if err != nil {
		t.Fatal(err)
	}
	desired.KubernetesOwnershipBaseAuthority = &reconcile.KubernetesOwnershipBaseAuthority{
		WireVersion: 1, AuthorityRevision: 1, NodeID: desired.NodeID,
		OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222",
		BaseVersion: desired.Version, BaseHash: hash,
		Classifications: []reconcile.KubernetesOwnershipPoolClassification{{
			Scope:       reconcile.KubernetesOwnershipPoolScope{OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222", ClusterID: "33333333-3333-3333-3333-333333333333", PoolID: "44444444-4444-4444-4444-444444444444"},
			Disposition: "arm_fence",
			Fields:      reconcile.KubernetesOwnershipPoolFields{Routes: []string{"10.44.0.0/16"}, WGPeers: []reconcile.KubernetesOwnershipWGPeer{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.44.0.0/16"}}}},
		}},
	}
	dir := t.TempDir()
	coordinator := ownershiplease.NewCoordinator(ownershiplease.NewProjector(), emptyAuthorityDomain{}, ownershiplease.NewFileFenceStore(filepath.Join(dir, "fences.json"))).
		WithBaseAuthorityStateStore(ownershiplease.NewFileBaseAuthorityStateStore(filepath.Join(dir, "authority.json")))
	reconciler := reconcile.New(reconcile.NewMemBackend(), "", "", logger)
	reconciler.OnDesired(func(commandCtx context.Context, state reconcile.DesiredState) (reconcile.DesiredState, error) {
		return coordinator.UpdateBaseAndSnapshot(commandCtx, state, ownershiplease.BaseAuthorityFromWire(state.KubernetesOwnershipBaseAuthority))
	})
	client := &laneProbingAuthorityClient{desired: desired, lane: lane, posted: make(chan reconcile.KubernetesOwnershipBaseAuthorityAck, 1)}
	done := make(chan struct{})
	go func() {
		produceDesiredStateCommands(ctx, lane, reconciler, client, coordinator, time.Hour, time.Second, logger)
		close(done)
	}()
	select {
	case ack := <-client.posted:
		if ack.AuthorityRevision != 1 || ack.BaseHash != hash {
			t.Fatalf("posted ack=%+v", ack)
		}
		cancel()
	case <-time.After(3 * time.Second):
		t.Fatal("authority ACK transport blocked on the mutation lane")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("desired-state producer did not stop")
	}
	select {
	case <-laneDone:
	case <-time.After(time.Second):
		t.Fatal("command lane did not stop")
	}
}
