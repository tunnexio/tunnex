package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

func actorLeaseStore(t *testing.T, s *WorkerRPCServer) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	s.LeaseStore = &sandboxrunner.LeaseStore{Root: root}
	return root
}

func actorReadRecord[T any](t *testing.T, root *os.Root, name string) T {
	t.Helper()
	f, err := root.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out T
	if err = json.NewDecoder(f).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func actorLease(a RuntimeAuthorization) sandboxrunner.Lease {
	return sandboxrunner.Lease{SandboxID: a.SandboxID, Generation: a.Generation, CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt}
}

func TestRuntimeActorAuthorizationPersistsOnlyValidatedImmutableLifetime(t *testing.T) {
	b := persistentTestBinding()
	s, c, _ := persistentRPCFixture(t, b)
	root := actorLeaseStore(t, s)
	a := testAuthorization(b, 0)
	foreign := a
	foreign.OrgID = uuid.New()
	if err := c.AuthorizeRuntime(context.Background(), foreign); err == nil {
		t.Fatal("foreign authorization accepted")
	}
	if _, err := root.Stat(a.SandboxID.String() + ".lease.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected authorization published lease", err)
	}
	if err := c.AuthorizeRuntime(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if got := actorReadRecord[sandboxrunner.Lease](t, root, a.SandboxID.String()+".lease.json"); got != actorLease(a) {
		t.Fatal("lease differs from original grant", got)
	}
	// Replaying an already validated grant repairs a missing local lease with
	// exactly its original timestamps, rather than starting a fresh TTL.
	if err := root.Remove(a.SandboxID.String() + ".lease.json"); err != nil {
		t.Fatal(err)
	}
	if err := c.AuthorizeRuntime(context.Background(), a); err != nil {
		t.Fatal("same-generation repair", err)
	}
	a.Generation++
	a.Desired = "stopped"
	if err := c.AuthorizeRuntime(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*RuntimeAuthorization){
		func(a *RuntimeAuthorization) { a.ExpiresAt = a.ExpiresAt.Add(time.Second) },
		func(a *RuntimeAuthorization) { a.Generation-- },
		func(a *RuntimeAuthorization) { a.Desired = "deleted" },
		func(a *RuntimeAuthorization) { a.SandboxID = uuid.New() },
	} {
		bad := a
		change(&bad)
		if err := c.AuthorizeRuntime(context.Background(), bad); err == nil {
			t.Fatal("mutated authorization accepted", bad)
		}
		got := actorReadRecord[sandboxrunner.Lease](t, root, a.SandboxID.String()+".lease.json")
		if got != actorLease(a) || s.active.Generation != a.Generation || s.active.Desired != a.Desired {
			t.Fatal("rejected authorization changed lease/pin", got)
		}
	}
}

func TestRuntimeActorLeaseFailurePreventsExecutionGrant(t *testing.T) {
	b := persistentTestBinding()
	s, c, _ := persistentRPCFixture(t, b)
	root := actorLeaseStore(t, s)
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.AuthorizeRuntime(context.Background(), testAuthorization(b, 0)); err == nil {
		t.Fatal("failed durable lease granted execution")
	}
	if s.active != nil || s.sandboxID != uuid.Nil {
		t.Fatal("failed durable lease changed in-memory grant")
	}
	if _, err := s.ControlRoot.Stat("api-binding.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed durable lease published pin", err)
	}
}

func TestRuntimeActorGuardFailureLeavesOnlyInertDurableLifetime(t *testing.T) {
	for _, haveStore := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-store", true: "guard-unavailable"}[haveStore], func(t *testing.T) {
			s, c, _ := persistentRPCFixture(t, persistentTestBinding())
			var root *os.Root
			if haveStore {
				root = actorLeaseStore(t, s)
			}
			// The zero guard has no backend and refuses preparation. This fixture
			// does not create cgroups or claim native deadline enforcement.
			s.LeaseGuard = &sandboxruntime.ActorCgroupLeaseGuard{}
			a := testAuthorization(s.Binding, 0)
			if err := c.AuthorizeRuntime(context.Background(), a); err == nil {
				t.Fatal("unarmed guard published an execution grant")
			}
			if s.active != nil || s.sandboxID != uuid.Nil || s.actorScope != nil {
				t.Fatal("failed guard changed in-memory authority")
			}
			if _, err := s.ControlRoot.Stat("api-binding.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed guard published pin", err)
			}
			if haveStore {
				if got := actorReadRecord[sandboxrunner.Lease](t, root, a.SandboxID.String()+".lease.json"); got != actorLease(a) {
					t.Fatal("failed guard changed durable original lifetime", got)
				}
			}
		})
	}
}

// All provider methods used by the concurrent actor fixture are synchronized.
// A success from Stop can deliberately leave execution running or make its
// confirmation unavailable; either must keep expiry pending without a receipt.
type actorProviderFixture struct {
	sandboxruntime.Provider
	mu                          sync.Mutex
	status                      sandboxruntime.Status
	sandboxID                   uuid.UUID
	stops, inspections          int
	stopErr, confirmationErr    error
	unpinnedErr                 error
	leaveRunning, replaceOnStop bool
	entered, release            chan struct{}
}

func (p *actorProviderFixture) Inspect(_ context.Context, id uuid.UUID) (sandboxruntime.Status, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inspections++
	if id != p.sandboxID {
		if p.unpinnedErr != nil {
			return sandboxruntime.Status{}, p.unpinnedErr
		}
		return sandboxruntime.Status{}, sandboxruntime.ErrMissing
	}
	if p.stops > 0 && p.confirmationErr != nil {
		return sandboxruntime.Status{}, p.confirmationErr
	}
	return p.status, nil
}

func (p *actorProviderFixture) Stop(ctx context.Context, _ uuid.UUID) error {
	p.mu.Lock()
	p.stops++
	entered, release := p.entered, p.release
	p.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopErr != nil {
		return p.stopErr
	}
	if !p.leaveRunning {
		p.status.Running = false
	}
	if p.replaceOnStop {
		p.status.RuntimeID = strings.Repeat("b", 64)
	}
	return nil
}

func (p *actorProviderFixture) running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status.Running
}

func actorExpiredFixture(t *testing.T) (*WorkerRPCServer, *WorkerRPCClient, *actorProviderFixture, RuntimeAuthorization, *os.Root) {
	t.Helper()
	b := persistentTestBinding()
	s, c, _ := persistentRPCFixture(t, b)
	root := actorLeaseStore(t, s)
	a := testAuthorization(b, 0)
	a.Desired = "stopped"
	a.CreatedAt = time.Now().UTC().Add(-301 * time.Second)
	a.ExpiresAt = a.CreatedAt.Add(300 * time.Second)
	if err := c.AuthorizeRuntime(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	hash, _ := sandboxruntime.Fingerprint(a.spec())
	p := &actorProviderFixture{sandboxID: a.SandboxID, status: sandboxruntime.Status{Exists: true, Running: true, RuntimeID: strings.Repeat("a", 64), ImageDigest: a.Profile.ConfigDigest, SpecHash: hash}}
	s.Provider = p
	return s, c, p, a, root
}

func TestRuntimeActorConfirmsExactExecutionBeforeExpiryReceipt(t *testing.T) {
	for _, scenario := range []string{"stop-error", "still-running", "confirmation-error", "replacement", "owned-runtime-mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, p, a, root := actorExpiredFixture(t)
			switch scenario {
			case "stop-error":
				p.stopErr = sandboxruntime.ErrUnavailable
			case "still-running":
				p.leaveRunning = true
			case "confirmation-error":
				p.confirmationErr = sandboxruntime.ErrUnavailable
			case "replacement":
				p.replaceOnStop = true
			case "owned-runtime-mismatch":
				p.status.SpecHash = strings.Repeat("c", 64)
			}
			if err := s.sweepRuntimeActor(context.Background(), time.Now().UTC()); err == nil {
				t.Fatal("uncertain execution accepted")
			}
			if _, err := root.Stat(a.SandboxID.String() + ".expired.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("uncertain execution wrote receipt", err)
			}
			if scenario == "owned-runtime-mismatch" && p.stops != 0 {
				t.Fatal("foreign execution stopped")
			}
			p.stopErr, p.confirmationErr = nil, nil
			p.leaveRunning, p.replaceOnStop = false, false
			hash, _ := sandboxruntime.Fingerprint(a.spec())
			p.status.SpecHash = hash
			p.status.RuntimeID = strings.Repeat("a", 64)
			if err := s.sweepRuntimeActor(context.Background(), time.Now().UTC()); err != nil {
				t.Fatal("retry failed", err)
			}
			receipt := actorReadRecord[sandboxrunner.ExpiryReceipt](t, root, a.SandboxID.String()+".expired.json")
			if receipt.Lease != actorLease(a) || receipt.StoppedAt.Before(a.ExpiresAt) || p.running() {
				t.Fatal("invalid confirmed expiry receipt", receipt)
			}
		})
	}
}

type actorFilesFixture struct {
	LaunchControlTransport
	provider      *actorProviderFixture
	err           error
	reads         int
	runningAtRead bool
}

func (f *actorFilesFixture) ReadPrivateNetworkConfig(context.Context, PrivateNetworkTarget) ([]byte, error) {
	f.reads++
	f.runningAtRead = f.provider.running()
	return []byte("fixture-owned-config"), f.err
}

type actorNetworkFixture struct {
	PrivateNetworkControl
	removals int
}

func (n *actorNetworkFixture) RemovePrivateNetwork(context.Context, PrivateNetworkTarget, []byte) error {
	n.removals++
	return ErrDisabled
}

func TestRuntimeActorNetworkFailureCannotPreventExecutionFence(t *testing.T) {
	for _, readFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "withdrawal-fails", true: "config-read-fails"}[readFails], func(t *testing.T) {
			s, _, p, a, root := actorExpiredFixture(t)
			files := &actorFilesFixture{provider: p}
			if readFails {
				files.err = ErrDisabled
			}
			network := &actorNetworkFixture{}
			s.Files, s.Network = files, network
			pin := s.currentPin()
			pin.Epoch = &PrivateNetworkTarget{SandboxID: a.SandboxID, RuntimeID: p.status.RuntimeID}
			pin.EpochGeneration = a.Generation
			if err := s.writePin(pin); err != nil {
				t.Fatal(err)
			}
			if err := s.sweepRuntimeActor(context.Background(), time.Now().UTC()); err != nil {
				t.Fatal("network failure blocked confirmed execution fence", err)
			}
			if p.running() || files.reads != 1 || files.runningAtRead || (!readFails && network.removals != 1) {
				t.Fatal("stop was not confirmed before network attempt")
			}
			_ = actorReadRecord[sandboxrunner.ExpiryReceipt](t, root, a.SandboxID.String()+".expired.json")
			if err := s.loadPin(); err != nil || s.withdrawn || s.epoch == nil || s.active.Desired != a.Desired || s.active.Generation != a.Generation {
				t.Fatal("offline receipt changed canonical cleanup state", err)
			}
		})
	}
}

func TestRuntimeActorLeaseAheadOfPinStillFencesOriginalLifetime(t *testing.T) {
	s, _, p, a, root := actorExpiredFixture(t)
	// Force durable pin publication to fail after Put of a valid stop generation.
	// Reopen the original root to model recovery of the unchanged old pin.
	next := a
	next.Generation++
	pin := s.currentPin()
	pin.Authorization = &next
	controlPath := s.ControlRoot.Name()
	if err := s.ControlRoot.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.writeAuthorizedPin(pin); err == nil {
		t.Fatal("pin failure was not injected")
	}
	control, err := os.OpenRoot(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	s.ControlRoot = control
	lease := actorReadRecord[sandboxrunner.Lease](t, root, a.SandboxID.String()+".lease.json")
	if lease != actorLease(next) || s.active.Generation != a.Generation {
		t.Fatal("failure was not between lease and pin publication", lease)
	}
	if err := s.sweepRuntimeActor(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if p.running() || s.active.Generation != a.Generation {
		t.Fatal("lease/pin crash window broadened canonical grant or skipped stop")
	}
	if got := actorReadRecord[sandboxrunner.ExpiryReceipt](t, root, a.SandboxID.String()+".expired.json"); got.Lease != lease {
		t.Fatal("receipt did not retain exact durable lifetime", got)
	}
}

func TestRuntimeActorRestartRestoresLeaseAheadOfPublishedPin(t *testing.T) {
	s, c, _ := persistentRPCFixture(t, persistentTestBinding())
	root := actorLeaseStore(t, s)
	a := testAuthorization(s.Binding, 0)
	if err := c.AuthorizeRuntime(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	// Model successful Put followed by failed pin publication. The original
	// interval remains unexpired, so an expiry sweep does not repair this gap.
	next := a
	next.Generation++
	next.Desired = "stopped"
	if err := s.LeaseStore.Put(actorLease(next)); err != nil {
		t.Fatal(err)
	}
	restarted := &WorkerRPCServer{Binding: s.Binding, ControlRoot: s.ControlRoot, LeaseStore: &sandboxrunner.LeaseStore{Root: root}}
	if err := restarted.loadPin(); err != nil {
		t.Fatal(err)
	}
	if restarted.active.Generation != a.Generation || restarted.actorScope != nil {
		t.Fatal("restart did not restore only the old published pin")
	}
	restored, err := restarted.restoreActorAuthorization(*restarted.active)
	if err != nil || restored.Generation != next.Generation || !sameWorkload(restored, a) {
		t.Fatal("restart lowered the durable generation or changed lifetime", restored, err)
	}
	if restarted.active.Generation != a.Generation || restored.Generation == restarted.active.Generation {
		t.Fatal("lease restoration broadened the published execution grant")
	}
	// A later valid canonical publication can converge on the retained fence;
	// the local durable timestamp and generation are never restarted or lowered.
	if err := c.AuthorizeRuntime(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if err := restarted.loadPin(); err != nil {
		t.Fatal(err)
	}
	restored, err = restarted.restoreActorAuthorization(*restarted.active)
	if err != nil || restored.Generation != restarted.active.Generation || actorLease(restored) != actorLease(next) {
		t.Fatal("new canonical generation could not recover", restored, err)
	}
	if err := root.Remove(a.SandboxID.String() + ".lease.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.restoreActorAuthorization(*restarted.active); err == nil {
		t.Fatal("missing durable lease recreated cached authority")
	}
}

func TestRuntimeActorHistoricalAndOrphanLeasesCannotStarveActiveExpiry(t *testing.T) {
	for _, scenario := range []string{"completed", "orphan-absent", "orphan-unconfirmed", "completed-corrupt", "completed-lifetime-mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, p, a, root := actorExpiredFixture(t)
			old := a
			old.SandboxID = uuid.New()
			old.Desired = "deleted"
			if err := s.LeaseStore.Put(actorLease(old)); err != nil {
				t.Fatal(err)
			}
			expectPending := false
			switch scenario {
			case "completed", "completed-corrupt", "completed-lifetime-mismatch":
				marker := workerPin{Binding: s.Binding, SandboxID: old.SandboxID, Authorization: &old}
				if scenario == "completed-lifetime-mismatch" {
					copy := old
					copy.CreatedAt = copy.CreatedAt.Add(-time.Second)
					marker.Authorization = &copy
					expectPending = true
				}
				raw, err := json.Marshal(marker)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "completed-corrupt" {
					raw, expectPending = []byte("{"), true
				}
				if err := s.writeRecord(completedName(old.SandboxID), raw); err != nil {
					t.Fatal(err)
				}
			case "orphan-unconfirmed":
				p.unpinnedErr, expectPending = sandboxruntime.ErrUnavailable, true
			}
			err := s.sweepRuntimeActor(context.Background(), time.Now().UTC())
			if (err != nil) != expectPending {
				t.Fatal("unexpected historical cleanup result", err)
			}
			if p.running() || p.stops != 1 || s.active.SandboxID != a.SandboxID || s.active.Generation != a.Generation {
				t.Fatal("historical lease altered or starved active expiry")
			}
			_ = actorReadRecord[sandboxrunner.ExpiryReceipt](t, root, a.SandboxID.String()+".expired.json")
			_, receiptErr := root.Stat(old.SandboxID.String() + ".expired.json")
			if expectPending && !errors.Is(receiptErr, os.ErrNotExist) || !expectPending && receiptErr != nil {
				t.Fatal("historical receipt did not preserve uncertainty", receiptErr)
			}
		})
	}
}

func TestRuntimeActorMissingPinDeniesEffectsButRetainsExactExpiryFence(t *testing.T) {
	s, c, p, a, root := actorExpiredFixture(t)
	if err := s.ControlRoot.Remove("api-binding.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Inspect(context.Background(), a.SandboxID); err == nil {
		t.Fatal("missing durable pin retained command authority")
	}
	if p.inspections != 0 {
		t.Fatal("missing pin dispatched a provider effect")
	}
	if err := s.sweepRuntimeActor(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal("cached exact identity could not stop after pin loss", err)
	}
	if p.running() || p.stops != 1 {
		t.Fatal("pin loss prevented exact expiry stop")
	}
	_ = actorReadRecord[sandboxrunner.ExpiryReceipt](t, root, a.SandboxID.String()+".expired.json")
	if _, err := c.Inspect(context.Background(), a.SandboxID); err == nil {
		t.Fatal("expiry repaired a missing execution grant")
	}
}

func TestRuntimeActorCorruptPinCannotUseCachedStopAuthority(t *testing.T) {
	s, _, p, a, root := actorExpiredFixture(t)
	if err := s.writeRecord("api-binding.json", []byte("{")); err != nil {
		t.Fatal(err)
	}
	if err := s.sweepRuntimeActor(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("corrupt pin accepted cached identity")
	}
	if p.stops != 0 || !p.running() {
		t.Fatal("corrupt pin triggered a provider stop")
	}
	if _, err := root.Stat(a.SandboxID.String() + ".expired.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupt pin acquired an execution receipt", err)
	}
}

func TestRuntimeActorLifetimeAndEffectSerializationSurviveTransportCancellation(t *testing.T) {
	s, c, p, a, root := actorExpiredFixture(t)
	p.entered, p.release = make(chan struct{}), make(chan struct{})
	transportCtx, disconnect := context.WithCancel(context.Background())
	disconnect()
	if err := c.CheckBinding(transportCtx, s.Binding); !errors.Is(err, context.Canceled) {
		// The portable in-process test transport can return its canceled context
		// through the handler's timeout; cancellation grants no actor ownership.
		if transportCtx.Err() != context.Canceled {
			t.Fatal("transport did not disconnect", err)
		}
	}
	actorCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.RunRuntimeActor(actorCtx, nil) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("actor did not stop")
		}
	}()
	select {
	case <-p.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("boot did not immediately fence expired execution")
	}
	if s.mu.TryLock() {
		s.mu.Unlock()
		t.Fatal("expiry did not hold actor effect mutex")
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), time.Second)
	defer pingCancel()
	if err := c.CheckBinding(pingCtx, s.Binding); err != nil {
		t.Fatal("fixed read-only health blocked behind effect", err)
	}
	a.Generation++
	commandDone := make(chan error, 1)
	go func() { commandDone <- c.AuthorizeRuntime(context.Background(), a) }()
	close(p.release)
	select {
	case err := <-commandDone:
		if err != nil {
			t.Fatal("serialized next generation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expiry deadlocked authorization")
	}
	if p.running() {
		t.Fatal("transport cancellation disabled actor expiry")
	}
	_ = actorReadRecord[sandboxrunner.ExpiryReceipt](t, root, a.SandboxID.String()+".expired.json")
	if got := actorReadRecord[sandboxrunner.Lease](t, root, a.SandboxID.String()+".lease.json"); got != actorLease(a) {
		t.Fatal("serialized authorization lost original lifetime", got)
	}
}

func TestRuntimeActorRequiresExplicitPersistentOptIn(t *testing.T) {
	s, c, _ := persistentRPCFixture(t, persistentTestBinding())
	if err := s.RunRuntimeActor(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("actor enabled without durable lease store", err)
	}
	if err := c.AuthorizeRuntime(context.Background(), testAuthorization(s.Binding, 0)); err != nil {
		t.Fatal("nil-store legacy authorization changed", err)
	}
	actorLeaseStore(t, s)
	s.Binding = boundedTestBinding()
	if err := s.RunRuntimeActor(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nonpersistent actor accepted", err)
	}
}
