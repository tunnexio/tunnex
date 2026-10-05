package sandboxruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
)

type fakeCgroupNode struct {
	parent   string
	fences   atomic.Int32
	closed   atomic.Int32
	fenceErr error
	checkErr error
	frozen   bool
}

func (n *fakeCgroupNode) Parent() string { return n.parent }
func (n *fakeCgroupNode) Frozen() bool   { return n.frozen }
func (n *fakeCgroupNode) Fence() error   { n.fences.Add(1); return n.fenceErr }
func (n *fakeCgroupNode) CheckRuntime(parent string, pid int, running bool) error {
	if parent != n.parent || running && pid <= 0 || !running && pid != 0 {
		return ErrOwnership
	}
	if running {
		return n.checkErr
	}
	return nil
}
func (n *fakeCgroupNode) Close() error { n.closed.Add(1); return nil }

type fakeCgroupBackend struct {
	node      *fakeCgroupNode
	createErr error
	calls     int
}

func (b *fakeCgroupBackend) Create(uuid.UUID) (cgroupLeaseNode, error) {
	b.calls++
	return b.node, b.createErr
}
func (b *fakeCgroupBackend) Close() error { return nil }
func guardFixture(t *testing.T, lifetime time.Duration) (*ActorCgroupLeaseGuard, *CgroupLeaseScope, sandboxrunner.Lease, *fakeCgroupNode) {
	t.Helper()
	node := &fakeCgroupNode{parent: "/owned/actor/sandbox-" + uuid.NewString()}
	g := newCgroupLeaseGuard(&fakeCgroupBackend{node: node})
	t.Cleanup(func() { _ = g.Close() })
	now := time.Now()
	l := sandboxrunner.Lease{SandboxID: uuid.New(), Generation: 1, CreatedAt: now, ExpiresAt: now.Add(lifetime)}
	s, err := g.Prepare(l)
	if err != nil {
		t.Fatal(err)
	}
	return g, s, l, node
}
func awaitFence(t *testing.T, n *fakeCgroupNode) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for n.fences.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n.fences.Load() != 1 {
		t.Fatal("independent expiry did not fence exactly once", n.fences.Load())
	}
}

func TestCgroupLeaseDeadlineIndependentOfEffectAndGuardLocks(t *testing.T) {
	g, s, l, node := guardFixture(t, 100*time.Millisecond)
	var effects sync.Mutex
	effects.Lock()
	defer effects.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	awaitFence(t, node)
	if _, err := leaseScope(s.Context(context.Background()), l.SandboxID, true); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expired launch accepted", err)
	}
	if _, err := leaseScope(s.Context(context.Background()), l.SandboxID, false); err != nil {
		t.Fatal("expired cleanup refused", err)
	}
}

func TestCgroupLeaseOriginalIntervalAndGenerationAreImmutable(t *testing.T) {
	g, old, l, node := guardFixture(t, time.Minute)
	next := l
	next.Generation = 2
	s, err := g.Prepare(next)
	if err != nil || s.Generation() != 2 {
		t.Fatal(err)
	}
	if _, err := leaseScope(old.Context(context.Background()), l.SandboxID, true); !errors.Is(err, ErrUnavailable) {
		t.Fatal("stale generation launch accepted", err)
	}
	if _, err := leaseScope(old.Context(context.Background()), l.SandboxID, false); err != nil {
		t.Fatal("owned old-generation cleanup rejected", err)
	}
	if _, err := g.Prepare(l); !errors.Is(err, ErrOwnership) {
		t.Fatal("generation decreased", err)
	}
	for _, mutate := range []func(*sandboxrunner.Lease){func(v *sandboxrunner.Lease) { v.ExpiresAt = v.ExpiresAt.Add(time.Second) }, func(v *sandboxrunner.Lease) { v.CreatedAt = v.CreatedAt.Add(time.Second) }} {
		changed := next
		mutate(&changed)
		if _, err := g.Prepare(changed); !errors.Is(err, ErrOwnership) {
			t.Fatal("original interval replaced", err)
		}
	}
	if node.fences.Load() != 0 {
		t.Fatal("invalid authorization fenced a valid scope")
	}
}

func TestCgroupLeaseKernelFailureSignalsActorAndNeverThaws(t *testing.T) {
	node := &fakeCgroupNode{parent: "/owned/child", fenceErr: errors.New("denied")}
	g := newCgroupLeaseGuard(&fakeCgroupBackend{node: node})
	defer g.Close()
	now := time.Now()
	l := sandboxrunner.Lease{SandboxID: uuid.New(), Generation: 1, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(-time.Second)}
	if _, err := g.Prepare(l); err == nil {
		t.Fatal("failed native fence accepted")
	}
	select {
	case <-g.Fatal():
	case <-time.After(time.Second):
		t.Fatal("actor termination not signaled")
	}
	l.Generation++
	if _, err := g.Prepare(l); err == nil || node.fences.Load() != 1 {
		t.Fatal("failed fence retried as a new lease")
	}
}

func TestCgroupLeaseInvalidNativeScopeFailsClosed(t *testing.T) {
	g := newCgroupLeaseGuard(&fakeCgroupBackend{createErr: ErrOwnership})
	defer g.Close()
	now := time.Now()
	l := sandboxrunner.Lease{SandboxID: uuid.New(), Generation: 1, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if _, err := g.Prepare(l); !errors.Is(err, ErrOwnership) {
		t.Fatal(err)
	}
	select {
	case <-g.Fatal():
	default:
		t.Fatal("unknown populated scope did not signal actor termination")
	}
}

func TestCgroupLeaseCloseFencesBeforeReleasingDescriptors(t *testing.T) {
	g, s, l, node := guardFixture(t, time.Minute)
	if err := g.Close(); err != nil || node.fences.Load() != 1 || node.closed.Load() != 1 {
		t.Fatal("close left active deadline unfenced", err)
	}
	if _, err := leaseScope(s.Context(context.Background()), l.SandboxID, true); err == nil {
		t.Fatal("closed guard context launched")
	}
	if _, err := g.Prepare(l); err == nil {
		t.Fatal("closed guard rearmed")
	}
}

func TestGuardedPodmanRejectsMissingForeignStaleAndBroadLaunch(t *testing.T) {
	g, s, l, _ := guardFixture(t, time.Minute)
	f := &fakeRunner{responses: func([]string) ([]byte, error) { return nil, nil }}
	p := NewPodman(f)
	p.leaseGuard = g
	spec := Spec{ID: l.SandboxID, ImageDigest: "sha256:" + strings.Repeat("a", 64), MemoryMiB: 128, CPUs: 1, PIDs: 64}
	if err := p.Create(context.Background(), spec); !errors.Is(err, ErrOwnership) {
		t.Fatal("missing token launched", err)
	}
	_, foreign, _, _ := guardFixture(t, time.Minute)
	if err := p.Create(foreign.Context(context.Background()), spec); !errors.Is(err, ErrOwnership) {
		t.Fatal("foreign token launched", err)
	}
	broad := spec
	broad.PIDs = 128
	if err := p.Create(s.Context(context.Background()), broad); !errors.Is(err, ErrOwnership) {
		t.Fatal("broader scope launched", err)
	}
	l.Generation = 2
	if _, err := g.Prepare(l); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(s.Context(context.Background()), l.SandboxID); !errors.Is(err, ErrUnavailable) {
		t.Fatal("stale scope started", err)
	}
	if len(f.calls) != 0 {
		t.Fatal("denied launch reached provider")
	}
}

func TestGuardedPodmanPinsPlacementAndVerifiesActualStart(t *testing.T) {
	g, scope, lease, node := guardFixture(t, time.Minute)
	created, running := false, false
	parent := node.parent
	spec := Spec{ID: lease.SandboxID, ImageDigest: "sha256:" + strings.Repeat("a", 64), MemoryMiB: 128, CPUs: 1, PIDs: 64}
	hash, _ := Fingerprint(spec)
	f := &fakeRunner{responses: func(args []string) ([]byte, error) {
		switch args[0] {
		case "info":
			return []byte("true"), nil
		case "container":
			if !created {
				return nil, ErrMissing
			}
			return nil, nil
		case "create":
			created = true
			return nil, nil
		case "start":
			running = true
			return nil, nil
		case "inspect":
			pid := 0
			if running {
				pid = 42
			}
			return json.Marshal([]any{map[string]any{"Id": strings.Repeat("b", 64), "Image": spec.ImageDigest, "Config": map[string]any{"Labels": map[string]string{ownerLabel: lease.SandboxID.String(), specLabel: hash}}, "State": map[string]any{"Running": running, "Pid": pid}, "HostConfig": map[string]any{"CgroupParent": parent}}})
		}
		return nil, nil
	}}
	p := NewPodman(f)
	p.leaseGuard = g
	ctx := scope.Context(context.Background())
	if err := p.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, call := range f.calls {
		if call[0] == "create" {
			argv := strings.Join(call, " ")
			found = strings.Contains(argv, "--cgroups=enabled --cgroup-parent "+node.parent+" ")
		}
	}
	if !found {
		t.Fatal("trusted scope placement missing")
	}
	parent = "/foreign/parent"
	before := len(f.calls)
	if err := p.Start(ctx, lease.SandboxID); !errors.Is(err, ErrOwnership) {
		t.Fatal("configured parent drift started", err)
	}
	for _, call := range f.calls[before:] {
		if call[0] == "start" {
			t.Fatal("start preceded parent proof")
		}
	}
	parent = node.parent
	node.checkErr = ErrOwnership
	if err := p.Start(ctx, lease.SandboxID); !errors.Is(err, ErrOwnership) {
		t.Fatal("payload placement mismatch acknowledged", err)
	}
	select {
	case <-g.Fatal():
	default:
		t.Fatal("running payload placement failure did not terminate actor")
	}
}

func TestGuardedPodmanExpiryFencesDuringBlockedCreate(t *testing.T) {
	g, scope, lease, node := guardFixture(t, 100*time.Millisecond)
	entered, release := make(chan struct{}), make(chan struct{})
	f := &fakeRunner{responses: func(args []string) ([]byte, error) {
		switch args[0] {
		case "info":
			return []byte("true"), nil
		case "container":
			return nil, ErrMissing
		case "create":
			close(entered)
			<-release
			return nil, ErrUnavailable
		}
		return nil, nil
	}}
	p := NewPodman(f)
	p.leaseGuard = g
	done := make(chan error, 1)
	go func() {
		done <- p.Create(scope.Context(context.Background()), Spec{ID: lease.SandboxID, ImageDigest: "sha256:" + strings.Repeat("a", 64), MemoryMiB: 128, CPUs: 1, PIDs: 64})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("create never entered")
	}
	awaitFence(t, node)
	close(release)
	if err := <-done; err == nil {
		t.Fatal("expired blocked create succeeded")
	}
	if err := p.Start(scope.Context(context.Background()), lease.SandboxID); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expired start accepted", err)
	}
}
