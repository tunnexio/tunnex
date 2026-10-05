package sandboxruntime

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
)

// The guard is an execution fence, independent of actor/provider effect locks.
// It does not withdraw WireGuard peers, remove provider metadata, or release an
// address. Those effects still require confirmed normal lifecycle cleanup.
const actorControlCgroup = "/tnxsandboxqual.slice/tunnex-sandbox-qual-actor.service/control"
const maxGuardScopes = 256

var actorControlPath = regexp.MustCompile(`^/[A-Za-z0-9][A-Za-z0-9_.-]*\.slice/[A-Za-z0-9][A-Za-z0-9_.-]*\.service/control$`)

// ValidActorControlCgroup accepts one explicitly supervised service subtree.
// The path is trusted deployment input; workload requests never select it.
func ValidActorControlCgroup(control string) bool {
	return len(control) <= 256 && actorControlPath.MatchString(control)
}

type cgroupLeaseNode interface {
	Parent() string
	Frozen() bool
	Fence() error
	CheckRuntime(parent string, pid int, running bool) error
	Close() error
}
type cgroupLeaseBackend interface {
	Create(uuid.UUID) (cgroupLeaseNode, error)
	Close() error
}

type cgroupLeaseRecord struct {
	id               uuid.UUID
	created, expires time.Time
	generation       atomic.Int64
	expired          atomic.Bool
	node             cgroupLeaseNode
	timer            *time.Timer
	fenceOnce        sync.Once
	fenceErr         error
}

// ActorCgroupLeaseGuard owns only its fixed delegated actor subtree. Fatal
// errors must terminate the actor, whose systemd unit kills its complete tree.
// Configure and close it within that actor lifetime, never the transport's.
type ActorCgroupLeaseGuard struct {
	mu      sync.Mutex
	backend cgroupLeaseBackend
	records map[uuid.UUID]*cgroupLeaseRecord
	fatal   chan error
	closed  bool
}

// CgroupLeaseScope is an opaque immutable generation view. No caller supplies
// a cgroup path, host PID, arbitrary resource limits or placement argv.
type CgroupLeaseScope struct {
	guard      *ActorCgroupLeaseGuard
	record     *cgroupLeaseRecord
	generation int64
}
type cgroupLeaseContextKey struct{}

func newCgroupLeaseGuard(backend cgroupLeaseBackend) *ActorCgroupLeaseGuard {
	return &ActorCgroupLeaseGuard{backend: backend, records: make(map[uuid.UUID]*cgroupLeaseRecord), fatal: make(chan error, 1)}
}

func validCgroupLease(l sandboxrunner.Lease) bool {
	return l.SandboxID != uuid.Nil && l.Generation > 0 && !l.CreatedAt.IsZero() && l.ExpiresAt.After(l.CreatedAt) && l.ExpiresAt.Sub(l.CreatedAt) <= 900*time.Second
}

func (g *ActorCgroupLeaseGuard) fail(err error) {
	if err != nil {
		select {
		case g.fatal <- errors.Join(ErrUnavailable, err):
		default:
		}
	}
}

func (g *ActorCgroupLeaseGuard) fence(r *cgroupLeaseRecord) error {
	// Mark before any I/O. Provider launch refuses even if a kernel write fails;
	// the separate fatal path then terminates the complete actor service tree.
	r.expired.Store(true)
	r.fenceOnce.Do(func() { r.fenceErr = r.node.Fence(); g.fail(r.fenceErr) })
	return r.fenceErr
}

// Prepare arms the original absolute expiry before returning a launch context.
// Forward generations preserve the timer and parent; they never thaw a scope.
// Expired scopes remain frozen for this actor lifetime, preventing a late
// provider call from executing after it finally completes. Expired cleanup is
// allowed. A stale generation may still use its existing view for cleanup, but
// can never launch once a newer view has been prepared.
func (g *ActorCgroupLeaseGuard) Prepare(l sandboxrunner.Lease) (*CgroupLeaseScope, error) {
	if g == nil || !validCgroupLease(l) {
		return nil, ErrInvalid
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.backend == nil {
		return nil, ErrUnavailable
	}
	r := g.records[l.SandboxID]
	if r != nil {
		if !r.created.Equal(l.CreatedAt) || !r.expires.Equal(l.ExpiresAt) || l.Generation < r.generation.Load() {
			return nil, ErrOwnership
		}
		r.generation.Store(l.Generation)
	} else {
		if len(g.records) >= maxGuardScopes {
			return nil, ErrUnavailable
		}
		node, err := g.backend.Create(l.SandboxID)
		if err != nil {
			g.fail(err)
			return nil, err
		}
		r = &cgroupLeaseRecord{id: l.SandboxID, created: l.CreatedAt, expires: l.ExpiresAt, node: node}
		r.generation.Store(l.Generation)
		g.records[l.SandboxID] = r
		if node.Frozen() {
			r.expired.Store(true)
		}
		// This callback never obtains g.mu or the actor/provider effect mutex.
		r.timer = time.AfterFunc(max(0, time.Until(l.ExpiresAt)), func() { _ = g.fence(r) })
	}
	if r.expired.Load() || !time.Now().Before(r.expires) {
		if err := g.fence(r); err != nil {
			return nil, err
		}
	}
	return &CgroupLeaseScope{guard: g, record: r, generation: l.Generation}, nil
}

func (s *CgroupLeaseScope) Generation() int64 {
	if s == nil {
		return 0
	}
	return s.generation
}

// Context is only for a validated actor-owned lease. Token details are private
// to this package and cannot originate in the worker JSON protocol.
func (s *CgroupLeaseScope) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, cgroupLeaseContextKey{}, s)
}

func (g *ActorCgroupLeaseGuard) Fatal() <-chan error { return g.fatal }

// Close fences before releasing descriptors. Closing cannot silently disable
// an active lease deadline while retained children continue executing.
func (g *ActorCgroupLeaseGuard) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	var err error
	for _, r := range g.records {
		r.timer.Stop()
		err = errors.Join(err, g.fence(r), r.node.Close())
	}
	return errors.Join(err, g.backend.Close())
}

func leaseScope(ctx context.Context, id uuid.UUID, launch bool) (*CgroupLeaseScope, error) {
	s, _ := ctx.Value(cgroupLeaseContextKey{}).(*CgroupLeaseScope)
	if s == nil {
		return nil, nil
	} // Existing unsplit providers preserve behavior.
	if s.guard == nil || s.record == nil || s.record.id != id || s.generation > s.record.generation.Load() {
		return nil, ErrOwnership
	}
	if launch && (s.generation != s.record.generation.Load() || s.record.expired.Load() || !time.Now().Before(s.record.expires)) {
		return nil, ErrUnavailable
	}
	return s, nil
}

func (s *CgroupLeaseScope) checkSpec(spec Spec) error {
	if spec.ID != s.record.id || spec.MemoryMiB != 128 || spec.PIDs != 64 || spec.CPUs != 1 {
		return ErrOwnership
	}
	return nil
}
