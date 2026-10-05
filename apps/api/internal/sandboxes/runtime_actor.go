package sandboxes

import (
	"context"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
)

func authorizationLease(a RuntimeAuthorization) sandboxrunner.Lease {
	return sandboxrunner.Lease{SandboxID: a.SandboxID, Generation: a.Generation, CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt}
}

func (s *WorkerRPCServer) restoreActorAuthorization(a RuntimeAuthorization) (RuntimeAuthorization, error) {
	if !a.valid(s.Binding) || s.LeaseStore == nil {
		return RuntimeAuthorization{}, ErrForbidden
	}
	l, err := s.LeaseStore.Get(a.SandboxID)
	if err != nil {
		return RuntimeAuthorization{}, err
	}
	if l.Generation < a.Generation || !l.CreatedAt.Equal(a.CreatedAt) || !l.ExpiresAt.Equal(a.ExpiresAt) {
		return RuntimeAuthorization{}, ErrConflict
	}
	a.Generation = l.Generation
	return a, nil
}

// actorProviderContext uses only the actor's validated immutable identity. Scope
// tokens never come from the remote request and do not accept caller paths/PIDs.
func (s *WorkerRPCServer) actorProviderContext(ctx context.Context, a RuntimeAuthorization) (context.Context, error) {
	if s.LeaseGuard == nil {
		return ctx, nil
	}
	restored, err := s.restoreActorAuthorization(a)
	if err != nil {
		return nil, err
	}
	if s.actorScope != nil && s.actorScope.Generation() > restored.Generation {
		return nil, ErrConflict
	}
	if s.actorScope == nil || s.actorScopeAuthorization == nil || !sameWorkload(*s.actorScopeAuthorization, restored) || s.actorScope.Generation() != restored.Generation {
		if err := s.prepareActorScope(restored); err != nil {
			return nil, err
		}
	}
	return s.actorScope.Context(ctx), nil
}

func (s *WorkerRPCServer) prepareActorScope(a RuntimeAuthorization) error {
	if s.LeaseGuard == nil {
		return nil
	}
	scope, err := s.LeaseGuard.Prepare(authorizationLease(a))
	if err != nil {
		return err
	}
	copy := a
	s.actorScope, s.actorScopeAuthorization = scope, &copy
	return nil
}

// persistActorLease is called only after authorization's immutable ownership,
// generation and provider checks, while the actor effect mutex is held. A
// failed pin write can leave a bounded lease, but never an execution grant
// without its original durable lifetime. A nil store preserves legacy behavior.
func (s *WorkerRPCServer) persistActorLease(a RuntimeAuthorization) error {
	if s.LeaseStore == nil {
		if s.LeaseGuard != nil {
			return ErrInvalid
		}
		return nil
	}
	if !a.valid(s.Binding) || s.LeaseStore.Root == nil {
		return ErrInvalid
	}
	if err := s.LeaseStore.Put(authorizationLease(a)); err != nil {
		return err
	}
	// Durable lifetime precedes independent arming; both precede the execution
	// pin. A failed guard leaves only an inert lease for bounded recovery.
	return s.prepareActorScope(a)
}

func (s *WorkerRPCServer) writeAuthorizedPin(p workerPin) error {
	if p.Authorization == nil {
		return ErrInvalid
	}
	if err := s.persistActorLease(*p.Authorization); err != nil {
		return err
	}
	return s.writePin(p)
}

func (s *WorkerRPCServer) sweepRuntimeActor(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.LeaseStore.Sweep(ctx, now, s.fenceExpiredRuntimeLocked)
}

// RunRuntimeActor supervises expiry for the lifetime of the retained provider
// actor, independently of the remote transport or its command contexts. The
// caller runs the UID-pinned Unix server with this same actor lifetime and owns
// fail-closed service/cgroup placement. This does not establish that placement.
//
// Sweep and command effects share one mutex. The one-second tick, an in-flight
// command's bounded deadline and the provider's stop grace mean expiry is an
// eventual execution fence; it is not an exact wall-clock TTL guarantee.
func (s *WorkerRPCServer) RunRuntimeActor(ctx context.Context, report func(error)) error {
	if s == nil || !s.Binding.Persistent() || s.Binding.Validate() != nil || s.LeaseStore == nil || s.LeaseStore.Root == nil || s.ControlRoot == nil || s.Provider == nil {
		return ErrInvalid
	}
	sweep := func() {
		workCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		err := s.sweepRuntimeActor(workCtx, time.Now().UTC())
		cancel()
		if err != nil && ctx.Err() == nil && report != nil {
			report(err)
		}
	}
	sweep()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			sweep()
		}
	}
}
