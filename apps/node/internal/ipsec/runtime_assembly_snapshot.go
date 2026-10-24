package ipsec

import (
	"context"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// runtimeAssemblySnapshot belongs to one post-nonce guard transaction. The
// full host inventories are read before and after all owner-specific FRR/MTU
// work. Nothing is stored on the controller or reused by returned telemetry.
type runtimeAssemblySnapshot struct {
	owners   map[uuid.UUID]runtimeActive
	prior    map[uuid.UUID]runtimeActive
	sequence uint64
	consumed bool
	readers  runtimeStatusReaders
	kernel   KernelInventory
	xfrm     XFRMInventory
	states   map[uuid.UUID][2]string
	started  time.Duration
	wall     time.Time
	c        *RuntimeController
}

func (c *RuntimeController) beginAssemblySnapshot(ctx context.Context, active map[uuid.UUID]runtimeActive) (*runtimeAssemblySnapshot, error) {
	// Retain independent hook semantics outside the real typed-inventory
	// fixture. The production path has no recoveryObserve override.
	if !c.exactPageRefreshScope() || len(active) != len(c.active) || ((c.recoveryObserve != nil || c.prove != nil) && c.statusReaders == nil) {
		return nil, nil
	}
	fresh := false
	for id, a := range active {
		if old, ok := c.active[id]; ok && a.Authority != nil && a.Authority != old.Authority {
			fresh = true
		}
	}
	if !fresh {
		return nil, nil
	}
	if ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return nil, ErrRuntimeController
	}
	ns, err := c.namespace()
	if err != nil {
		return nil, ErrRuntimeController
	}
	r := runtimeStatusReaders{}
	if c.statusReaders != nil {
		r = *c.statusReaders
	} else {
		kr, e := NewKernelReader(c.config.IPPath)
		if e != nil {
			return nil, ErrRuntimeController
		}
		xr, e := NewXFRMReader(c.config.IPPath)
		if e != nil || c.config.Daemon == nil {
			return nil, ErrRuntimeController
		}
		r = runtimeStatusReaders{daemon: c.config.Daemon.Inspect, kernel: kr.Read, xfrm: xr.Read, alive: c.config.DaemonAlive}
	}
	if r.daemon == nil || r.kernel == nil || r.xfrm == nil || r.alive == nil || !r.alive() {
		return nil, ErrRuntimeController
	}
	_, sequence, err := c.journal.guardTemplates()
	if err != nil {
		return nil, ErrRuntimeController
	}
	s := &runtimeAssemblySnapshot{owners: map[uuid.UUID]runtimeActive{}, prior: map[uuid.UUID]runtimeActive{}, sequence: sequence, readers: r, states: map[uuid.UUID][2]string{}, started: c.recoveryNow(), wall: time.Now(), c: c}
	for id, a := range active {
		old, ok := c.active[id]
		if !ok || a.Entry.Allocation.ConnectionID != id || a.Entry.Allocation.Namespace != ns || !reflect.DeepEqual(a.Entry, old.Entry) || !reflect.DeepEqual(a.Environment, old.Environment) || !reflect.DeepEqual(a.Delivery, old.Delivery) {
			return nil, ErrRuntimeController
		}
		s.owners[id] = cloneMaintenanceActive(a)
		s.prior[id] = cloneMaintenanceActive(old)
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d, k, x, de, ke, xe := runtimeReadStatusSnapshot(readCtx, r)
	if de != nil || ke != nil || xe != nil || readCtx.Err() != nil || !s.current(ctx, active) {
		return nil, ErrRuntimeController
	}
	s.kernel, s.xfrm = k, x
	for id, a := range s.owners {
		state := runtimeTunnelStatuses(a.Entry, d, k, x)
		for _, v := range state[:a.Entry.Allocation.activeTunnelCount()] {
			if v != "up" && v != "down" {
				return nil, ErrRuntimeController
			}
		}
		s.states[id] = state
	}
	return s, nil
}

func (s *runtimeAssemblySnapshot) current(ctx context.Context, active map[uuid.UUID]runtimeActive) bool {
	if s == nil || s.c == nil || ctx.Err() != nil || len(active) != len(s.owners) || len(s.c.active) != len(s.prior) || !s.readers.alive() || !s.c.qualification.current() || s.c.config.DaemonAlive == nil || !s.c.config.DaemonAlive() {
		return false
	}
	now := s.c.recoveryNow()
	if now < s.started || now-s.started > 5*time.Second || time.Since(s.wall) > 5*time.Second {
		return false
	}
	ns, err := s.c.namespace()
	if err != nil {
		return false
	}
	_, sequence, err := s.c.journal.guardTemplates()
	if err != nil || sequence != s.sequence {
		return false
	}
	for id, owner := range s.owners {
		a, ok := active[id]
		if !ok || !reflect.DeepEqual(a, owner) || a.Authority != owner.Authority || a.Entry.Allocation.Namespace != ns {
			return false
		}
		prior, ok := s.c.active[id]
		if !ok || !reflect.DeepEqual(prior, s.prior[id]) || prior.Authority != s.prior[id].Authority {
			return false
		}
		if a.Authority == nil {
			return false
		}
		if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
			return false
		}
	}
	return true
}

func (s *runtimeAssemblySnapshot) statuses(e RuntimeJournalEntry) ([2]string, error) {
	if s == nil || s.consumed {
		return [2]string{}, ErrRuntimeController
	}
	a, ok := s.owners[e.Allocation.ConnectionID]
	if !ok || !reflect.DeepEqual(a.Entry, e) {
		return [2]string{}, ErrRuntimeController
	}
	v, ok := s.states[e.Allocation.ConnectionID]
	if !ok {
		return [2]string{}, ErrRuntimeController
	}
	return v, nil
}

func (s *runtimeAssemblySnapshot) finish(ctx context.Context, active map[uuid.UUID]runtimeActive) error {
	if s == nil || s.consumed {
		return ErrRuntimeController
	}
	s.consumed = true
	if !s.current(ctx, active) {
		return ErrRuntimeController
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second-time.Since(s.wall))
	defer cancel()
	d, k, x, de, ke, xe := runtimeReadStatusSnapshot(readCtx, s.readers)
	if de != nil || ke != nil || xe != nil || readCtx.Err() != nil || !s.current(ctx, active) {
		return ErrRuntimeController
	}
	for id, a := range s.owners {
		if runtimeTunnelStatuses(a.Entry, d, k, x) != s.states[id] || !reflect.DeepEqual(connectionXFRMSnapshot(a.Entry, s.xfrm), connectionXFRMSnapshot(a.Entry, x)) || !reflect.DeepEqual(connectionKernelSnapshot(a.Entry, s.kernel), connectionKernelSnapshot(a.Entry, k)) {
			return ErrRuntimeController
		}
	}
	return nil
}
