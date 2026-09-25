package ipsec

import (
	"context"
	"reflect"
	"runtime"
	"time"

	"github.com/google/uuid"
)

// selectedRuntimeSlot reports completed route duty, never active authority.
func selectedRuntimeSlot(e RuntimeJournalEntry) uint8 {
	if e.ContractVersion == 0 && e.Recovery == nil {
		return 1
	}
	if e.ContractVersion != 2 || !validJournalRecovery(e) || e.Recovery.Stage != "completed" {
		return 0
	}
	return e.Recovery.SelectedSlot
}

// RecoveryCapability is separate from the fixed-path material capability.
// Current native platform/process qualification remains mandatory on every use.
func (c *RuntimeController) RecoveryCapability() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.capabilityFor(runtime.GOOS, runtime.GOARCH)
}

func (c *RuntimeController) recoveryNow() time.Duration {
	if c.recoveryClock == nil {
		origin := time.Now()
		c.recoveryClock = func() time.Duration { return time.Since(origin) }
	}
	return c.recoveryClock()
}
func (c *RuntimeController) observeRecovery(ctx context.Context, e RuntimeJournalEntry) [2]string {
	if c.recoveryObserve != nil {
		return c.recoveryObserve(ctx, e)
	}
	unknown := [2]string{"unknown", "unknown"}
	kr, err := NewKernelReader(c.config.IPPath)
	if err != nil {
		return unknown
	}
	xr, err := NewXFRMReader(c.config.IPPath)
	if err != nil {
		return unknown
	}
	return runtimeObservedStatuses(ctx, e, runtimeStatusReaders{daemon: c.config.Daemon.Inspect, kernel: kr.Read, xfrm: xr.Read, alive: c.config.DaemonAlive})
}
func (c *RuntimeController) reconcileRecoveryRoutes(ctx context.Context, e RuntimeJournalEntry, target uint8) error {
	if c.recoverySwitch != nil {
		return c.recoverySwitch(ctx, e.Allocation, e.Observed, target)
	}
	return c.kernel.ReconcileSelection(ctx, e.Allocation, e.Observed, target)
}
func (c *RuntimeController) recoveryLease(ctx context.Context, e RuntimeJournalEntry, hash string) (*PermitLeaseAuthority, PermitLeaseIdentity, error) {
	authority := NewPermitLeaseAuthority()
	identity := PermitLeaseIdentity{PolicyHash: hash, Binding: e.Engines[0].Binding, DeliveryID: e.DeliveryID}
	request, err := authority.Begin(identity)
	if err != nil {
		return nil, identity, ErrRuntimeController
	}
	lease, err := c.client.RenewIPsecLease(ctx, e.Allocation.ConnectionID, RuntimeLeaseRequest{DeliveryID: e.DeliveryID, DesiredRevision: e.Engines[0].Binding.DesiredRevision, PolicyHash: hash, Nonce: request.Nonce})
	if err != nil || lease.DeliveryID != e.DeliveryID || lease.DesiredRevision != e.Engines[0].Binding.DesiredRevision || lease.PolicyHash != hash || lease.Nonce != request.Nonce || authority.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: lease.TTLMS}) != nil {
		return nil, identity, ErrRuntimeController
	}
	return authority, identity, nil
}

// applyRecovery executes only authenticated versioned material, serialized by
// Apply. No saved transition, observation or process cache can restore a lease.
func (c *RuntimeController) applyRecovery(ctx context.Context, m RuntimeMaterial, entries []RuntimeJournalEntry, pos int, env RuntimeEnvironment, grants []GuardGrant) (RuntimeAcknowledgement, error) {
	entry := entries[pos]
	metricSequence := uint64(0)
	id := entry.Allocation.ConnectionID
	if c.active == nil {
		c.active = map[uuid.UUID]runtimeActive{}
	}
	if c.recoveryHistory == nil {
		c.recoveryHistory = map[uuid.UUID]*recoveryDecision{}
	}
	if c.recoveryPrepared == nil {
		c.recoveryPrepared = map[uuid.UUID]RuntimeEnvironment{}
	}
	withdraw := func() error { delete(c.active, id); return c.installActive(ctx, entries) }
	fail := func() (RuntimeAcknowledgement, error) {
		c.recoveryMetrics.refuse(entry.DeliveryID, metricSequence)
		_ = withdraw()
		return RuntimeAcknowledgement{}, ErrRuntimeController
	}
	if !validJournalRecovery(entry) || entry.ContractVersion != 2 || entry.AbsenceOnly {
		return fail()
	}
	metricSequence = entry.Recovery.Sequence
	if entry.Recovery.Stage == "pending" {
		c.recoveryMetrics.begin(entry.DeliveryID, metricSequence, time.Now())
	}
	prepared, known := c.recoveryPrepared[entry.DeliveryID]
	if !known || !reflect.DeepEqual(prepared, env) {
		delete(c.recoveryHistory, id)
		if withdraw() != nil {
			return fail()
		}
		if entry.Phase == RuntimeApplied {
			missing, err := c.kernel.RestartNeedsRecreation(ctx, entry.Allocation, entry.Observed)
			if err != nil {
				return fail()
			}
			if missing {
				// Persisted Applied is not evidence that kernel links survived a
				// restart. Recreate only independently proved complete absence,
				// under fresh CP authority and the already installed deny guard.
				authority, identity, err := c.recoveryLease(ctx, entry, m.Policy.Hash)
				if err != nil {
					return fail()
				}
				missing, err = c.kernel.RestartNeedsRecreation(ctx, entry.Allocation, entry.Observed)
				if err != nil || !missing {
					return fail()
				}
				if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
					return fail()
				}
				owned, err := c.kernel.Apply(ctx, entry.Allocation, [2]Ownership{})
				if err != nil {
					return fail()
				}
				entries[pos].Observed = owned
				if c.journal.Save(entries) != nil {
					return fail()
				}
			}
		}
		if entry.Phase == RuntimeReserved || entry.Phase == RuntimeApplying {
			entries[pos].Phase = RuntimeApplying
			if c.journal.Save(entries) != nil {
				return fail()
			}
			owned, err := c.kernel.Apply(ctx, entry.Allocation, entry.Observed)
			if err != nil {
				return fail()
			}
			entries[pos].Observed = owned
			if c.journal.Save(entries) != nil {
				return fail()
			}
		}
		entry = entries[pos]
		for i, t := range entry.Engines {
			if c.config.Daemon.removeTunnel(ctx, t) != nil {
				return fail()
			}
			secret := []byte(m.Secrets[i].PSK)
			err := c.config.Daemon.stageTunnel(ctx, t, secret)
			for j := range secret {
				secret[j] = 0
			}
			if err != nil {
				return fail()
			}
		}
		// Either peer may be unavailable; only independent readback can declare Up.
		for _, t := range entry.Engines {
			_ = c.config.Daemon.initiateTunnel(ctx, t)
		}
		if entry.Phase == RuntimeApplying {
			entries[pos].Phase = RuntimeApplied
			if c.journal.Save(entries) != nil {
				return fail()
			}
		}
		entry = entries[pos]
		c.recoveryPrepared[entry.DeliveryID] = env
	}
	// Revalidate old permits before potentially slow CP or daemon observations.
	if c.installActive(ctx, entries) != nil {
		return fail()
	}
	authority, identity, err := c.recoveryLease(ctx, entry, m.Policy.Hash)
	if err != nil {
		delete(c.recoveryHistory, id)
		return fail()
	}
	started := c.recoveryNow()
	statuses := c.observeRecovery(ctx, entry)
	now := c.recoveryNow()
	if now < started || now-started > 5*time.Second || !c.qualification.current() {
		delete(c.recoveryHistory, id)
		return fail()
	}
	// A corrected peer cannot restart a start_action=none / dpd_action=clear
	// connection itself. Retry only complete, independently verified all-Down
	// evidence, under refusal. A healthy alternate and failover hold are untouched.
	if statuses == ([2]string{"down", "down"}) {
		delete(c.recoveryHistory, id)
		if withdraw() != nil {
			return fail()
		}
		if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
			return fail()
		}
		for _, t := range entry.Engines {
			retryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if c.recoveryInitiate != nil {
				_ = c.recoveryInitiate(retryCtx, t)
			} else {
				_ = c.config.Daemon.initiateTunnel(retryCtx, t)
			}
			cancel()
		}
		// Retry time cannot extend the old lease or authorize reopening. Revalidate
		// current CP policy with a new nonce before considering the fresh result.
		authority, identity, err = c.recoveryLease(ctx, entry, m.Policy.Hash)
		if err != nil {
			return fail()
		}
		started = c.recoveryNow()
		statuses = c.observeRecovery(ctx, entry)
		now = c.recoveryNow()
		if now < started || now-started > 5*time.Second || !c.qualification.current() {
			return fail()
		}
	}
	epoch := recoveryEpoch{Binding: entry.Engines[0].Binding, PolicyHash: m.Policy.Hash, DeliveryID: entry.DeliveryID, Namespace: entry.Allocation.Namespace, Tunnels: [2]uuid.UUID{entry.Engines[0].TunnelID, entry.Engines[1].TunnelID}}
	history := c.recoveryHistory[id]
	if history == nil {
		history = &recoveryDecision{}
		c.recoveryHistory[id] = history
	}
	slot := selectedRuntimeSlot(entry)
	pending := entry.Recovery.Stage == "pending"
	target := slot
	if pending {
		// A crash never discards a durable transition. Complete only its exact
		// target under fresh authority; do not infer a rollback from source health.
		target = entry.Recovery.PendingTo
		if statuses[target-1] != "up" || statuses[1-(target-1)] == "unknown" {
			delete(c.recoveryHistory, id)
			return fail()
		}
	} else {
		advice := history.observe(epoch, now, recoveryObservation{Epoch: epoch, Current: slot, Status: statuses, Authorized: true, At: started})
		if advice.Refuse {
			if withdraw() != nil {
				return fail()
			}
			if advice.Target == 0 {
				return fail()
			}
			target = advice.Target
		}
	}
	if target < 1 || target > 2 {
		return fail()
	}
	_, active := c.active[id]
	if pending || target != slot || !active {
		if withdraw() != nil {
			return fail()
		}
		if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
			return fail()
		}
		if !pending && target != slot {
			if entry.Recovery.Sequence == ^uint64(0) {
				return fail()
			}
			next := *entry.Recovery
			next.Sequence++
			metricSequence = next.Sequence
			c.recoveryMetrics.begin(entry.DeliveryID, metricSequence, time.Now())
			next.Stage = "pending"
			next.PendingFrom = slot
			next.PendingTo = target
			entries[pos].Recovery = &next
			if c.journal.Save(entries) != nil {
				return fail()
			}
			entry = entries[pos]
			pending = true
		}
		// Fresh target readback follows verified refusal and precedes route mutation.
		started = c.recoveryNow()
		statuses = c.observeRecovery(ctx, entry)
		now = c.recoveryNow()
		if now < started || now-started > 5*time.Second || statuses[target-1] != "up" || statuses[1-(target-1)] == "unknown" || !c.qualification.current() {
			return fail()
		}
		if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
			return fail()
		}
		if c.reconcileRecoveryRoutes(ctx, entry, target) != nil {
			return fail()
		}
		candidate := entry
		completed := *entry.Recovery
		completed.Stage = "completed"
		completed.SelectedSlot = target
		completed.PendingFrom = 0
		completed.PendingTo = 0
		candidate.Recovery = &completed
		if c.proveCurrent(ctx, candidate, env) != nil {
			return fail()
		}
		if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil || !c.qualification.current() {
			return fail()
		}
		if pending {
			entries[pos] = candidate
			if c.journal.Save(entries) != nil {
				return fail()
			}
		}
		entry = candidate
	} else if c.proveCurrent(ctx, entry, env) != nil {
		return fail()
	}
	c.active[id] = runtimeActive{Entry: entry, Environment: env, Grants: grants, Identity: identity, Authority: authority}
	if c.installActive(ctx, entries) != nil {
		return fail()
	}
	if _, ok := c.active[id]; !ok {
		return fail()
	}
	// Retry standby establishment only after the selected route and its permits
	// are independently proved. Initiation cannot manufacture health or grants;
	// a later normal reconciliation must observe the resulting SA itself.
	c.retryDownStandby(ctx, entry, authority, identity)
	c.recoveryMetrics.complete(entry.DeliveryID, metricSequence, time.Now())
	return RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}, nil
}

// This process-local attempt history confers no authority and is never journaled.
type runtimeStandbyRetry struct {
	DeliveryID, TunnelID uuid.UUID
	At                   time.Duration
}

func (c *RuntimeController) retryDownStandby(ctx context.Context, entry RuntimeJournalEntry, authority *PermitLeaseAuthority, identity PermitLeaseIdentity) {
	slot := selectedRuntimeSlot(entry)
	if slot < 1 || slot > 2 || !c.qualification.current() || (c.recoveryInitiate == nil && c.config.Daemon == nil) {
		return
	}
	id := entry.Allocation.ConnectionID
	if c.standbyRetries == nil {
		c.standbyRetries = map[uuid.UUID]runtimeStandbyRetry{}
	}
	// Bound history to currently active connections. A new delivery never reuses
	// an old delivery's timing decision.
	for key := range c.standbyRetries {
		if _, ok := c.active[key]; !ok {
			delete(c.standbyRetries, key)
		}
	}
	target := 1 - int(slot-1)
	now := c.recoveryNow()
	old, seen := c.standbyRetries[id]
	if seen && old.DeliveryID == entry.DeliveryID && old.TunnelID == entry.Engines[target].TunnelID {
		if now < old.At || now-old.At < 30*time.Second {
			return
		}
	}
	if _, err := authority.RemainingForApply(identity, 5*time.Second); err != nil {
		return
	}
	started := c.recoveryNow()
	statuses := c.observeRecovery(ctx, entry)
	now = c.recoveryNow()
	if now < started || now-started > 5*time.Second || statuses[slot-1] != "up" || statuses[target] != "down" || !c.qualification.current() {
		return
	}
	if _, err := authority.RemainingForApply(identity, 2*time.Second); err != nil {
		return
	}
	c.standbyRetries[id] = runtimeStandbyRetry{DeliveryID: entry.DeliveryID, TunnelID: entry.Engines[target].TunnelID, At: now}
	retryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if c.recoveryInitiate != nil {
		_ = c.recoveryInitiate(retryCtx, entry.Engines[target])
	} else {
		_ = c.config.Daemon.initiateTunnel(retryCtx, entry.Engines[target])
	}
}
