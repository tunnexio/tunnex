package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"time"
)

// Process-local attempt pacing is not health, a grant or a durable cleanup duty.
// Save BEFORE VICI initiation: a timeout can leave negotiation running. Only a
// later independent observation can report success or authorize another attempt.
type runtimeBGPRetry struct {
	TunnelID uuid.UUID
	At       time.Duration
}

// Initial negotiation is separate from staging and from observed health.
// Keep Applying until independent ownership/CHILD proof succeeds; retry known
// Down peers without reloading either configuration or touching an Up peer.
func (c *RuntimeController) initiateStagedBGPChildren(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, authority *PermitLeaseAuthority, identity PermitLeaseIdentity) error {
	if c.closed || !c.started || !c.bgpStaged[e.DeliveryID] || e.ContractVersion != 3 || e.AbsenceOnly || (e.Phase != RuntimeApplying && e.Phase != RuntimeApplied) || !validJournalBGP(e) || !validBGPRoutes(e) || (e.BGPRoutes != nil && e.BGPRoutes.Stage != "completed") || c.config.Environment == nil || c.config.DaemonAlive == nil || (c.recoveryInitiate == nil && c.config.Daemon == nil) {
		return ErrRuntimeController
	}
	if _, active := c.active[e.Allocation.ConnectionID]; active {
		return ErrRuntimeController
	}
	if c.bgpRetries == nil {
		c.bgpRetries = map[uuid.UUID][2]runtimeBGPRetry{}
	}
	for slot, tunnel := range e.Engines[:e.Allocation.activeTunnelCount()] {
		ns, err := c.namespace()
		current, observeErr := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
		if err != nil || ns != e.Allocation.Namespace || observeErr != nil || !reflect.DeepEqual(current, env) || !c.qualification.current() || !c.config.DaemonAlive() || c.kernel.verifyBGPRoutes(ctx, e.Allocation, e.Observed, bgpRouteUnion(e.BGPRoutes), true) != nil {
			return ErrRuntimeController
		}
		started := c.recoveryNow()
		statuses := c.observeRecovery(ctx, e)
		now := c.recoveryNow()
		if now < started || now-started > 5*time.Second || (statuses[0] != "up" && statuses[0] != "down") || (statuses[1] != "up" && statuses[1] != "down") {
			return ErrRuntimeController
		}
		if _, err := authority.RemainingForApply(identity, 5*time.Second); err != nil || ctx.Err() != nil {
			return ErrRuntimeController
		}
		currentNS, nsErr := c.namespace()
		if nsErr != nil || currentNS != e.Allocation.Namespace || !c.qualification.current() || !c.config.DaemonAlive() {
			return ErrRuntimeController
		}
		if statuses[slot] != "down" {
			continue
		}
		history := c.bgpRetries[e.DeliveryID]
		previous := history[slot]
		if previous.TunnelID == tunnel.TunnelID && (now < previous.At || now-previous.At < 30*time.Second) {
			continue
		}
		// Record before the request: a timeout can leave negotiation running.
		history[slot] = runtimeBGPRetry{TunnelID: tunnel.TunnelID, At: now}
		c.bgpRetries[e.DeliveryID] = history
		attemptCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if c.recoveryInitiate != nil {
			_ = c.recoveryInitiate(attemptCtx, tunnel)
		} else {
			_ = c.config.Daemon.initiateTunnel(attemptCtx, tunnel)
		}
		cancel()
	}
	return nil
}

// Called under the controller lock only after normal BGP route/guard proof and
// fresh lease publication. Never selects a global slot or replaces healthy
// grants. Unknown/partial transport evidence causes no initiation.
func (c *RuntimeController) retryMissingBGPChild(ctx context.Context, e RuntimeJournalEntry) {
	active, ok := c.active[e.Allocation.ConnectionID]
	p := c.bgpProcesses[e.DeliveryID]
	if !ok || c.closed || !c.started || e.ContractVersion != 3 || e.Phase != RuntimeApplied || !validJournalBGP(e) || e.BGPRoutes == nil || e.BGPRoutes.Stage != "completed" || !reflect.DeepEqual(active.Entry, e) || c.qualification == nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || p == nil || !p.Alive() || c.config.Environment == nil || (c.recoveryInitiate == nil && c.config.Daemon == nil) {
		return
	}
	if _, err := active.Authority.RemainingForApply(active.Identity, 5*time.Second); err != nil {
		return
	}
	ns, err := c.namespace()
	if err != nil || ns != e.Allocation.Namespace {
		return
	}
	env, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
	if err != nil || !reflect.DeepEqual(env, active.Environment) || c.kernel.verifyBGPRoutes(ctx, e.Allocation, e.Observed, e.BGPRoutes.Owned, true) != nil {
		return
	}
	started := c.recoveryNow()
	statuses := c.observeRecovery(ctx, e)
	now := c.recoveryNow()
	if now < started || now-started > 5*time.Second {
		return
	}
	if statuses != ([2]string{"up", "down"}) && statuses != ([2]string{"down", "up"}) {
		return
	}
	for _, route := range e.BGPRoutes.Owned {
		if route.Slot < 1 || route.Slot > 2 || statuses[route.Slot-1] != "up" {
			return
		}
	}
	c.attemptBGPChildRetry(ctx, e, active.Environment, active.Authority, active.Identity, statuses, true)
}

func (c *RuntimeController) attemptBGPChildRetry(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, authority *PermitLeaseAuthority, identity PermitLeaseIdentity, statuses [2]string, requireSession bool) {
	now := c.recoveryNow()
	if c.bgpRetries == nil {
		c.bgpRetries = map[uuid.UUID][2]runtimeBGPRetry{}
	}
	for id := range c.bgpRetries {
		found := false
		entries, err := c.journal.Entries()
		if err != nil {
			return
		}
		for _, entry := range entries {
			found = found || (entry.DeliveryID == id && entry.Phase == RuntimeApplied)
		}
		if !found {
			delete(c.bgpRetries, id)
		}
	}
	history := c.bgpRetries[e.DeliveryID]
	target := -1
	for slot, state := range statuses {
		if state != "down" {
			continue
		}
		old := history[slot]
		if old.TunnelID == e.Engines[slot].TunnelID && (now < old.At || now-old.At < 30*time.Second) {
			continue
		}
		target = slot
		break
	}
	if target < 0 {
		return
	}
	p := c.bgpProcesses[e.DeliveryID]
	// Re-prove ownership/environment and health immediately before the request;
	// the sample that paced the attempt cannot become authority by itself.
	current, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
	if err != nil || !reflect.DeepEqual(current, env) || c.kernel.verifyBGPRoutes(ctx, e.Allocation, e.Observed, e.BGPRoutes.Owned, true) != nil || (requireSession && (p == nil || !p.Alive())) || !c.qualification.current() || !c.config.DaemonAlive() {
		return
	}
	secondStarted := c.recoveryNow()
	again := c.observeRecovery(ctx, e)
	secondNow := c.recoveryNow()
	if secondNow < secondStarted || secondNow-secondStarted > 5*time.Second || again != statuses {
		return
	}
	currentNS, nsErr := c.namespace()
	if nsErr != nil || currentNS != e.Allocation.Namespace || !c.qualification.current() || !c.config.DaemonAlive() || (requireSession && (p == nil || !p.Alive())) {
		return
	}
	if _, err := authority.RemainingForApply(identity, 2*time.Second); err != nil {
		return
	}
	history[target] = runtimeBGPRetry{TunnelID: e.Engines[target].TunnelID, At: secondNow}
	c.bgpRetries[e.DeliveryID] = history
	retryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if c.recoveryInitiate != nil {
		_ = c.recoveryInitiate(retryCtx, e.Engines[target])
	} else {
		_ = c.config.Daemon.initiateTunnel(retryCtx, e.Engines[target])
	}
}

// All-Down restoration withdraws application and route authority before any
// negotiation. It never adopts health, clears process duties or restages PSKs.
func (c *RuntimeController) retryAllDownBGPChildren(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, authority *PermitLeaseAuthority, identity PermitLeaseIdentity, entries []RuntimeJournalEntry) (bool, error) {
	if e.Phase != RuntimeApplied || c.observeRecovery(ctx, e) != ([2]string{"down", "down"}) {
		return false, nil
	}
	delete(c.active, e.Allocation.ConnectionID)
	if c.installActive(ctx, entries) != nil {
		return true, ErrRuntimeController
	}
	if WithdrawBGPRoutes(ctx, c.journal, c.kernel, e.DeliveryID.String()) != nil {
		return true, ErrRuntimeController
	}
	latest, err := c.journal.Entries()
	if err != nil {
		return true, err
	}
	found := false
	for _, entry := range latest {
		if entry.DeliveryID == e.DeliveryID {
			e = entry
			found = true
		}
	}
	if !found || e.BGPRoutes == nil || e.BGPRoutes.Stage != "completed" || len(e.BGPRoutes.Owned) != 0 || len(e.BGPRoutes.Target) != 0 || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return true, ErrRuntimeController
	}
	if _, err := authority.RemainingForApply(identity, 5*time.Second); err != nil {
		return true, err
	}
	current, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
	if err != nil || !reflect.DeepEqual(current, env) || c.kernel.verifyBGPRoutes(ctx, e.Allocation, e.Observed, nil, true) != nil {
		return true, ErrRuntimeController
	}
	c.attemptBGPChildRetry(ctx, e, env, authority, identity, [2]string{"down", "down"}, false)
	return true, nil
}
