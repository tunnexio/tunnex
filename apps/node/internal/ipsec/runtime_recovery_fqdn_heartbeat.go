package ipsec

import (
	"context"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// Only an exact expiry-only change can bridge a telemetry conflict. The new
// lease is discarded by heartbeat; old installed authority, grants and native
// timeouts remain unchanged until normal maintenance obtains its own new nonce.
func (c *RuntimeController) recoveryHeartbeatExpiryLease(ctx context.Context, old runtimeActive) (*PermitLeaseAuthority, PermitLeaseIdentity, func() bool, error) {
	fail := func(err error) (*PermitLeaseAuthority, PermitLeaseIdentity, func() bool, error) {
		return nil, PermitLeaseIdentity{}, nil, err
	}
	id := old.Entry.Allocation.ConnectionID
	current := func() bool {
		if ctx.Err() != nil || old.Authority == nil || c.active[id].Authority != old.Authority || !reflect.DeepEqual(c.active[id], old) || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !c.fqdnGrantsCurrent(old.Grants) {
			return false
		}
		_, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second)
		return err == nil
	}
	if !runtimeDesktopEntrySupported(old.Entry) || old.Entry.ContractVersion != 2 || len(old.FQDNLeaseDescriptors) == 0 || !current() {
		return fail(&runtimeRecoveryLeaseConflict{})
	}
	fresh, err := c.refreshFQDNExpiryMaterial(ctx, old)
	if err != nil || !current() {
		// The original authenticated conflict still permits the existing exact
		// target-only withdrawal proof. It cannot authorize a policy retry.
		return fail(&runtimeRecoveryLeaseConflict{})
	}
	policy := retainedFQDNLeasePolicy(fresh.FQDNLeaseDescriptors)
	policy.Hash = fresh.PolicyHash
	authority, identity, err := c.recoveryLeaseClassified(ctx, old.Entry, fresh.PolicyHash, policy)
	if err != nil {
		return fail(err)
	}
	if !current() {
		return fail(ErrRuntimeController)
	}
	return authority, identity, current, nil
}

// Invoke only after the atomic guard commit and all candidate/old-owner fences.
// A new policy nonce supersedes the advisory epoch, not the durable selected
// transport. Keep the original sample time and discard accumulated failover
// evidence; only the next real heartbeat may publish a new recovery report.
func (c *RuntimeController) resetCommittedRecoveryPolicyAdvice(active, prior map[uuid.UUID]runtimeActive) error {
	reset := map[uuid.UUID]recoveryDecision{}
	for id, next := range active {
		old, retained := prior[id]
		if !retained || next.Entry.ContractVersion != 2 || !runtimeDesktopEntrySupported(next.Entry) || next.Identity.PolicyHash == old.Identity.PolicyHash {
			continue
		}
		if old.Authority == nil || next.Authority == nil || old.Authority == next.Authority || next.Identity.Binding != old.Identity.Binding || next.Identity.DeliveryID != old.Identity.DeliveryID || !validDigest(next.Identity.PolicyHash) || !reflect.DeepEqual(next.Entry, old.Entry) || !reflect.DeepEqual(next.Delivery, old.Delivery) || !reflect.DeepEqual(next.Environment, old.Environment) {
			return ErrRuntimeController
		}
		h := c.recoveryHistory[id]
		if h == nil || !h.seen {
			// Missing advice remains missing. This is never a recovery shortcut.
			continue
		}
		if h.epoch != recoveryReportEpoch(old) || h.current != selectedRuntimeSlot(old.Entry) || c.recoveryNow() < h.lastNow {
			return ErrRuntimeController
		}
		nextHistory := *h
		nextHistory.epoch = recoveryReportEpoch(next)
		nextHistory.consecutive, nextHistory.firstDown = 0, 0
		reset[id] = nextHistory
	}
	for id, history := range reset {
		value := history
		c.recoveryHistory[id] = &value
		delete(c.recoveryReportClocks, id)
	}
	return nil
}
