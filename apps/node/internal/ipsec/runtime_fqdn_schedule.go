package ipsec

import (
	"context"
	"reflect"
	"runtime"
	"sort"
	"time"

	"github.com/google/uuid"
)

// This process-local record is scheduling advice, never a permit. Its owner is
// the exact successfully committed authority and its deadline uses the emitted
// native timeout, conservatively anchored before replacement starts.
type runtimeFQDNNativeWindow struct {
	owner    runtimeActive
	deadline time.Duration
}

func (c *RuntimeController) rememberFQDNNativeWindows(in GuardIntent, active map[uuid.UUID]runtimeActive, started time.Duration) {
	windows := map[uuid.UUID]runtimeFQDNNativeWindow{}
	for _, connection := range in.Connections {
		owner, ok := active[connection.ID]
		if !ok || connection.PrefixOnly || owner.Entry.ContractVersion != 3 {
			continue
		}
		for _, grant := range connection.Grants {
			if grant.FQDN.Version != 2 || grant.FQDNPermitFor <= 0 {
				continue
			}
			end := started + grant.FQDNPermitFor/time.Second*time.Second
			prior, exists := windows[connection.ID]
			if !exists || end < prior.deadline {
				windows[connection.ID] = runtimeFQDNNativeWindow{owner: owner, deadline: end}
			}
		}
	}
	c.fqdnNativeWindows = windows
}

func (c *RuntimeController) shortFQDNNativeOwners() []uuid.UUID {
	now := c.recoveryNow()
	var ids []uuid.UUID
	for id, window := range c.fqdnNativeWindows {
		owner, ok := c.active[id]
		if !ok || owner.Authority == nil || owner.Authority != window.owner.Authority || !reflect.DeepEqual(owner, window.owner) || window.deadline <= now || !c.fqdnGrantsCurrent(owner.Grants) {
			delete(c.fqdnNativeWindows, id)
			continue
		}
		if window.deadline-now <= 10*time.Second {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	return ids
}

func runtimeFQDNWait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// FollowupFQDNMaintenanceObserved runs before optional caller work. At most one
// extra normal renewal is performed. A bounded material-only wait can see a DNS
// generation published just after a short native commit without prematurely
// replacing an unchanged, still finite member with the normal early cutoff.
// Authoritative discovery and cleanup must still run after this method returns.
func (c *RuntimeController) FollowupFQDNMaintenanceObserved(ctx context.Context, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error) error {
	if c == nil {
		return ErrRuntimeController
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !supportedRuntimePlatform(runtime.GOOS, runtime.GOARCH) {
		return ErrRuntimeController
	}
	for _, owner := range c.active {
		if owner.Entry.ContractVersion == 3 && !c.bgpQualificationCurrent() {
			return ErrRuntimeController
		}
	}
	return c.followupFQDNMaintenance(ctx, NewPermitLeaseAuthority, c.bgpQualificationCurrent, publish, publishRecovery, runtimeFQDNWait)
}

func (c *RuntimeController) followupFQDNMaintenance(ctx context.Context, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error, wait func(context.Context, time.Duration) error) error {
	if ctx.Err() != nil || c.closed || !c.started || wait == nil {
		return ErrRuntimeController
	}
	ids := c.shortFQDNNativeOwners()
	if len(ids) == 0 {
		return nil
	}
	client, ok := c.client.(runtimeCurrentMaterialClient)
	if !ok {
		return nil
	}
	// The total material polling budget includes HTTP and validation. There is no
	// native mutation while waiting; existing members retain their original expiry.
	fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	until := c.recoveryNow() + 2*time.Second
	refreshed := map[uuid.UUID]maintenanceItem{}
	for attempt := 0; attempt < 9; attempt++ {
		if fetchCtx.Err() != nil || c.recoveryNow() >= until {
			return nil
		}
		for _, id := range ids {
			if _, ready := refreshed[id]; ready {
				continue
			}
			window, exists := c.fqdnNativeWindows[id]
			old, active := c.active[id]
			if !exists || !active || window.deadline <= c.recoveryNow() || !reflect.DeepEqual(old, window.owner) {
				return nil
			}
			if !c.fqdnGrantsCurrent(old.Grants) || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
				return ErrRuntimeController
			}
			m, err := client.IPsecMaterial(fetchCtx, id, old.Delivery.DesiredRevision)
			if err != nil {
				return nil
			}
			fresh, validateErr := c.prepareFQDNFollowupMaterial(fetchCtx, old, m, true)
			// Discard sensitive material before any wait or renewal.
			for i := range m.Secrets {
				m.Secrets[i] = RuntimeSecret{}
			}
			if fetchCtx.Err() != nil || c.recoveryNow() >= until {
				return nil
			}
			if validateErr != nil {
				// An authenticated changed/invalid intent may not preserve the old marked
				// authority while waiting. Reuse the existing conservative withdrawal.
				kept := make([]GuardGrant, 0, len(old.Grants))
				for _, grant := range old.Grants {
					if !grant.FQDNManaged {
						kept = append(kept, grant)
					}
				}
				old.Grants = kept
				c.active[id] = old
				return c.withdrawFQDNActiveLocked(ctx, []uuid.UUID{id})
			}
			if fresh.PolicyHash != old.Identity.PolicyHash {
				refreshed[id] = fresh
			}
		}
		if len(refreshed) == len(ids) {
			// Fresh metadata is not authority. All ordinary proofs and a new CP nonce
			// are still required by the original atomic maintenance path.
			return c.commitFQDNFollowup(ctx, authority, bgpCurrent, refreshed, publish)
		}
		remaining := until - c.recoveryNow()
		if remaining <= 0 {
			return nil
		}
		delay := 250 * time.Millisecond
		if remaining < delay {
			delay = remaining
		}
		if wait(fetchCtx, delay) != nil {
			return nil
		}
	}
	return nil
}
