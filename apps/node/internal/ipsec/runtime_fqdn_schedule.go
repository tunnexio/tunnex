package ipsec

import (
	"context"
	"runtime"
	"sort"
	"time"

	"github.com/google/uuid"
)

// This process-local record is scheduling advice, never a permit. Its owner is
// the exact successfully committed authority. An emitted deadline uses the
// native timeout, conservatively anchored before replacement starts. Omitted
// advice has no native deadline and can only schedule a fresh authorization.
type runtimeFQDNNativeWindow struct {
	owner    runtimeActive
	deadline time.Duration
	omitted  bool
}

func (c *RuntimeController) rememberFQDNNativeWindows(in GuardIntent, active map[uuid.UUID]runtimeActive, started time.Duration) {
	windows := map[uuid.UUID]runtimeFQDNNativeWindow{}
	for _, connection := range in.Connections {
		owner, ok := active[connection.ID]
		if !ok || connection.PrefixOnly || (owner.Entry.ContractVersion != 3 && !runtimeDesktopEntrySupported(owner.Entry)) {
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
		if _, emitted := windows[connection.ID]; !emitted && c.fqdnOmittedWindowEligible(connection, owner) {
			windows[connection.ID] = runtimeFQDNNativeWindow{owner: owner, omitted: true}
		}
	}
	c.fqdnNativeWindows = windows
}

func (c *RuntimeController) shortFQDNNativeOwners() []uuid.UUID {
	now := c.recoveryNow()
	// A follow-up runs before the next complete shared-owner renewal. Each
	// owner may consume its existing five-second preproof and five-second
	// assembly bounds, followed by the five-second atomic commit. Start the
	// existing fresh-material path while the emitted window can still fund
	// that work, rather than waiting for a fixed ten-second window regardless
	// of owner count. This is scheduling advice, never a longer permit.
	runway := c.fqdnRenewalRunway()
	var ids []uuid.UUID
	for id, window := range c.fqdnNativeWindows {
		owner, ok := c.active[id]
		if !ok || !c.fqdnRefreshWindowCurrent(window, owner, now) || !c.fqdnGrantsCurrent(owner.Grants) {
			delete(c.fqdnNativeWindows, id)
			continue
		}
		if window.omitted || window.deadline-now <= runway {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	return ids
}

func (c *RuntimeController) fqdnRenewalRunway() time.Duration {
	return time.Duration(2*len(c.active)+1) * 5 * time.Second
}

func (c *RuntimeController) fqdnNativeWindowNeedsRefresh(id uuid.UUID, old runtimeActive) bool {
	window, ok := c.fqdnNativeWindows[id]
	now := c.recoveryNow()
	return ok && c.fqdnRefreshWindowCurrent(window, old, now) && (window.omitted || window.deadline-now <= c.fqdnRenewalRunway())
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
			if !exists || !active || !c.fqdnRefreshWindowCurrent(window, old, c.recoveryNow()) {
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
		if len(refreshed) > 0 {
			// Fresh metadata is not authority. All ordinary proofs and a new CP nonce
			// are still required by the original atomic maintenance path. Every
			// selected owner was validated above; an unchanged sibling must not
			// hold back a ready earlier deadline. Its original finite authority
			// and the complete all-owner native proof remain mandatory.
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
