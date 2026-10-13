package ipsec

import "context"

// Denial is required even when an unchanged session dies after both earlier
// liveness checks. Fresh authority can permit transport only; no stale grant
// survives cleanup or recreation before fresh RIB reconciliation.
func (c *RuntimeController) denyBGPApplySessionCleanup(ctx context.Context, active runtimeActive, identity PermitLeaseIdentity, authority *PermitLeaseAuthority, entries []RuntimeJournalEntry) (runtimeActive, error) {
	active.Grants = nil
	active.Identity = identity
	active.Authority = authority
	c.active[active.Entry.Allocation.ConnectionID] = active
	if c.installActive(ctx, entries) != nil {
		return runtimeActive{}, ErrRuntimeController
	}
	return active, nil
}
