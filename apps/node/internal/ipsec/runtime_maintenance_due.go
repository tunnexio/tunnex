package ipsec

import (
	"reflect"
	"time"
)

// This is scheduling advice from a successful native commit. It is neither
// authority nor a cached proof, and never changes an emitted timeout.
type runtimeOrdinaryNativeWindow struct {
	owner      runtimeActive
	observedAt time.Duration
	deadline   time.Duration
}

// maintenanceRenewalDue is called only after ordinary eligibility and fresh
// native proof. Missing or mismatched advice always requests normal renewal.
// A deferral preserves the original authority and must not acknowledge a new
// delivery or skip discovery, revocation, or status observation.
func (c *RuntimeController) maintenanceRenewalDue(old runtimeActive) bool {
	if c == nil || !c.started || c.closed || old.Authority == nil || len(c.active) == 0 || len(c.active) > 256 {
		return true
	}
	id := old.Entry.Allocation.ConnectionID
	current, active := c.active[id]
	window, known := c.ordinaryNativeWindows[id]
	if !active || !known || !reflect.DeepEqual(current, old) || window.owner.Authority != old.Authority || !reflect.DeepEqual(window.owner, old) {
		return true
	}
	now := c.recoveryNow()
	if window.observedAt < 0 || now < window.observedAt || window.deadline <= window.observedAt || window.deadline <= now {
		return true
	}
	// Keep each owner's existing five-second preproof and assembly allowance,
	// plus the shared five-second commit reserve, ahead of actual native expiry.
	runway := time.Duration(2*len(c.active)+1) * 5 * time.Second
	if window.deadline-now <= runway {
		return true
	}
	_, err := old.Authority.RemainingForApply(old.Identity, runway)
	return err != nil
}
