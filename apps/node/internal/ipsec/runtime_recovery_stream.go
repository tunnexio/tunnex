package ipsec

import (
	"context"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// RefreshIPsecActiveRecoveryObserved publishes each real observation before
// another owner can consume its budget. The ten-second round ceiling is the
// existing report-freshness bound, not additional authority or native-read time.
// A not-yet-started owner is deferred unless its full five-second turn fits.
func (c *RuntimeController) RefreshIPsecActiveRecoveryObserved(ctx context.Context, publish func(context.Context, RuntimeRecoveryHeartbeat) error) error {
	if c == nil {
		return ErrRuntimeController
	}
	return c.refreshIPsecActiveRecoveryObserved(ctx, publish, c.bgpQualificationCurrent)
}

func (c *RuntimeController) refreshIPsecActiveRecoveryObserved(parent context.Context, publish func(context.Context, RuntimeRecoveryHeartbeat) error, bgpCurrent func() bool) error {
	if c == nil || publish == nil || parent.Err() != nil {
		return ErrRuntimeController
	}
	round, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	deadline, _ := round.Deadline()
	seen := map[uuid.UUID]bool{}
	for i := 0; i < 256; i++ {
		if parent.Err() != nil {
			return ErrRuntimeController
		}
		// Defer before starting any native work. The next serial call again chooses
		// the oldest actual sample; no invented report clock makes it appear fresh.
		if time.Until(deadline) < 5*time.Second {
			return nil
		}
		owner, stop := context.WithTimeout(round, 5*time.Second)
		sampled, err := c.refreshIPsecRecoveryOwnerObserved(owner, seen, publish, bgpCurrent)
		stop()
		if err != nil {
			return err
		}
		if sampled == uuid.Nil {
			return nil
		}
		if seen[sampled] {
			return ErrRuntimeController
		}
		seen[sampled] = true
	}
	return nil
}

// The caller serializes owners. Holding c.mu across this synchronous callback
// matches the maintenance publication path and prevents a later native owner
// from changing the report's context before publication completes.
func (c *RuntimeController) refreshIPsecRecoveryOwnerObserved(ctx context.Context, seen map[uuid.UUID]bool, publish func(context.Context, RuntimeRecoveryHeartbeat) error, bgpCurrent func() bool) (uuid.UUID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	reports, err := c.refreshIPsecActiveRecoveryLockedQualified(ctx, seen, false, time.Now(), bgpCurrent)
	if err != nil {
		return uuid.Nil, err
	}
	if len(reports) == 0 {
		return uuid.Nil, nil
	}
	if len(reports) != 1 {
		return uuid.Nil, ErrRuntimeController
	}
	out := reports[0]
	if out.ConnectionID == uuid.Nil || seen[out.ConnectionID] {
		return uuid.Nil, ErrRuntimeController
	}
	// Equal durable sequence consumed this turn but provides no new publication.
	if out.Report.SelectionSequence == nil {
		return out.ConnectionID, nil
	}
	before, ok := c.active[out.ConnectionID]
	if !ok || before.Authority == nil {
		return uuid.Nil, ErrRuntimeController
	}
	before = cloneMaintenanceActive(before)
	deadline := before.Authority.deadline
	if !c.rememberRecoveryReport(ctx, out.ConnectionID, out.Delivery, out.Report) {
		return uuid.Nil, ErrRuntimeController
	}
	clock, known := c.recoveryReportClock(before)
	if !known {
		return uuid.Nil, ErrRuntimeController
	}
	// Capture the actual post-native clock now. HTTP duration and later owners
	// must not move it forward or renew any installed authority.
	publicationErr := publish(ctx, out)
	after, current := c.active[out.ConnectionID]
	// Check existence, exact authority pointer and immutable shape before reading
	// any epoch fields. A disappeared owner has no valid report-clock entry.
	if !current || after.Authority != before.Authority || !reflect.DeepEqual(after, before) || before.Authority.deadline != deadline {
		entries, e := c.journal.Entries()
		if e == nil {
			_, _ = c.refuse(ctx, entries)
		}
		return uuid.Nil, ErrRuntimeController
	}
	now := c.recoveryNow()
	afterClock, clockCurrent := c.recoveryReportClock(after)
	if ctx.Err() != nil || !clockCurrent || afterClock != clock || now < clock.returned || now-clock.returned > 5*time.Second || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		entries, e := c.journal.Entries()
		if e == nil {
			_, _ = c.refuse(ctx, entries)
		}
		return uuid.Nil, ErrRuntimeController
	}
	if _, e := before.Authority.RemainingForApply(before.Identity, 5*time.Second); e != nil {
		entries, journalErr := c.journal.Entries()
		if journalErr == nil {
			_, _ = c.refuse(ctx, entries)
		}
		return uuid.Nil, ErrRuntimeController
	}
	// A failed advisory HTTP delivery stops this round. It cannot renew or revoke
	// otherwise current native authority, just as the legacy control path cannot.
	if publicationErr != nil {
		return uuid.Nil, publicationErr
	}
	return out.ConnectionID, nil
}
