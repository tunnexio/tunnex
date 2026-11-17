package ipsec

import (
	"context"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// A changed policy ends only its own old-epoch deferral. This requirement is
// process-local evidence of the completed guard commit, not a report clock or
// forwarding authority. A real new-epoch report must still precede the ACK.
type maintenanceCommittedRecoveryRequirement struct {
	active      runtimeActive
	before      runtimeRecoveryReportClock
	sequence    uint64
	committedAt time.Duration
}

func (d *maintenancePulseDeferral) transferCommitted(ctx context.Context, c *RuntimeController, prior, candidates, staged map[uuid.UUID]runtimeActive) (resultErr error) {
	if d == nil || !d.used {
		return nil
	}
	stage, owner := "input", uuid.Nil
	started := time.Now()
	defer func() {
		if resultErr != nil {
			c.emitRuntimeDiagnostic(ctx, "maintenance_report_commit", stage, owner, started, true)
		}
	}()
	if c == nil || ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || len(d.committed) != 0 {
		return ErrRuntimeController
	}
	stage = "current_set"
	if !reflect.DeepEqual(c.active, staged) {
		return ErrRuntimeController
	}
	for id, candidate := range candidates {
		owner, stage = id, "candidate"
		actual, ok := c.active[id]
		if !ok || actual.Authority != candidate.Authority || !reflect.DeepEqual(actual, candidate) {
			return ErrRuntimeController
		}
	}
	moved := map[uuid.UUID]maintenanceCommittedRecoveryRequirement{}
	now := c.recoveryNow()
	for id, before := range d.owners {
		owner, stage = id, "before"
		old, oldOK := prior[id]
		next, nextOK := c.active[id]
		expected := before.active
		expected.Authority = old.Authority
		if !oldOK || !nextOK || !reflect.DeepEqual(old, expected) || now < d.started {
			return ErrRuntimeController
		}
		if next.Identity.PolicyHash == old.Identity.PolicyHash {
			continue
		}
		stage = "candidate"
		candidate, ok := candidates[id]
		if !ok || !reflect.DeepEqual(next, candidate) || next.Authority != candidate.Authority {
			return ErrRuntimeController
		}
		stage = "transport"
		if next.Entry.ContractVersion != 2 || !validJournalRecovery(next.Entry) || next.Entry.Recovery.Stage != "completed" || !reflect.DeepEqual(next.Entry, old.Entry) || !reflect.DeepEqual(next.Delivery, old.Delivery) || !reflect.DeepEqual(next.Environment, old.Environment) || next.Identity.Binding != old.Identity.Binding || next.Identity.DeliveryID != old.Identity.DeliveryID {
			return ErrRuntimeController
		}
		stage = "policy"
		if !validDigest(next.Identity.PolicyHash) || !c.fqdnGrantsCurrent(next.Grants) {
			return ErrRuntimeController
		}
		stage = "authority"
		if old.Authority == nil || next.Authority == nil || old.Authority == next.Authority {
			return ErrRuntimeController
		}
		if _, err := old.Authority.RemainingForApply(old.Identity, time.Millisecond); err != nil {
			return ErrRuntimeController
		}
		if _, err := next.Authority.RemainingForApply(next.Identity, 5*time.Second); err != nil {
			return ErrRuntimeController
		}
		stage = "history"
		h := c.recoveryHistory[id]
		if h == nil || !h.seen || h.epoch != recoveryReportEpoch(next) || h.current != selectedRuntimeSlot(next.Entry) || h.consecutive != 0 || h.firstDown != 0 || h.lastAt < before.history.lastAt || h.lastNow < before.history.lastNow || h.lastAt > h.lastNow || now < h.lastNow {
			return ErrRuntimeController
		}
		// Atomic adoption invalidates the old-epoch report. This seam cannot
		// transfer an old returned timestamp into the committed policy.
		if _, known := c.recoveryReportClock(next); known {
			return ErrRuntimeController
		}
		stage = "sequence"
		sequence := c.recoveryStatusSequence[next.Entry.DeliveryID]
		if sequence < before.clock.sequence || sequence == 0 || sequence > 9007199254740991 {
			return ErrRuntimeController
		}
		moved[id] = maintenanceCommittedRecoveryRequirement{active: cloneMaintenanceActive(next), before: before.clock, sequence: sequence, committedAt: now}
	}
	// Validate every owner before altering any tracking. Unchanged owners keep
	// their original snapshot and their unchanged ten-second returned clock.
	d.committed = moved
	for id := range moved {
		delete(d.owners, id)
	}
	return nil
}

func committedRecoveryActiveCurrent(ctx context.Context, c *RuntimeController, id uuid.UUID, requirement maintenanceCommittedRecoveryRequirement) bool {
	if c == nil || ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || c.recoveryNow() < requirement.committedAt {
		return false
	}
	current, ok := c.active[id]
	if !ok || current.Authority == nil || current.Authority != requirement.active.Authority || !reflect.DeepEqual(current, requirement.active) || !c.fqdnGrantsCurrent(current.Grants) {
		return false
	}
	_, err := current.Authority.RemainingForApply(current.Identity, time.Millisecond)
	return err == nil
}

// A removed old-epoch owner is eligible only for its own exact freshly sampled
// committed report. The caller still checks every unchanged tracked owner.
func (d *maintenancePulseDeferral) committedRecoveryPendingCurrent(ctx context.Context, c *RuntimeController, out RuntimeRecoveryHeartbeat) bool {
	if d == nil {
		return false
	}
	requirement, ok := d.committed[out.ConnectionID]
	if !ok || !committedRecoveryActiveCurrent(ctx, c, out.ConnectionID, requirement) || out.Report.SelectionSequence == nil || *out.Report.SelectionSequence <= requirement.sequence {
		return false
	}
	a := c.active[out.ConnectionID]
	h := c.recoveryHistory[out.ConnectionID]
	if h == nil || !h.seen || h.epoch != recoveryReportEpoch(a) || h.current != selectedRuntimeSlot(a.Entry) || h.lastAt < requirement.committedAt {
		return false
	}
	return maintenancePendingRecoveryCurrent(c, a, requirement.before, h, c.recoveryNow(), out)
}

func (d *maintenancePulseDeferral) committedReportsCurrent(ctx context.Context, c *RuntimeController) bool {
	if d == nil {
		return true
	}
	for id, requirement := range d.committed {
		if !committedRecoveryActiveCurrent(ctx, c, id, requirement) {
			return false
		}
		clock, known := c.recoveryReportClock(c.active[id])
		now := c.recoveryNow()
		if !known || clock.sequence <= requirement.sequence || clock.returned < requirement.committedAt || now < clock.returned || now-clock.returned > 10*time.Second {
			return false
		}
	}
	return true
}
