package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"time"
)

// One oldest due static owner per existing boundary keeps each pulse bounded;
// the existing oldest-sample selection supplies fairness without a new goroutine.
// The runtime owner already holds c.mu, outside any guard transaction.
func (c *RuntimeController) refreshMaintenanceActiveRecovery(ctx context.Context, allowed map[uuid.UUID]bool, publish func(context.Context, RuntimeRecoveryHeartbeat) error) (resultErr error) {
	stage, connection := "input", uuid.Nil
	startedDiagnostic := time.Now()
	if publish == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	defer func() {
		if resultErr != nil {
			c.emitRuntimeDiagnostic(ctx, "maintenance_pulse", stage, connection, startedDiagnostic, true)
		}
	}()
	started := c.recoveryNow()
	seen := map[uuid.UUID]bool{}
	stage = "history"
	for id, a := range c.active {
		stage = "history"
		if allowed[id] && a.Entry.ContractVersion == 2 {
			connection = id
			e := a.Entry
			h := c.recoveryHistory[id]
			epoch := recoveryEpoch{Binding: e.Engines[0].Binding, PolicyHash: a.Identity.PolicyHash, DeliveryID: e.DeliveryID, Namespace: e.Allocation.Namespace, Tunnels: [2]uuid.UUID{e.Engines[0].TunnelID, e.Engines[1].TunnelID}}
			stage = "history_entry"
			if !validJournalRecovery(e) || e.Recovery.Stage != "completed" || !validRecoveryEpoch(epoch) {
				return ErrRuntimeController
			}
			// Report clocks survive advisory-history invalidation. A known clock
			// discontinuity still refuses even when that history is absent.
			stage = "clock"
			clock, known := c.recoveryReportClock(a)
			if known && c.recoveryNow() < clock.returned {
				return ErrRuntimeController
			}
			// A canceled recovery observation can discard this process-local
			// advice without revoking an active owner. Omit its optional pulse;
			// ordinary maintenance still requires fresh leases and exact native
			// proofs, and ordinary Apply can establish new recovery advice.
			if h == nil || !h.seen {
				seen[id] = true
				continue
			}
			stage = "history_epoch"
			if h.epoch != epoch {
				return ErrRuntimeController
			}
			stage = "history_selection"
			if h.current != selectedRuntimeSlot(e) {
				return ErrRuntimeController
			}
			stage = "history_clock"
			if c.recoveryNow() < h.lastNow {
				return ErrRuntimeController
			}
			// Active telemetry may wait at most three seconds between turns;
			// standalone and inactive recovery keep their original due intervals.
			stage = "clock"
			if known && c.recoveryNow()-clock.returned < 3*time.Second {
				seen[id] = true
			}
		}
		stage = "history"
		if !allowed[id] {
			seen[id] = true
		}
	}
	connection = uuid.Nil
	stage = "sample"
	reports, err := c.refreshIPsecActiveRecoveryLocked(ctx, seen, true, time.Now())
	if err != nil {
		return err
	}
	for _, out := range reports {
		connection = out.ConnectionID
		stage = "report_binding"
		if out.Report.SelectionSequence == nil {
			return ErrRuntimeController
		}
		before, ok := c.active[out.ConnectionID]
		if !ok || !reflect.DeepEqual(before.Delivery, out.Delivery) || before.Authority == nil {
			return ErrRuntimeController
		}
		stage = "publish"
		if publish(ctx, out) != nil {
			return ErrRuntimeController
		}
		stage = "final_binding"
		after, ok := c.active[out.ConnectionID]
		final := c.recoveryNow()
		if !ok || !reflect.DeepEqual(after, before) || final < started || final-started > 5*time.Second || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
			return ErrRuntimeController
		}
		stage = "prior_reserve"
		if _, err = before.Authority.RemainingForApply(before.Identity, 5*time.Second); err != nil {
			return ErrRuntimeController
		}
		stage = "remember"
		if !c.rememberRecoveryReport(ctx, out.ConnectionID, out.Delivery, out.Report) {
			return ErrRuntimeController
		}
	}
	return nil
}
