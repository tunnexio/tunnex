package ipsec

import (
	"context"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// The recovery reducer's lastNow is a native sample clock, including samples
// that cannot publish a newer durable sequence. Keep report timing separate.
// This clock schedules telemetry only and carries no forwarding authority.
type runtimeRecoveryReportClock struct {
	epoch    recoveryEpoch
	digest   string
	current  uint8
	sequence uint64
	returned time.Duration
}

func recoveryReportEpoch(a runtimeActive) recoveryEpoch {
	e := a.Entry
	return recoveryEpoch{Binding: e.Engines[0].Binding, PolicyHash: a.Identity.PolicyHash, DeliveryID: e.DeliveryID, Namespace: e.Allocation.Namespace, Tunnels: [2]uuid.UUID{e.Engines[0].TunnelID, e.Engines[1].TunnelID}}
}

func (c *RuntimeController) recoveryReportClock(a runtimeActive) (runtimeRecoveryReportClock, bool) {
	clock, known := c.recoveryReportClocks[a.Entry.Allocation.ConnectionID]
	epoch := recoveryReportEpoch(a)
	return clock, known && validRecoveryEpoch(epoch) && clock.epoch == epoch && clock.digest == a.Entry.OwnershipDigest && clock.current == selectedRuntimeSlot(a.Entry) && clock.sequence > 0 && clock.sequence <= c.recoveryStatusSequence[a.Entry.DeliveryID]
}

// The owner holds c.mu. Call only when a real native observation is returned or
// its maintenance callback has completed; sequence assignment before native IO
// and equal-sequence skipped samples cannot move the report clock.
func (c *RuntimeController) rememberRecoveryReport(ctx context.Context, id uuid.UUID, d RuntimeDelivery, report RuntimeStatusReport) bool {
	if c == nil || ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return false
	}
	a, known := c.active[id]
	if !known || a.Authority == nil || a.Entry.ContractVersion != 2 || a.Entry.Phase != RuntimeApplied || !validJournalRecovery(a.Entry) || a.Entry.Recovery.Stage != "completed" || a.Entry.DeliveryID != d.ID || a.Entry.OwnershipDigest != d.OwnershipDigest || !reflect.DeepEqual(a.Delivery, d) {
		return false
	}
	epoch := recoveryReportEpoch(a)
	h := c.recoveryHistory[id]
	if !validRecoveryEpoch(epoch) || h == nil || !h.seen || h.epoch != epoch || h.current != selectedRuntimeSlot(a.Entry) || report.DeliveryID != d.ID || report.DesiredRevision != d.DesiredRevision || report.ConfigurationRevision != d.Manifest.ConfigurationRevision || report.RecoveryVersion == nil || *report.RecoveryVersion != 1 || report.SelectionSequence == nil {
		return false
	}
	sequence := *report.SelectionSequence
	if sequence == 0 || sequence > 9007199254740991 || sequence != c.recoveryStatusSequence[d.ID] {
		return false
	}
	for i, tunnel := range report.Tunnels {
		if tunnel.ID != d.Manifest.Tunnels[i].ID || tunnel.Slot != i+1 || tunnel.Selected != d.Manifest.Tunnels[i].Selected || (tunnel.Status != "up" && tunnel.Status != "down" && tunnel.Status != "unknown") {
			return false
		}
	}
	if report.ActiveSlot != nil && (*report.ActiveSlot != int(selectedRuntimeSlot(a.Entry)) || report.Tunnels[*report.ActiveSlot-1].Status != "up") {
		return false
	}
	if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
		return false
	}
	now := c.recoveryNow()
	clock, current := c.recoveryReportClock(a)
	if now < h.lastNow || (current && (now < clock.returned || sequence <= clock.sequence)) {
		return false
	}
	if c.recoveryReportClocks == nil {
		c.recoveryReportClocks = map[uuid.UUID]runtimeRecoveryReportClock{}
	}
	c.recoveryReportClocks[id] = runtimeRecoveryReportClock{epoch: epoch, digest: a.Entry.OwnershipDigest, current: selectedRuntimeSlot(a.Entry), sequence: sequence, returned: now}
	return true
}
