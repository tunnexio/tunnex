package ipsec

import (
	"context"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
)

type maintenancePulseSnapshot struct {
	clock   runtimeRecoveryReportClock
	history recoveryDecision
	active  runtimeActive
}

// This schedules optional telemetry only. The one-second native sample interval
// bounds the entire collection, not each owner. Every original lease, bridge and
// combined native proof still runs against its real monotonic clock.
type maintenancePulseDeferral struct {
	started time.Duration
	owners  map[uuid.UUID]maintenancePulseSnapshot
	open    bool
	used    bool
}

func (c *RuntimeController) beginMaintenancePulseDeferral(allowed map[uuid.UUID]bool, publish func(context.Context, RuntimeRecoveryHeartbeat) error) *maintenancePulseDeferral {
	if publish == nil {
		return nil
	}
	d := &maintenancePulseDeferral{started: c.recoveryNow(), owners: map[uuid.UUID]maintenancePulseSnapshot{}, open: true}
	for id, a := range c.active {
		if !allowed[id] || a.Entry.ContractVersion != 2 {
			continue
		}
		clock, known := c.recoveryReportClock(a)
		h := c.recoveryHistory[id]
		// Missing advice or publication evidence retains the original scheduling.
		// A real returned report must be inside the unchanged two-second debounce.
		if a.Entry.Phase != RuntimeApplied || !validJournalRecovery(a.Entry) || a.Entry.Recovery.Stage != "completed" || !known || h == nil || !h.seen || h.epoch != clock.epoch || h.current != clock.current || d.started < h.lastNow || d.started < clock.returned || d.started-clock.returned >= 2*time.Second || a.Authority == nil {
			return nil
		}
		before := cloneMaintenanceActive(a)
		d.owners[id] = maintenancePulseSnapshot{clock: clock, history: *h, active: before}
	}
	if len(d.owners) == 0 {
		return nil
	}
	return d
}

func (d *maintenancePulseDeferral) deferPulse(ctx context.Context, c *RuntimeController) bool {
	if d == nil || !d.open {
		return false
	}
	now := c.recoveryNow()
	if ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || now < d.started || now-d.started >= time.Second {
		d.open = false
		return false
	}
	due := false
	for id, before := range d.owners {
		a, present := c.active[id]
		clock, known := c.recoveryReportClock(a)
		h := c.recoveryHistory[id]
		if !present || !known || clock != before.clock || h == nil || *h != before.history || now < h.lastNow || now < clock.returned || !reflect.DeepEqual(a, before.active) {
			d.open = false
			return false
		}
		if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
			d.open = false
			return false
		}
		due = due || now-clock.returned >= 2*time.Second
	}
	d.used = d.used || due
	return true
}

// Deferral may not create a stale report interval during slower native assembly,
// commit or publication. Reuse the existing ten-second report requirement; an
// overrun refuses through the ordinary maintenance failure path. The clock can
// advance only through an actual newer, exact-bound returned observation.
func (d *maintenancePulseDeferral) reportsCurrent(c *RuntimeController) bool {
	return d.reportsCurrentWithRecovery(c, nil)
}

// A freshly sampled recovery report is published before rememberRecoveryReport
// advances its returned clock. Its own previous report may cross the report-age
// boundary during sampling. Qualify that exact pending observation without
// changing a clock or granting any forwarding authority; other owners still
// require their already returned reports. The private caller holds c.mu and
// supplies the report directly from refreshIPsecActiveRecoveryLockedQualified;
// there is no external or cached report ingress at this publication boundary.
func (d *maintenancePulseDeferral) reportsCurrentForRecovery(ctx context.Context, c *RuntimeController, out RuntimeRecoveryHeartbeat) bool {
	if ctx.Err() != nil {
		return false
	}
	if d != nil && d.used {
		if _, tracked := d.owners[out.ConnectionID]; !tracked {
			return false
		}
	}
	return d.reportsCurrentWithRecovery(c, &out)
}

func (d *maintenancePulseDeferral) reportsCurrentWithRecovery(c *RuntimeController, pending *RuntimeRecoveryHeartbeat) bool {
	if d == nil || !d.used {
		return true
	}
	now := c.recoveryNow()
	if now < d.started {
		return false
	}
	for id, before := range d.owners {
		a, present := c.active[id]
		clock, known := c.recoveryReportClock(a)
		h := c.recoveryHistory[id]
		previous := before.active
		previous.Authority = a.Authority // Only the completed finite renewal may replace authority.
		if !present || !reflect.DeepEqual(a, previous) || a.Entry.Phase != RuntimeApplied || !validJournalRecovery(a.Entry) || a.Entry.Recovery.Stage != "completed" || !known || clock.sequence < before.clock.sequence || clock.returned < before.clock.returned || clock.epoch != before.clock.epoch || clock.digest != before.clock.digest || clock.current != before.clock.current || h == nil || !h.seen || h.epoch != clock.epoch || h.current != clock.current || now < h.lastNow || now < clock.returned {
			return false
		}
		if pending != nil && pending.ConnectionID == id {
			if !maintenancePendingRecoveryCurrent(c, a, clock, h, now, *pending) {
				return false
			}
		} else if now-clock.returned > 10*time.Second {
			return false
		}
	}
	return true
}

func maintenancePendingRecoveryCurrent(c *RuntimeController, a runtimeActive, clock runtimeRecoveryReportClock, h *recoveryDecision, now time.Duration, out RuntimeRecoveryHeartbeat) bool {
	r, d := out.Report, out.Delivery
	if !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || a.Authority == nil || out.ConnectionID != a.Entry.Allocation.ConnectionID || !reflect.DeepEqual(d, a.Delivery) || r.BGP != nil || r.TransportVersion != nil || r.TunnelCount != nil || r.DeliveryID != d.ID || r.DesiredRevision != d.DesiredRevision || r.ConfigurationRevision != d.Manifest.ConfigurationRevision || r.RecoveryVersion == nil || *r.RecoveryVersion != 1 || r.SelectionSequence == nil || *r.SelectionSequence == 0 || *r.SelectionSequence > 9007199254740991 || *r.SelectionSequence <= clock.sequence || *r.SelectionSequence != c.recoveryStatusSequence[d.ID] || h.lastAt < 0 || h.lastAt <= clock.returned || h.lastAt > h.lastNow || h.lastNow > now || now-h.lastAt > 5*time.Second {
		return false
	}
	if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
		return false
	}
	for i, tunnel := range r.Tunnels {
		if tunnel.ID != d.Manifest.Tunnels[i].ID || tunnel.Slot != i+1 || tunnel.Selected != d.Manifest.Tunnels[i].Selected || (tunnel.Status != "up" && tunnel.Status != "down") {
			return false
		}
	}
	selected := int(selectedRuntimeSlot(a.Entry))
	if selected < 1 || selected > len(r.Tunnels) {
		return false
	}
	if r.Tunnels[selected-1].Status == "up" {
		return r.ActiveSlot != nil && *r.ActiveSlot == selected
	}
	return r.ActiveSlot == nil
}

// Only an owner already excluded by ordinary maintenance may leave tracking.
// The combined guard still has its journal entry and must install its denial.
func (d *maintenancePulseDeferral) finishCollection(staged map[uuid.UUID]runtimeActive) {
	if d == nil {
		return
	}
	d.open = false
	for id := range d.owners {
		if _, retained := staged[id]; !retained {
			delete(d.owners, id)
		}
	}
}

func cloneMaintenanceActive(a runtimeActive) runtimeActive {
	before := cloneDNSOwnerActive(a)
	before.Delivery = a.Delivery
	m := &before.Delivery.Manifest
	m.LocalPrefixes = copyDNSSlice(m.LocalPrefixes)
	m.RemotePrefixes = copyDNSSlice(m.RemotePrefixes)
	m.RetainedGuardPredecessors = copyDNSSlice(m.RetainedGuardPredecessors)
	m.TransportVersion, m.TunnelCount = copyDNSPointer(m.TransportVersion), copyDNSPointer(m.TunnelCount)
	m.RecoveryVersion, m.BGPVersion = copyDNSPointer(m.RecoveryVersion), copyDNSPointer(m.BGPVersion)
	m.BGP = copyDNSPointer(m.BGP)
	m.AzureBGPRecreationVersion = copyDNSPointer(m.AzureBGPRecreationVersion)
	m.AzureProfileRecreationVersion = copyDNSPointer(m.AzureProfileRecreationVersion)
	return before
}

// Extra telemetry must be funded by original authorities, never the newly
// collected candidates. One attempt per original tracked owner uses the existing
// five-second sample bound and keeps the original five-second commit reserve.
// Tight windows keep their ordinary schedule and every original freshness fence.
func (d *maintenancePulseDeferral) pulseBeforeAssembly(ctx context.Context, c *RuntimeController, publish func(context.Context, RuntimeRecoveryHeartbeat) error) error {
	if d == nil || !d.used || len(d.owners) == 0 || publish == nil {
		return nil
	}
	if !d.reportsCurrent(c) || ctx.Err() != nil {
		return ErrRuntimeController
	}
	// A total budget at/above the lease ceiling cannot be funded. Skip optional
	// work rather than impose a new owner-count limit or overflow a duration.
	if len(d.owners) >= int(MaxPermitLease/(5*time.Second))-1 {
		return nil
	}
	budget := time.Duration(len(d.owners)+1) * 5 * time.Second
	original := make(map[uuid.UUID]runtimeActive, len(c.active))
	for id, a := range c.active {
		if a.Authority == nil {
			return ErrRuntimeController
		}
		if _, err := a.Authority.RemainingForApply(a.Identity, budget); err != nil {
			return nil
		}
		original[id] = cloneMaintenanceActive(a)
	}
	ids := make([]uuid.UUID, 0, len(d.owners))
	for id, before := range d.owners {
		if !reflect.DeepEqual(original[id], before.active) {
			return ErrRuntimeController
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := c.recoveryReportClocks[ids[i]], c.recoveryReportClocks[ids[j]]
		if a.returned != b.returned {
			return a.returned < b.returned
		}
		return ids[i].String() < ids[j].String()
	})
	originalCurrent := func() bool {
		if !reflect.DeepEqual(c.active, original) {
			return false
		}
		for _, a := range original {
			if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
				return false
			}
		}
		return true
	}
	for _, id := range ids {
		if !d.reportsCurrent(c) || ctx.Err() != nil || !originalCurrent() {
			return ErrRuntimeController
		}
		if err := c.refreshMaintenanceActiveRecovery(ctx, map[uuid.UUID]bool{id: true}, publish); err != nil {
			return err
		}
		if !originalCurrent() {
			return ErrRuntimeController
		}
	}
	if !d.reportsCurrent(c) || ctx.Err() != nil {
		return ErrRuntimeController
	}
	return nil
}
