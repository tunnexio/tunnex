package ipsec

import (
	"context"
	"reflect"
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
		if !present || !reflect.DeepEqual(a, previous) || a.Entry.Phase != RuntimeApplied || !validJournalRecovery(a.Entry) || a.Entry.Recovery.Stage != "completed" || !known || clock.sequence < before.clock.sequence || clock.returned < before.clock.returned || clock.epoch != before.clock.epoch || clock.digest != before.clock.digest || clock.current != before.clock.current || h == nil || !h.seen || h.epoch != clock.epoch || h.current != clock.current || now < h.lastNow || now < clock.returned || now-clock.returned > 10*time.Second {
			return false
		}
	}
	return true
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
