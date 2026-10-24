package ipsec

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// This optimization is restricted to the qualified mixed AWS short-DNS slice.
// Other providers and ordinary-only gateways retain their existing pipeline.
func (c *RuntimeController) exactPageRefreshScope() bool {
	if c == nil || !c.started || c.closed || len(c.active) < 2 || len(c.active) > 256 || len(c.fqdnNativeWindows) < 2 {
		return false
	}
	currentWindows := 0
	for id, w := range c.fqdnNativeWindows {
		if a, ok := c.active[id]; ok && len(a.FQDNLeaseDescriptors) > 0 && a.Authority != nil && a.Authority == w.owner.Authority && reflect.DeepEqual(a, w.owner) {
			currentWindows++
		}
	}
	if currentWindows < 2 {
		return false
	}
	for _, a := range c.active {
		if a.Entry.Allocation.ProfileID != "" || (a.Delivery.Manifest.ProfileID != "aws-static-ipv4-v1" && a.Delivery.Manifest.ProfileID != "aws-bgp-ipv4-v1") {
			return false
		}
		if (a.Delivery.Manifest.ProfileID == "aws-static-ipv4-v1") != (a.Entry.ContractVersion == 2) {
			return false
		}
		if !runtimeFQDNFollowupEntrySupported(a.Entry) || a.Entry.AbsenceOnly || a.Entry.Phase != RuntimeApplied {
			return false
		}
	}
	return true
}

// Classify a complete current page without mutating any runtime owner. A
// semantic change, new delivery or partial page stays on the normal path.
// Once candidate work begins, refusal is handled here and cannot replay Apply.
func (c *RuntimeController) tryMaintainExactRuntimePage(ctx context.Context, materials []RuntimeMaterial, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) ([]RuntimeMaintenanceResult, bool, error) {
	if !c.exactPageRefreshScope() || len(materials) != len(c.active) || ctx.Err() != nil {
		return nil, false, nil
	}
	if _, gateErr := os.Lstat(filepath.Join(c.config.JournalDir, "restoration-startup-gate")); !os.IsNotExist(gateErr) {
		return nil, false, nil
	}
	ns, err := c.namespace()
	if err != nil {
		return nil, false, nil
	}
	entries, err := c.journal.Entries()
	if err != nil {
		return nil, false, nil
	}
	seen, deliveries := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
	candidates := map[uuid.UUID]maintenanceItem{}
	for _, m := range materials {
		id := m.Manifest.ConnectionID
		old, ok := c.active[id]
		if !ok || seen[id] || deliveries[m.ID] || old.Environment.Namespace != ns || old.Entry.Allocation.Namespace != ns || !reflect.DeepEqual(m.RuntimeDelivery, old.Delivery) || old.Authority == nil || !c.fqdnGrantsCurrent(old.Grants) {
			return nil, false, nil
		}
		seen[id], deliveries[m.ID] = true, true
		matches := 0
		for _, e := range entries {
			if e.Allocation.ConnectionID == id {
				if e.DeliveryID == old.Delivery.ID {
					if !reflect.DeepEqual(e, old.Entry) {
						return nil, false, nil
					}
					matches++
				} else if e.Phase != RuntimeRetainedRefusal || e.CleanupDesiredRevision >= m.DesiredRevision {
					return nil, false, nil
				}
			}
		}
		if matches != 1 {
			return nil, false, nil
		}
		var item maintenanceItem
		if len(old.FQDNLeaseDescriptors) > 0 {
			item, err = c.prepareFQDNFollowupMaterial(ctx, old, m, true)
		} else {
			item, err = c.prepareExactOrdinaryPageMaterial(ctx, old, m)
		}
		if err != nil {
			return nil, false, nil
		}
		if item.PolicyHash != old.Identity.PolicyHash || c.maintenanceRenewalDue(old) {
			candidates[id] = item
		}
	}
	if len(candidates) == 0 {
		// The complete page is byte-for-byte current, but claiming validation
		// still requires fresh native/route proof for every original owner.
		owners := map[uuid.UUID]runtimeActive{}
		for id, a := range c.active {
			owners[id] = cloneMaintenanceActive(a)
		}
		fail := func() ([]RuntimeMaintenanceResult, bool, error) {
			c.withdrawDNSOwnerView(uuid.Nil)
			c.active = nil
			_, _ = c.refuse(ctx, entries)
			return nil, true, &runtimeMaintenanceBatchAborted{}
		}
		for _, a := range owners {
			if c.maintenanceCurrent(ctx, a, bgpCurrent) != nil {
				return fail()
			}
		}
		if c.retainedMaintenanceCurrent(ctx, owners, bgpCurrent) != nil {
			return fail()
		}
		result := make([]RuntimeMaintenanceResult, 0, len(materials))
		for _, m := range materials {
			d := m.RuntimeDelivery
			result = append(result, RuntimeMaintenanceResult{Retained: &d})
		}
		return result, true, nil
	}
	reports := map[uuid.UUID]RuntimeStatusReport{}
	capture := func(parent context.Context, d RuntimeDelivery, out RuntimeStatusReport) error {
		item, ok := candidates[d.Manifest.ConnectionID]
		if !ok || !reflect.DeepEqual(item.RuntimeDelivery, d) || out.DeliveryID != d.ID || out.DesiredRevision != d.DesiredRevision || out.ConfigurationRevision != d.Manifest.ConfigurationRevision {
			return ErrRuntimeController
		}
		if _, duplicate := reports[d.ID]; duplicate {
			return ErrRuntimeController
		}
		if publish != nil {
			if err := publish(parent, d, out); err != nil {
				return err
			}
		}
		reports[d.ID] = out
		return nil
	}
	if err = c.commitExactRuntimeRefresh(ctx, authority, bgpCurrent, candidates, capture, true); err != nil {
		return nil, true, &runtimeMaintenanceBatchAborted{}
	}
	current := map[uuid.UUID]runtimeActive{}
	for id, a := range c.active {
		current[id] = cloneMaintenanceActive(a)
	}
	fail := func() ([]RuntimeMaintenanceResult, bool, error) {
		c.withdrawDNSOwnerView(uuid.Nil)
		c.active = nil
		_, _ = c.refuse(ctx, entries)
		return nil, true, &runtimeMaintenanceBatchAborted{}
	}
	if len(current) != len(materials) || c.retainedMaintenanceCurrent(ctx, current, bgpCurrent) != nil {
		return fail()
	}
	results := make([]RuntimeMaintenanceResult, 0, len(materials))
	for _, m := range materials {
		a, ok := current[m.Manifest.ConnectionID]
		if !ok || !reflect.DeepEqual(a.Delivery, m.RuntimeDelivery) {
			return fail()
		}
		if _, updated := candidates[m.Manifest.ConnectionID]; updated {
			report, present := reports[m.ID]
			if !present {
				return fail()
			}
			if a.Entry.ContractVersion == 2 {
				clock, known := c.recoveryReportClock(a)
				now := c.recoveryNow()
				if !known || report.SelectionSequence == nil || clock.sequence != *report.SelectionSequence || now < clock.returned || now-clock.returned > 10*time.Second {
					return fail()
				}
			}
			results = append(results, RuntimeMaintenanceResult{Acknowledgement: RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}, Report: report})
		} else {
			d := m.RuntimeDelivery
			results = append(results, RuntimeMaintenanceResult{Retained: &d})
		}
	}
	return results, true, nil
}

func (c *RuntimeController) prepareExactOrdinaryPageMaterial(ctx context.Context, old runtimeActive, m RuntimeMaterial) (maintenanceItem, error) {
	if !reflect.DeepEqual(m.RuntimeDelivery, old.Delivery) || m.Policy.Hash != old.Identity.PolicyHash || len(runtimeFQDNLeaseDescriptors(m.Policy)) != 0 {
		return maintenanceItem{}, ErrRuntimeController
	}
	e, g, err := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, old.Environment.Namespace)
	if err != nil {
		return maintenanceItem{}, err
	}
	for i := range e.Engines[:e.Allocation.activeTunnelCount()] {
		e.Engines[i].LocalAddress = old.Environment.Underlays[i].LocalAddress
		e.Allocation.Tunnels[i].Alias = old.Entry.Allocation.Tunnels[i].Alias
	}
	e.Restoration, e.Allocation.Generation, e.Phase, e.Observed = old.Entry.Restoration, old.Entry.Allocation.Generation, old.Entry.Phase, old.Entry.Observed
	if e.ContractVersion == 3 {
		e.BGPRoutes, e.BGPProcess, e.BGPProcessRetired, e.BGPProcessHistory = old.Entry.BGPRoutes, old.Entry.BGPProcess, old.Entry.BGPProcessRetired, old.Entry.BGPProcessHistory
	}
	if e.ContractVersion == 2 {
		e.Recovery = old.Entry.Recovery
	}
	if !reflect.DeepEqual(e, old.Entry) {
		return maintenanceItem{}, ErrRuntimeController
	}
	g, err = c.observeDesktopGrants(ctx, g)
	if err != nil || ctx.Err() != nil || !reflect.DeepEqual(g, old.Grants) || !c.fqdnGrantsCurrent(g) {
		return maintenanceItem{}, ErrRuntimeController
	}
	return maintenanceItem{RuntimeDelivery: m.RuntimeDelivery, Entry: e, Grants: g, FQDNLeaseDescriptors: runtimeFQDNLeaseDescriptors(m.Policy), PolicyHash: m.Policy.Hash}, nil
}
