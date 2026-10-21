package ipsec

import (
	"context"
	"reflect"

	"github.com/google/uuid"
)

// A DNS failure/revocation or restoration can change the policy hash without
// changing any ordinary application or transport intent. This witness permits
// collecting NEW authority only; it never transfers the old policy's lease.
// Restrict it to removal of all desktop static-CNAME grants, or restoration
// from none, on an already-exported AWS BGP desktop source. Changed nonempty
// generations continue through the existing expiry-only/ordinary Apply paths.
func (c *RuntimeController) fqdnPolicyTransitionEligible(old runtimeActive, m maintenanceItem) bool {
	if old.Entry.ContractVersion != 3 || old.Entry.Allocation.ProfileID != "" || !old.Entry.Allocation.BGP || !validDigest(m.PolicyHash) || m.PolicyHash == old.Identity.PolicyHash || (len(old.FQDNLeaseDescriptors) == 0) == (len(m.FQDNLeaseDescriptors) == 0) {
		return false
	}
	if c.config.FQDNPolicy == nil {
		return false
	}
	view := c.config.FQDNPolicy.view.Load()
	if view == nil || view.policy.NodeID != c.config.GatewayID.String() {
		return false
	}
	for _, f := range old.FQDNLeaseDescriptors {
		if f.ResolverKind != "static_cname" || f.DeviceID == "" || f.PublicKey == "" {
			return false
		}
	}
	if len(m.FQDNLeaseDescriptors) == 0 {
		for _, prior := range old.FQDNLeaseDescriptors {
			for _, allow := range view.policy.Allow {
				if allow.FQDNManaged && allow.RuleID == prior.RuleID {
					return false
				}
			}
		}
	}
	ordinary := make([]GuardGrant, 0, len(m.Grants))
	marked := 0
	for _, g := range old.Grants {
		if g.FQDNManaged {
			return false
		}
	} // scoped withdrawal must already be complete
	for _, g := range m.Grants {
		if !g.FQDNManaged {
			ordinary = append(ordinary, g)
			continue
		}
		if g.FQDN.Version != 2 || g.FQDN.ResolverKind != "static_cname" || g.DesktopDeviceID == uuid.Nil {
			return false
		}
		known := false
		for _, prefix := range c.bgpDesktopExports[old.Entry.DeliveryID] {
			known = known || prefix == g.Source
		}
		if !known {
			return false
		} // no new BGP export or source is adopted by maintenance
		marked++
	}
	if len(old.Grants) != len(ordinary) {
		return false
	}
	for i := range ordinary {
		if old.Grants[i] != ordinary[i] {
			return false
		}
	}
	return marked == len(m.FQDNLeaseDescriptors) && c.fqdnGrantsCurrent(m.Grants)
}

// The conflict path reads normal material once. Expiry-only rollover keeps its
// existing validator; the distinct policy-transition path first withdraws old
// marked grants, preserving only exact ordinary tuples under the old deadline.
func (c *RuntimeController) refreshFQDNMaintenanceMaterial(ctx context.Context, old runtimeActive) (maintenanceItem, runtimeActive, error) {
	client, ok := c.client.(runtimeCurrentMaterialClient)
	if !ok || ctx.Err() != nil {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	m, err := client.IPsecMaterial(ctx, old.Entry.Allocation.ConnectionID, old.Delivery.DesiredRevision)
	defer func() {
		for i := range m.Secrets {
			m.Secrets[i] = RuntimeSecret{}
		}
	}()
	if err != nil {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	if item, e := c.prepareFQDNExpiryMaterial(ctx, old, m); e == nil {
		return item, old, nil
	}
	if !reflect.DeepEqual(m.RuntimeDelivery, old.Delivery) {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	entry, grants, err := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, old.Environment.Namespace)
	if err != nil {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	for i := range entry.Engines[:entry.Allocation.activeTunnelCount()] {
		entry.Engines[i].LocalAddress = old.Environment.Underlays[i].LocalAddress
	}
	entry.Restoration, entry.Allocation.Generation = old.Entry.Restoration, old.Entry.Allocation.Generation
	for i := range entry.Allocation.Tunnels[:entry.Allocation.activeTunnelCount()] {
		entry.Allocation.Tunnels[i].Alias = old.Entry.Allocation.Tunnels[i].Alias
	}
	entry.Phase, entry.Observed = old.Entry.Phase, old.Entry.Observed
	if entry.ContractVersion == 3 {
		entry.BGPRoutes, entry.BGPProcess, entry.BGPProcessRetired, entry.BGPProcessHistory = old.Entry.BGPRoutes, old.Entry.BGPProcess, old.Entry.BGPProcessRetired, old.Entry.BGPProcessHistory
	}
	if !reflect.DeepEqual(entry, old.Entry) {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	c.publishDesktopNAT(old.Entry.Allocation.ConnectionID, grants)
	grants, err = c.observeDesktopGrants(ctx, grants)
	if err != nil || ctx.Err() != nil {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	item := maintenanceItem{RuntimeDelivery: m.RuntimeDelivery, Entry: entry, Grants: grants, FQDNLeaseDescriptors: runtimeFQDNLeaseDescriptors(m.Policy), PolicyHash: m.Policy.Hash, FQDNPolicyPriorHash: old.Identity.PolicyHash}
	pruned := old
	pruned.Grants = make([]GuardGrant, 0, len(old.Grants))
	for _, g := range old.Grants {
		if !g.FQDNManaged {
			pruned.Grants = append(pruned.Grants, g)
		} else if g.FQDN.Version != 2 || g.FQDN.ResolverKind != "static_cname" || g.DesktopDeviceID == uuid.Nil {
			return maintenanceItem{}, old, ErrRuntimeController
		}
	}
	if !reflect.DeepEqual(c.active[old.Entry.Allocation.ConnectionID], old) || !c.fqdnPolicyTransitionEligible(pruned, item) {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	if err = c.withdrawChangedFQDNMaterial(ctx, m, grants); err != nil {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	current, ok := c.active[old.Entry.Allocation.ConnectionID]
	if !ok || ctx.Err() != nil || !reflect.DeepEqual(current, pruned) {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	return item, current, nil
}

// BeforePolicy publishes its conservative intersection before waiting for the
// owner lock. A renewal that already owns that lock must perform the existing
// scoped withdrawal before taking retained snapshots, rather than treating an
// intentionally removed marked grant as failure of all ordinary authority.
func (c *RuntimeController) withdrawPendingFQDNPolicyLocked(ctx context.Context) error {
	var ids []uuid.UUID
	for id, a := range c.active {
		if c.fqdnGrantsCurrent(a.Grants) {
			continue
		}
		if a.Entry.ContractVersion != 3 || a.Entry.Allocation.ProfileID != "" || c.config.FQDNPolicy == nil {
			return ErrRuntimeController
		}
		view := c.config.FQDNPolicy.view.Load()
		if view == nil || view.policy.NodeID != c.config.GatewayID.String() {
			return ErrRuntimeController
		}
		for _, g := range a.Grants {
			if g.FQDNManaged && (g.FQDN.Version != 2 || g.FQDN.ResolverKind != "static_cname" || g.DesktopDeviceID == uuid.Nil) {
				return ErrRuntimeController
			}
		}
		ids = append(ids, id)
	}
	return c.withdrawFQDNActiveLocked(ctx, ids)
}
