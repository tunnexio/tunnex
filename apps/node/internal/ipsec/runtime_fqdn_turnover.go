package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"time"
)

type runtimeCurrentMaterialClient interface {
	IPsecMaterial(context.Context, uuid.UUID, int64) (RuntimeMaterial, error)
}

// refreshFQDNExpiryMaterial handles only an authenticated expiry-only rollover.
// A conflict never authorizes anything: a fresh normal material and a subsequent
// new-nonce lease must both succeed before the caller can atomically replace permits.
func (c *RuntimeController) refreshFQDNExpiryMaterial(ctx context.Context, old runtimeActive) (maintenanceItem, error) {
	client, ok := c.client.(runtimeCurrentMaterialClient)
	if !ok || ctx.Err() != nil || len(old.FQDNLeaseDescriptors) == 0 {
		return maintenanceItem{}, ErrRuntimeController
	}
	m, err := client.IPsecMaterial(ctx, old.Entry.Allocation.ConnectionID, old.Delivery.DesiredRevision)
	defer func() {
		for i := range m.Secrets {
			m.Secrets[i] = RuntimeSecret{}
		}
	}()
	if err != nil {
		return maintenanceItem{}, ErrRuntimeController
	}
	return c.prepareFQDNExpiryMaterial(ctx, old, m)
}

func (c *RuntimeController) prepareFQDNExpiryMaterial(ctx context.Context, old runtimeActive, m RuntimeMaterial) (maintenanceItem, error) {
	if ctx.Err() != nil || len(old.FQDNLeaseDescriptors) == 0 || !reflect.DeepEqual(m.RuntimeDelivery, old.Delivery) || m.Policy.Hash == old.Identity.PolicyHash {
		return maintenanceItem{}, ErrRuntimeController
	}
	entry, grants, err := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, old.Environment.Namespace)
	if err != nil {
		return maintenanceItem{}, ErrRuntimeController
	}
	// Match the same immutable native intent, retaining only journal-owned runtime
	// progress fields. This is not an Apply/reconfiguration or a new delivery.
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
	if entry.ContractVersion == 2 {
		entry.Recovery = old.Entry.Recovery
	}
	if !reflect.DeepEqual(entry, old.Entry) {
		return maintenanceItem{}, ErrRuntimeController
	}
	descriptors := runtimeFQDNLeaseDescriptors(m.Policy)
	if len(descriptors) != len(old.FQDNLeaseDescriptors) {
		return maintenanceItem{}, ErrRuntimeController
	}
	advanced := false
	for i, next := range descriptors {
		prior := old.FQDNLeaseDescriptors[i]
		if next.ExpiresAt.Before(prior.ExpiresAt) || !next.ExpiresAt.After(time.Now()) {
			return maintenanceItem{}, ErrRuntimeController
		}
		advanced = advanced || next.ExpiresAt.After(prior.ExpiresAt)
		next.ExpiresAt, prior.ExpiresAt = time.Time{}, time.Time{}
		if next != prior {
			return maintenanceItem{}, ErrRuntimeController
		}
	}
	if !advanced {
		return maintenanceItem{}, ErrRuntimeController
	}
	// Fresh native peer/no-SNAT observations are still mandatory for desktop grants.
	grants, err = c.observeDesktopGrants(ctx, grants)
	if err != nil || ctx.Err() != nil || len(grants) != len(old.Grants) || !c.fqdnGrantsCurrent(grants) {
		return maintenanceItem{}, ErrRuntimeController
	}
	for i, next := range grants {
		prior := old.Grants[i]
		if next.FQDNManaged {
			next.FQDN.ExpiresAt, prior.FQDN.ExpiresAt = time.Time{}, time.Time{}
			next.DesktopExpiresAt, prior.DesktopExpiresAt = time.Time{}, time.Time{}
		}
		if next != prior {
			return maintenanceItem{}, ErrRuntimeController
		}
	}
	return maintenanceItem{RuntimeDelivery: m.RuntimeDelivery, Entry: entry, Grants: grants, FQDNLeaseDescriptors: descriptors, PolicyHash: m.Policy.Hash, FQDNExpiryPriorHash: old.Identity.PolicyHash}, nil
}
