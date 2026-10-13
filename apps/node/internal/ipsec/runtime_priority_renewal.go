package ipsec

import (
	"context"
	"reflect"
	"runtime"
	"sort"

	"github.com/google/uuid"
)

// RenewActiveIPsecRuntimeObserved renews only exact process-local applied owners.
// It obtains a new authoritative CP lease for each owner, proves the existing
// native transport and atomically installs finite permits using normal maintenance.
// It never fetches or caches private material, performs first Apply, or emits ACKs.
func (c *RuntimeController) RenewActiveIPsecRuntimeObserved(ctx context.Context, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error) error {
	if c == nil {
		return ErrRuntimeController
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !supportedRuntimePlatform(runtime.GOOS, runtime.GOARCH) {
		return ErrRuntimeController
	}
	for _, a := range c.active {
		if a.Entry.ContractVersion == 3 && !c.bgpQualificationCurrent() {
			return ErrRuntimeController
		}
	}
	return c.renewActiveIPsecRuntimeObserved(ctx, NewPermitLeaseAuthority, c.bgpQualificationCurrent, publish, publishRecovery)
}

func (c *RuntimeController) renewActiveIPsecRuntimeObserved(ctx context.Context, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error) error {
	count := len(c.active)
	prepare := func(ns string, entries []RuntimeJournalEntry) ([]maintenanceItem, error) {
		ids := make([]uuid.UUID, 0, count)
		for id := range c.active {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
		items := make([]maintenanceItem, 0, count)
		deliveries := map[uuid.UUID]bool{}
		for _, id := range ids {
			a := c.active[id]
			d, e := a.Delivery, a.Entry
			if !runtimeDeliveryValid(d, c.config.OrgID, c.config.GatewayID, "apply") || d.CoversDeliveryRevision != 0 || d.Manifest.ConnectionID != id || d.ID != e.DeliveryID || d.OwnershipDigest != e.OwnershipDigest || d.DesiredRevision != e.Engines[0].Binding.DesiredRevision || e.Allocation.ConnectionID != id || e.Allocation.Namespace != ns || e.Phase != RuntimeApplied || (e.ContractVersion != 2 && e.ContractVersion != 3) || a.Authority == nil || !validDigest(a.Identity.PolicyHash) || a.Identity != (PermitLeaseIdentity{DeliveryID: d.ID, Binding: e.Engines[0].Binding, PolicyHash: a.Identity.PolicyHash}) || !reflect.DeepEqual(a.Environment.Namespace, ns) || deliveries[d.ID] || !c.fqdnGrantsCurrent(a.Grants) {
				return nil, ErrRuntimeController
			}
			// A process-local record is not sufficient by itself: require its
			// exact complete applied entry in the trusted current journal.
			matches := 0
			for _, current := range entries {
				if current.Allocation.ConnectionID == id && current.DeliveryID == d.ID {
					if !reflect.DeepEqual(current, e) {
						return nil, ErrRuntimeController
					}
					matches++
				}
			}
			if matches != 1 {
				return nil, ErrRuntimeController
			}
			deliveries[d.ID] = true
			items = append(items, maintenanceItem{RuntimeDelivery: d, Entry: e, Grants: a.Grants, PolicyHash: a.Identity.PolicyHash})
		}
		return items, nil
	}
	// The returned normal maintenance results are deliberately discarded: retained
	// applied context cannot acknowledge a fresh pending delivery or cleanup.
	_, err := c.maintainIPsecRuntimeItems(ctx, count, prepare, authority, bgpCurrent, publish, publishRecovery)
	return err
}
