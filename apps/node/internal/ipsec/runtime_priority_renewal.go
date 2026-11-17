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
// An exact FQDN expiry conflict may fetch bounded current normal material,
// discarded immediately after validation. It never caches secrets, performs
// first Apply, or emits ACKs.
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
	// This retained-only scheduling choice is not validation and produces no
	// ACK. Normal discovery/material reconciliation and status observation run
	// afterward. Missing native emission advice always requests ordinary proof.
	due := map[uuid.UUID]bool{}
	dueScheduling := c.exactPageRefreshScope()
	for id, a := range c.active {
		due[id] = !dueScheduling || c.maintenanceRenewalDue(a)
	}
	count := 0
	for _, needed := range due {
		if needed {
			count++
		}
	}
	prepare := func(ns string, entries []RuntimeJournalEntry, stage *string, connection *uuid.UUID) ([]maintenanceItem, error) {
		ids := make([]uuid.UUID, 0, count)
		for id := range c.active {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
		items := make([]maintenanceItem, 0, count)
		deliveries := map[uuid.UUID]bool{}
		for _, id := range ids {
			*stage, *connection = "maintenance_priority_owner", id
			a := c.active[id]
			d, e := a.Delivery, a.Entry
			if !runtimeDeliveryValid(d, c.config.OrgID, c.config.GatewayID, "apply") || d.CoversDeliveryRevision != 0 || d.Manifest.ConnectionID != id || d.ID != e.DeliveryID || d.OwnershipDigest != e.OwnershipDigest || d.DesiredRevision != e.Engines[0].Binding.DesiredRevision || e.Allocation.ConnectionID != id || e.Allocation.Namespace != ns || e.Phase != RuntimeApplied || (e.ContractVersion != 2 && e.ContractVersion != 3 && !(e.ContractVersion == 4 && e.Allocation.ProfileID == GCPClassicStaticProfile && validClassicJournal(e))) || a.Authority == nil || !validDigest(a.Identity.PolicyHash) || a.Identity != (PermitLeaseIdentity{DeliveryID: d.ID, Binding: e.Engines[0].Binding, PolicyHash: a.Identity.PolicyHash}) || !reflect.DeepEqual(a.Environment.Namespace, ns) || deliveries[d.ID] {
				return nil, ErrRuntimeController
			}
			// A process-local record is not sufficient by itself: require its
			// exact complete applied entry in the trusted current journal.
			*stage = "maintenance_priority_journal_binding"
			matches := 0
			for _, current := range entries {
				if current.Allocation.ConnectionID == id && current.DeliveryID == d.ID {
					if !reflect.DeepEqual(current, e) {
						// Classify only the first differing mutable duty, without
						// logging either journal value or changing the exact refusal.
						switch {
						case !reflect.DeepEqual(current.BGPProcess, e.BGPProcess):
							*stage = "maintenance_priority_journal_process"
						case !reflect.DeepEqual(current.BGPRoutes, e.BGPRoutes):
							*stage = "maintenance_priority_journal_routes"
						case !reflect.DeepEqual(current.Recovery, e.Recovery):
							*stage = "maintenance_priority_journal_recovery"
						}
						return nil, ErrRuntimeController
					}
					matches++
				}
			}
			*stage = "maintenance_priority_journal_count"
			if matches != 1 {
				return nil, ErrRuntimeController
			}
			*stage = "maintenance_priority_fqdn_current"
			if !c.fqdnGrantsCurrent(a.Grants) {
				return nil, &runtimeFQDNPolicyRetraction{connection: id}
			}
			deliveries[d.ID] = true
			if !due[id] {
				// Recheck after prior journal/policy work: crossing the immutable
				// native runway must not silently omit a newly due owner.
				if c.maintenanceRenewalDue(a) {
					return nil, ErrRuntimeController
				}
				continue
			}
			items = append(items, maintenanceItem{RuntimeDelivery: d, Entry: e, Grants: a.Grants, FQDNLeaseDescriptors: append([]RuntimeFQDNGrant(nil), a.FQDNLeaseDescriptors...), PolicyHash: a.Identity.PolicyHash})
		}
		return items, nil
	}
	if count > 0 && c.exactPageRefreshScope() {
		ns, nsErr := c.namespace()
		entries, journalErr := c.journal.Entries()
		if nsErr == nil && journalErr == nil {
			stage, connection := "maintenance_priority_owner", uuid.Nil
			items, err := prepare(ns, entries, &stage, &connection)
			if err == nil && len(items) == count {
				fresh := map[uuid.UUID]maintenanceItem{}
				for _, item := range items {
					fresh[item.Manifest.ConnectionID] = item
				}
				// Retained priority has no new delivery to acknowledge. Its exact
				// due owners use the same fresh-nonce/full-native transaction.
				return c.commitExactRuntimeRefresh(ctx, authority, bgpCurrent, fresh, publish, true)
			}
		}
		// No candidate/native work has started. Preserve normal pending-policy
		// withdrawal and refusal handling on a failed classification.
	}
	// The returned normal maintenance results are deliberately discarded: retained
	// applied context cannot acknowledge a fresh pending delivery or cleanup.
	_, err := c.maintainIPsecRuntimeItems(ctx, count, prepare, authority, bgpCurrent, publish, publishRecovery, true)
	return err
}
