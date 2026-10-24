package ipsec

import (
	"context"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
)

// A normal page and its first lease may age during shared-owner preproof and
// telemetry. Recollect expiry-only metadata once at the final preassembly
// boundary. Nothing here is published or installed: every replacement is a new
// nonce-bound candidate, with fresh native proof, before guard sequence capture.
func (c *RuntimeController) refreshFQDNAssemblyCandidates(ctx context.Context, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, prior, candidates, staged, required, cutoff map[uuid.UUID]runtimeActive, materials []maintenanceItem) error {
	client, available := c.client.(runtimeCurrentMaterialClient)
	if !available {
		return nil
	}
	var ids []uuid.UUID
	for id, a := range candidates {
		if len(a.FQDNLeaseDescriptors) > 0 && c.fqdnNativeWindowNeedsRefresh(id, prior[id]) {
			ids = append(ids, id)
		}
	}
	if len(ids) < 2 {
		return nil
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	current := func() bool {
		if ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !reflect.DeepEqual(c.active, prior) {
			return false
		}
		for id, a := range candidates {
			if !reflect.DeepEqual(a, staged[id]) || !reflect.DeepEqual(a, required[id]) || !c.fqdnGrantsCurrent(a.Grants) {
				return false
			}
			if a.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent()) {
				return false
			}
		}
		for _, a := range prior {
			if a.Authority == nil {
				return false
			}
			if _, e := a.Authority.RemainingForApply(a.Identity, 5*time.Second); e != nil {
				return false
			}
		}
		return true
	}
	if authority == nil || !current() {
		return ErrRuntimeController
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	started := c.recoveryNow()
	updates := map[uuid.UUID]runtimeActive{}
	items := map[uuid.UUID]maintenanceItem{}
	wait := c.fqdnMaterialWait
	if wait == nil {
		wait = runtimeFQDNWait
	}
	for attempt := 0; attempt < 9; attempt++ {
		for _, id := range ids {
			if _, ready := items[id]; ready {
				continue
			}
			old, a := prior[id], candidates[id]
			m, err := client.IPsecMaterial(fetchCtx, id, old.Delivery.DesiredRevision)
			item, validateErr := c.prepareFQDNFollowupMaterial(fetchCtx, old, m, true)
			for i := range m.Secrets {
				m.Secrets[i] = RuntimeSecret{}
			}
			if err != nil || validateErr != nil || !current() || fetchCtx.Err() != nil || c.recoveryNow() < started || c.recoveryNow()-started >= 2*time.Second {
				return ErrRuntimeController
			}
			if item.PolicyHash != a.Identity.PolicyHash || !reflect.DeepEqual(item.FQDNLeaseDescriptors, a.FQDNLeaseDescriptors) {
				items[id] = item
			}
		}
		if len(items) == len(ids) {
			break
		}
		// Keep the original candidate when normal publication has not changed.
		// Waiting never renews it, and all network work shares this same budget.
		remaining := 2*time.Second - (c.recoveryNow() - started)
		if remaining <= 500*time.Millisecond {
			break
		}
		if err := wait(fetchCtx, 250*time.Millisecond); err != nil {
			return ErrRuntimeController
		}
	}
	for _, id := range ids {
		item, changed := items[id]
		if !changed {
			continue
		}
		old, a := prior[id], candidates[id]
		fresh := authority()
		if fresh == nil {
			return ErrRuntimeController
		}
		identity := old.Identity
		identity.PolicyHash = item.PolicyHash
		policy := retainedFQDNLeasePolicy(item.FQDNLeaseDescriptors)
		request, err := fresh.BeginFQDN(identity, runtimeFQDNLeaseKeys(policy))
		if err != nil {
			return ErrRuntimeController
		}
		lease, err := c.client.RenewIPsecLease(fetchCtx, id, RuntimeLeaseRequest{DeliveryID: item.ID, DesiredRevision: item.DesiredRevision, PolicyHash: item.PolicyHash, Nonce: request.Nonce, FQDNGrants: runtimeFQDNLeaseDescriptors(policy)})
		if err != nil || lease.DeliveryID != item.ID || lease.DesiredRevision != item.DesiredRevision || lease.PolicyHash != item.PolicyHash || lease.Nonce != request.Nonce || fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: lease.TTLMS, FQDNPermits: lease.FQDNPermits}) != nil || fetchCtx.Err() != nil || c.recoveryNow() < started || c.recoveryNow()-started >= 2*time.Second || !current() {
			return ErrRuntimeController
		}
		a.Identity, a.Authority = identity, fresh
		a.Grants = item.Grants
		a.FQDNLeaseDescriptors = item.FQDNLeaseDescriptors
		updates[id], items[id] = a, item
	}
	// Re-prove changed candidates after their nonce; no old observation is
	// promoted across HTTP. The canonical SA/BGP/MTU/desktop proof still follows.
	for _, id := range ids {
		a, changed := updates[id]
		if !changed {
			continue
		}
		proofCtx, proofCancel := context.WithTimeout(ctx, 5*time.Second)
		err := c.proveCurrent(proofCtx, a.Entry, a.Environment)
		if err == nil {
			err = c.proveDesktopGrants(proofCtx, a.Grants)
		}
		if proofCtx.Err() != nil {
			err = ErrRuntimeController
		}
		proofCancel()
		if err != nil || !current() {
			return ErrRuntimeController
		}
		if _, err = a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
			return ErrRuntimeController
		}
	}
	for id, a := range updates {
		candidates[id], staged[id], required[id] = a, a, a
		delete(cutoff, id)
		for i := range materials {
			if materials[i].Manifest.ConnectionID == id {
				materials[i] = items[id]
			}
		}
	}
	return nil
}
