package ipsec

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// A DNS failure/revocation or restoration can change the policy hash without
// changing any ordinary application or transport intent. This witness permits
// collecting NEW authority only; it never transfers the old policy's lease.
// Restrict it to removal of all desktop static-CNAME grants, or restoration
// from none, on a qualified AWS desktop owner. BGP sources must already be
// exported; static sources still require fresh peer and no-SNAT proof.
// Changed nonempty generations continue through the existing expiry-only/ordinary Apply paths.
func (c *RuntimeController) fqdnPolicyTransitionEligible(old runtimeActive, m maintenanceItem) bool {
	if !runtimeDesktopEntrySupported(old.Entry) || !validDigest(m.PolicyHash) || m.PolicyHash == old.Identity.PolicyHash || (len(old.FQDNLeaseDescriptors) == 0) == (len(m.FQDNLeaseDescriptors) == 0) {
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
		if old.Entry.Allocation.BGP && !known {
			return false
		} // no new BGP export is adopted by maintenance
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
	if entry.ContractVersion == 2 {
		entry.Recovery = old.Entry.Recovery
	}
	if !reflect.DeepEqual(entry, old.Entry) {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	c.publishDesktopNAT(old.Entry.Allocation.ConnectionID, grants)
	grants, err = c.observeDesktopGrants(ctx, grants)
	pending := errors.Is(err, errDesktopNATPending)
	if (err != nil && !pending) || ctx.Err() != nil {
		return maintenanceItem{}, old, ErrRuntimeController
	}
	item := maintenanceItem{RuntimeDelivery: m.RuntimeDelivery, Entry: entry, Grants: grants, FQDNLeaseDescriptors: runtimeFQDNLeaseDescriptors(m.Policy), PolicyHash: m.Policy.Hash, FQDNPolicyPriorHash: old.Identity.PolicyHash, FQDNRestorePending: pending}
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
	if pending {
		// A completed ordinary-only owner may wait for its new exemption. The
		// caller still proves its exact old native authority; no new lease or ACK.
		if !c.fqdnRestorationPendingEligible(old, item) {
			return maintenanceItem{}, old, ErrRuntimeController
		}
		return item, old, nil
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
	started := time.Now()
	fail := func(id uuid.UUID, stage string) error {
		c.emitRuntimeDiagnostic(ctx, "maintenance_pending_fqdn", stage, id, started, true)
		return ErrRuntimeController
	}
	var ids []uuid.UUID
	for id, a := range c.active {
		if c.fqdnGrantsCurrent(a.Grants) {
			continue
		}
		// runtimeDesktopEntrySupported also refuses profiled owners; name the
		// profile leaf first so each refusal keeps its own diagnostic stage.
		if a.Entry.Allocation.ProfileID != "" {
			return fail(id, "pending_owner_profile")
		}
		if !runtimeDesktopEntrySupported(a.Entry) {
			return fail(id, "pending_owner_contract")
		}
		if c.config.FQDNPolicy == nil {
			return fail(id, "pending_policy_source")
		}
		view := c.config.FQDNPolicy.view.Load()
		if view == nil {
			return fail(id, "pending_policy_view")
		}
		if view.policy.NodeID != c.config.GatewayID.String() {
			return fail(id, "pending_policy_binding")
		}
		for _, g := range a.Grants {
			if g.FQDNManaged && (g.FQDN.Version != 2 || g.FQDN.ResolverKind != "static_cname" || g.DesktopDeviceID == uuid.Nil) {
				return fail(id, "pending_grant_binding")
			}
		}
		ids = append(ids, id)
	}
	err := c.withdrawFQDNActiveLocked(ctx, ids)
	if err != nil {
		// This rebuild covers all pending owners. These IDs identify the affected
		// owners, not the source of a shared native failure; inner diagnostics
		// retain that failure's existing stage and binding.
		for _, id := range ids {
			c.emitRuntimeDiagnostic(ctx, "maintenance_pending_fqdn", "pending_guard_rebuild", id, started, true)
		}
	}
	return err
}

// This marker comes only from complete desktop observation with a recognized
// missing exact exemption. Retain no old marked tuple and adopt no new source.
func (c *RuntimeController) fqdnRestorationPendingEligible(old runtimeActive, m maintenanceItem) bool {
	return m.FQDNRestorePending && len(old.FQDNLeaseDescriptors) == 0 && len(m.FQDNLeaseDescriptors) > 0 && c.fqdnPolicyTransitionEligible(old, m)
}

// Only the canonical installer emits this at an explicitly qualified policy
// boundary, before adopting candidates. nativeReplaced records native phase.
// It is not a generic required-binding or native-proof error.
type runtimeFQDNPolicyRetraction struct {
	connection     uuid.UUID
	nativeReplaced bool
}

func (*runtimeFQDNPolicyRetraction) Error() string {
	return "FQDN policy retracted before maintenance commit"
}

func (c *RuntimeController) retractFQDNOnly(ctx context.Context, signal *runtimeFQDNPolicyRetraction, original, staged map[uuid.UUID]runtimeActive, current func() bool) error {
	if signal == nil || signal.connection == uuid.Nil || current == nil || !current() || c.config.FQDNPolicy == nil || len(original) != len(c.active) || len(original) != len(staged) {
		return ErrRuntimeController
	}
	view := c.config.FQDNPolicy.view.Load()
	if view == nil || view.policy.NodeID != c.config.GatewayID.String() || view.policy.Version < 9 {
		return ErrRuntimeController
	}
	expected := make(map[uuid.UUID]runtimeActive, len(original))
	var ids []uuid.UUID
	signaled := false
	for id, old := range original {
		live, ok := c.active[id]
		candidate, stagedOK := staged[id]
		if !ok || !stagedOK || old.Authority == nil || !reflect.DeepEqual(live, old) {
			return ErrRuntimeController
		}
		if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
			return ErrRuntimeController
		}
		if candidate.Authority == nil {
			return ErrRuntimeController
		}
		if _, err := candidate.Authority.RemainingForApply(candidate.Identity, time.Millisecond); err != nil {
			return ErrRuntimeController
		}
		if candidate.Authority != old.Authority {
			for _, g := range candidate.Grants {
				if g.FQDN.Version == 2 {
					if _, err := candidate.Authority.RemainingFQDNForApply(candidate.Identity, guardFQDNGrantDigest(g), time.Millisecond); err != nil {
						return ErrRuntimeController
					}
				}
			}
		}
		// Fresh candidate authority is discarded, never transferred. Every original
		// ordinary tuple and immutable owner binding must still be the same.
		identity := candidate.Identity
		identity.PolicyHash = old.Identity.PolicyHash
		ordinary := func(gs []GuardGrant) []GuardGrant {
			out := make([]GuardGrant, 0, len(gs))
			for _, g := range gs {
				if !g.FQDNManaged {
					out = append(out, g)
				}
			}
			return out
		}
		if identity != old.Identity || !reflect.DeepEqual(candidate.Entry, old.Entry) || !reflect.DeepEqual(candidate.Environment, old.Environment) || !reflect.DeepEqual(candidate.Delivery, old.Delivery) || !reflect.DeepEqual(ordinary(candidate.Grants), ordinary(old.Grants)) {
			return ErrRuntimeController
		}
		stale := !c.fqdnGrantsCurrent(candidate.Grants) || !c.fqdnGrantsCurrent(old.Grants)
		kept := cloneMaintenanceActive(old)
		if stale {
			if !runtimeDesktopEntrySupported(old.Entry) {
				return ErrRuntimeController
			}
			for _, grants := range [][]GuardGrant{old.Grants, candidate.Grants} {
				for _, g := range grants {
					if g.FQDNManaged && (g.FQDN.Version != 2 || g.FQDN.ResolverKind != "static_cname" || g.DesktopDeviceID == uuid.Nil) {
						return ErrRuntimeController
					}
				}
			}
			kept.Grants = make([]GuardGrant, 0, len(old.Grants))
			for _, g := range old.Grants {
				if !g.FQDNManaged || view.matches(g) {
					kept.Grants = append(kept.Grants, g)
				}
			}
			ids = append(ids, id)
			signaled = signaled || id == signal.connection
		}
		expected[id] = kept
	}
	if !signaled || !current() || c.config.FQDNPolicy.view.Load() != view {
		return ErrRuntimeController
	}
	// Existing scoped withdrawal performs a complete new native assembly under
	// original finite authority, without exposing any candidate lease or ACK.
	if err := c.withdrawFQDNActiveLockedMode(ctx, ids, false); err != nil {
		return err
	}
	if !current() || c.config.FQDNPolicy.view.Load() != view || !reflect.DeepEqual(c.active, expected) {
		return ErrRuntimeController
	}
	for _, old := range original {
		if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
			return ErrRuntimeController
		}
	}
	return nil
}

// Preparation may have already pruned exactly the withdrawn marked tuples.
// That is the only allowed difference from the pre-IO owner snapshot. It does
// not adopt any input-page field or lease and produces no Apply result.
func (c *RuntimeController) retractFQDNPreparation(ctx context.Context, signal *runtimeFQDNPolicyRetraction, before map[uuid.UUID]runtimeActive, current func() bool) error {
	if c.config.FQDNPolicy == nil || len(before) != len(c.active) {
		return ErrRuntimeController
	}
	view := c.config.FQDNPolicy.view.Load()
	if view == nil {
		return ErrRuntimeController
	}
	original := map[uuid.UUID]runtimeActive{}
	for id, old := range before {
		live, ok := c.active[id]
		if !ok {
			return ErrRuntimeController
		}
		pruned := cloneMaintenanceActive(old)
		pruned.Grants = make([]GuardGrant, 0, len(old.Grants))
		for _, g := range old.Grants {
			if !g.FQDNManaged || view.matches(g) {
				pruned.Grants = append(pruned.Grants, g)
			}
		}
		if !reflect.DeepEqual(live, old) && !reflect.DeepEqual(live, pruned) {
			return ErrRuntimeController
		}
		original[id] = cloneMaintenanceActive(live)
	}
	return c.retractFQDNOnly(ctx, signal, original, before, current)
}
