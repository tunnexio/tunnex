package ipsec

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

// Only a completed native owner may receive an expiry-only refresh. AWS static
// keeps its durably selected recovery slot; existing BGP providers keep their
// process and RIB qualification. Neither path can complete a pending switch.
func runtimeFQDNFollowupEntrySupported(e RuntimeJournalEntry) bool {
	if e.ContractVersion == 3 {
		return e.BGPProcess != nil && e.BGPProcess.Stage == "ready" && e.BGPRoutes != nil && e.BGPRoutes.Stage == "completed" && validJournalBGP(e)
	}
	return runtimeDesktopEntrySupported(e)
}

// The short-member follow-up is an expiry-only update of an exact live
// owner, not a general Apply. The combined installer already performs the full
// fresh native/environment/peer/RIB/MTU proof AFTER the new CP nonce. Repeating
// that proof in a preliminary collection can consume the old native member.
func (c *RuntimeController) commitFQDNFollowup(ctx context.Context, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, refreshed map[uuid.UUID]maintenanceItem, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) error {
	return c.commitExactRuntimeRefresh(ctx, authority, bgpCurrent, refreshed, publish, false)
}

// Ordinary candidates enter this same native transaction only after exact
// already-applied page/priority validation. The flag never permits a policy,
// transport, delivery, or grant change; a new CP nonce remains mandatory.
func (c *RuntimeController) commitExactRuntimeRefresh(ctx context.Context, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, refreshed map[uuid.UUID]maintenanceItem, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, allowUnchanged bool) error {
	return c.commitExactRuntimeRefreshAttempt(ctx, authority, bgpCurrent, refreshed, publish, allowUnchanged, nil)
}

func (c *RuntimeController) commitExactRuntimeRefreshAttempt(ctx context.Context, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, refreshed map[uuid.UUID]maintenanceItem, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, allowUnchanged bool, reconciledPrior map[uuid.UUID]runtimeActive) error {
	entries, err := c.journal.Entries()
	if err != nil {
		c.deniedClassicTransports = nil
		c.withdrawDNSOwnerView(uuid.Nil)
		c.active = nil
		c.fqdnNativeWindows = nil
		return ErrRuntimeController
	}
	fail := func() error {
		c.deniedClassicTransports = nil
		c.active = nil
		_, _ = c.refuse(ctx, entries)
		return ErrRuntimeController
	}
	// Static-only gateways do not need FRR. If any retained owner uses BGP,
	// preserve its qualification throughout the shared atomic replacement.
	transportCurrent := func() bool {
		for _, owner := range c.active {
			if owner.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent()) {
				return false
			}
		}
		return true
	}
	if authority == nil || !transportCurrent() || ctx.Err() != nil || len(refreshed) == 0 || len(refreshed) > 256 {
		return fail()
	}
	if _, gateErr := os.Lstat(filepath.Join(c.config.JournalDir, "restoration-startup-gate")); !os.IsNotExist(gateErr) {
		return fail()
	}
	original := make(map[uuid.UUID]runtimeActive, len(c.active))
	for id, a := range c.active {
		original[id] = cloneMaintenanceActive(a)
	}
	staged := make(map[uuid.UUID]runtimeActive, len(c.active))
	for id, a := range c.active {
		staged[id] = a
	}
	prior := map[uuid.UUID]runtimeActive{}
	required := map[uuid.UUID]runtimeActive{}
	for id, m := range refreshed {
		old, ok := c.active[id]
		window, known := c.fqdnNativeWindows[id]
		unchanged := allowUnchanged && m.PolicyHash == old.Identity.PolicyHash && reflect.DeepEqual(m.Grants, old.Grants) && reflect.DeepEqual(m.FQDNLeaseDescriptors, old.FQDNLeaseDescriptors) && m.FQDNPolicyPriorHash == "" && !m.FQDNRestorePending
		// Canonical deny-first BGP reconciliation removes the old native
		// scheduling window. Its exact surviving owner can still obtain a NEW
		// nonce-bound permit; neither its old authority nor deadline is extended.
		reconciled, wasReconciled := reconciledPrior[id]
		expiryOwner := (known && reflect.DeepEqual(old, window.owner)) || (wasReconciled && reflect.DeepEqual(old, reconciled))
		expiry := expiryOwner && m.FQDNExpiryPriorHash == old.Identity.PolicyHash
		if !ok || (!unchanged && !expiry) || old.Authority == nil || !runtimeFQDNFollowupEntrySupported(old.Entry) || old.Entry.AbsenceOnly || old.Entry.Phase != RuntimeApplied || !runtimeDeliveryValid(old.Delivery, c.config.OrgID, c.config.GatewayID, "apply") || old.Delivery.CoversDeliveryRevision != 0 || old.Identity != (PermitLeaseIdentity{DeliveryID: old.Delivery.ID, Binding: old.Entry.Engines[0].Binding, PolicyHash: old.Identity.PolicyHash}) || !validDigest(old.Identity.PolicyHash) || !reflect.DeepEqual(m.RuntimeDelivery, old.Delivery) || !reflect.DeepEqual(m.Entry, old.Entry) {
			return fail()
		}
		matches := 0
		for _, e := range entries {
			if e.Allocation.ConnectionID != id {
				continue
			}
			if e.DeliveryID == old.Entry.DeliveryID {
				if !reflect.DeepEqual(e, old.Entry) {
					return fail()
				}
				matches++
			} else if e.Phase != RuntimeRetainedRefusal || e.CleanupDesiredRevision >= m.DesiredRevision {
				return fail()
			}
		}
		if matches != 1 || c.maintenanceCurrentWithNativeProof(ctx, old, bgpCurrent, false) != nil {
			return fail()
		}
		if !c.fqdnGrantsCurrent(m.Grants) {
			// Discovery was validated but its policy view was retracted before
			// lease collection. Only the original finite owners can survive.
			retracted := cloneMaintenanceActive(old)
			retracted.Grants = m.Grants
			staged[id] = retracted
			health := func() bool {
				return ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive != nil && c.config.DaemonAlive() && transportCurrent()
			}
			if c.retractFQDNOnly(ctx, &runtimeFQDNPolicyRetraction{connection: id}, original, staged, health) == nil {
				return nil
			}
			return fail()
		}
		fresh := authority()
		if fresh == nil {
			return fail()
		}
		identity := old.Identity
		identity.PolicyHash = m.PolicyHash
		policy := retainedFQDNLeasePolicy(m.FQDNLeaseDescriptors)
		request, err := fresh.BeginFQDN(identity, runtimeFQDNLeaseKeys(policy))
		if err != nil {
			return fail()
		}
		lease, err := c.client.RenewIPsecLease(ctx, id, RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, PolicyHash: m.PolicyHash, Nonce: request.Nonce, FQDNGrants: runtimeFQDNLeaseDescriptors(policy)})
		if err != nil || lease.DeliveryID != m.ID || lease.DesiredRevision != m.DesiredRevision || lease.PolicyHash != m.PolicyHash || lease.Nonce != request.Nonce || fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: lease.TTLMS, FQDNPermits: lease.FQDNPermits}) != nil {
			return fail()
		}
		if !reflect.DeepEqual(c.active[id], old) || c.maintenanceCurrentWithNativeProof(ctx, old, bgpCurrent, false) != nil {
			return fail()
		}
		if _, err = fresh.RemainingForApply(identity, 5*time.Second); err != nil {
			return fail()
		}
		candidate := old
		candidate.Authority, candidate.Identity = fresh, identity
		candidate.Grants, candidate.FQDNLeaseDescriptors = m.Grants, runtimeFQDNLeaseDescriptors(policy)
		prior[id], required[id], staged[id] = old, candidate, candidate
	}
	// The old native FQDN window schedules this attempt; it does not authorize
	// the replacement. It may expire during fresh discovery or native proof.
	// Only the independently issued new nonce and exact fresh FQDN permits can
	// authorize the new member. Keep ordinary authority and every current owner,
	// transport and native proof fence independent of that scheduling deadline.
	health := func() bool {
		return ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive != nil && c.config.DaemonAlive() && transportCurrent()
	}
	current := func() bool {
		if !health() {
			return false
		}
		for id, old := range prior {
			if !reflect.DeepEqual(c.active[id], old) {
				return false
			}
		}
		return true
	}
	if !current() {
		return fail()
	}
	// The first nonce may already describe an older same-answer publication.
	// Reuse the one bounded preassembly phase after preliminary proof, before
	// any guard sequence is captured. Only uncommitted candidates can change.
	beforeAssembly := func(boundary context.Context) error {
		if c.exactPageRefreshScope() {
			return c.refreshFQDNAssemblyCandidatesWithSiblings(boundary, authority, bgpCurrent, original, required, staged, required, nil, nil, refreshed, prior)
		}
		return c.refreshFQDNAssemblyCandidates(boundary, authority, bgpCurrent, original, required, staged, required, nil, nil)
	}
	if err := c.installActiveCandidatesFQDN(ctx, entries, staged, required, prior, current, nil, nil, beforeAssembly, true); err != nil {
		if reconciledPrior == nil && errors.Is(err, errMaintenanceBGPRouteChanged) && c.exactPageRefreshScope() {
			reconciled, reconcileErr := c.reconcileExactRefreshBGP(ctx, entries, original, refreshed, bgpCurrent)
			if reconcileErr == nil {
				// Refetched candidates start over. The normal bounded late
				// boundary may still add another original owner, but only with
				// its own fresh material, nonce and complete native proof.
				return c.commitExactRuntimeRefreshAttempt(ctx, authority, bgpCurrent, refreshed, publish, allowUnchanged, reconciled)
			}
			return fail()
		}
		var retraction *runtimeFQDNPolicyRetraction
		if errors.As(err, &retraction) && c.retractFQDNOnly(ctx, retraction, original, staged, health) == nil {
			return nil
		}
		return fail()
	}
	committed := make(map[uuid.UUID]runtimeActive, len(c.active))
	for id, a := range c.active {
		committed[id] = cloneMaintenanceActive(a)
	}
	committedCurrent := func() bool {
		if ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !transportCurrent() {
			return false
		}
		for id, a := range required {
			if !reflect.DeepEqual(c.active[id], a) {
				return false
			}
			if _, e := a.Authority.RemainingForApply(a.Identity, time.Millisecond); e != nil {
				return false
			}
			for _, g := range a.Grants {
				if g.FQDN.Version == 2 {
					if _, e := a.Authority.RemainingFQDNForApply(a.Identity, guardFQDNGrantDigest(g), time.Millisecond); e != nil {
						return false
					}
				}
			}
		}
		return true
	}
	checkCommitted := func() (bool, error) {
		if !committedCurrent() {
			return false, ErrRuntimeController
		}
		for id, a := range required {
			if !c.fqdnGrantsCurrent(a.Grants) {
				// These owners already passed atomic adoption. Retain exactly
				// their committed finite ordinary authority, never extend it.
				err := c.retractFQDNOnly(ctx, &runtimeFQDNPolicyRetraction{connection: id, nativeReplaced: true}, committed, committed, func() bool {
					return ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive != nil && c.config.DaemonAlive() && transportCurrent()
				})
				return err == nil, err
			}
		}
		return false, nil
	}
	// This path creates no Apply ACK. Publish fresh normal transport observations
	// only after the ordinary atomic commit, with the same post-IO authority fence.
	for _, a := range required {
		if withdrawn, err := checkCommitted(); err != nil {
			return fail()
		} else if withdrawn {
			return nil
		}
		if publish != nil {
			d := a.Delivery
			report, transportErr := runtimeFQDNFollowupReport(d)
			if transportErr != nil {
				return fail()
			}
			bgp, bgpErr := runtimeBGPContract(d.Manifest)
			recovery, recoveryErr := runtimeRecoveryContract(d.Manifest)
			if bgpErr != nil || recoveryErr != nil {
				return fail()
			}
			report, err = c.observeIPsecStatusLocked(ctx, d, report, bgp, recovery)
			if err != nil {
				return fail()
			}
			if withdrawn, err := checkCommitted(); err != nil {
				return fail()
			} else if withdrawn {
				return nil
			}
			if publish(ctx, d, report) != nil {
				return fail()
			}
		}
		if withdrawn, err := checkCommitted(); err != nil {
			return fail()
		} else if withdrawn {
			return nil
		}
	}
	if withdrawn, err := checkCommitted(); err != nil {
		return fail()
	} else if withdrawn {
		return nil
	}
	return nil
}

// Preserve the normal transport report envelope for supported one- and two-tunnel owners.
func runtimeFQDNFollowupReport(d RuntimeDelivery) (RuntimeStatusReport, error) {
	count, err := runtimeTransportContract(d.Manifest)
	if err != nil {
		return RuntimeStatusReport{}, err
	}
	report := RuntimeStatusReport{DeliveryID: d.ID, DesiredRevision: d.DesiredRevision, ConfigurationRevision: d.Manifest.ConfigurationRevision}
	if count == 1 {
		version, tunnels := 1, 1
		report.TransportVersion = &version
		report.TunnelCount = &tunnels
	}
	for i, t := range d.Manifest.Tunnels[:count] {
		report.Tunnels[i] = RuntimeTunnelStatus{ID: t.ID, Slot: t.Slot, Status: "unknown", Selected: t.Selected}
	}
	return report, nil
}
