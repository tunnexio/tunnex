package ipsec

import (
	"context"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

// The short-member follow-up is an expiry-only update of an exact live BGP
// owner, not a general Apply. The combined installer already performs the full
// fresh native/environment/peer/RIB/MTU proof AFTER the new CP nonce. Repeating
// that proof in a preliminary collection can consume the old native member.
func (c *RuntimeController) commitFQDNFollowup(ctx context.Context, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, refreshed map[uuid.UUID]maintenanceItem, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) error {
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
	if authority == nil || bgpCurrent == nil || !bgpCurrent() || ctx.Err() != nil || len(refreshed) == 0 || len(refreshed) > 256 {
		return fail()
	}
	if _, gateErr := os.Lstat(filepath.Join(c.config.JournalDir, "restoration-startup-gate")); !os.IsNotExist(gateErr) {
		return fail()
	}
	staged := make(map[uuid.UUID]runtimeActive, len(c.active))
	for id, a := range c.active {
		staged[id] = a
	}
	prior := map[uuid.UUID]runtimeActive{}
	deadlines := map[uuid.UUID]time.Duration{}
	required := map[uuid.UUID]runtimeActive{}
	for id, m := range refreshed {
		old, ok := c.active[id]
		window, known := c.fqdnNativeWindows[id]
		if !ok || !known || old.Authority == nil || old.Entry.ContractVersion != 3 || old.Entry.AbsenceOnly || old.Entry.Phase != RuntimeApplied || old.Entry.BGPProcess == nil || old.Entry.BGPProcess.Stage != "ready" || old.Entry.BGPRoutes == nil || old.Entry.BGPRoutes.Stage != "completed" || !runtimeDeliveryValid(old.Delivery, c.config.OrgID, c.config.GatewayID, "apply") || old.Delivery.CoversDeliveryRevision != 0 || old.Identity != (PermitLeaseIdentity{DeliveryID: old.Delivery.ID, Binding: old.Entry.Engines[0].Binding, PolicyHash: old.Identity.PolicyHash}) || !validDigest(old.Identity.PolicyHash) || !validJournalBGP(old.Entry) || !reflect.DeepEqual(old, window.owner) || window.deadline <= c.recoveryNow() || m.FQDNExpiryPriorHash != old.Identity.PolicyHash || !reflect.DeepEqual(m.RuntimeDelivery, old.Delivery) || !reflect.DeepEqual(m.Entry, old.Entry) || !c.fqdnGrantsCurrent(m.Grants) {
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
		deadlines[id] = window.deadline
	}
	current := func() bool {
		if ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !bgpCurrent() {
			return false
		}
		for id, old := range prior {
			if deadlines[id] <= c.recoveryNow() || !reflect.DeepEqual(c.active[id], old) || !c.fqdnGrantsCurrent(required[id].Grants) {
				return false
			}
		}
		return true
	}
	if !current() || c.installActiveCandidates(ctx, entries, staged, required, prior, current) != nil {
		return fail()
	}
	committedCurrent := func() bool {
		if ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !bgpCurrent() {
			return false
		}
		for id, a := range required {
			if !reflect.DeepEqual(c.active[id], a) || !c.fqdnGrantsCurrent(a.Grants) {
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
	// This path creates no Apply ACK. Publish fresh normal transport observations
	// only after the ordinary atomic commit, with the same post-IO authority fence.
	for _, a := range required {
		if !committedCurrent() {
			return fail()
		}
		if publish != nil {
			d := a.Delivery
			report, transportErr := runtimeFQDNFollowupReport(d)
			if transportErr != nil {
				return fail()
			}
			report, err = c.observeIPsecStatusLocked(ctx, d, report, true, false)
			if err != nil || !committedCurrent() || publish(ctx, d, report) != nil {
				return fail()
			}
		}
		if !committedCurrent() {
			return fail()
		}
	}
	if !committedCurrent() {
		return fail()
	}
	return nil
}

// Preserve the normal transport report envelope for one- and two-tunnel BGP.
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
