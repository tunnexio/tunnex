package ipsec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	"github.com/google/uuid"
)

// MaintainIPsecRuntime renews only exact process-local, already applied intent.
// It never performs first Apply, recreates transport or reconciles learned routes.
// Omitted results require ordinary Apply; explicit deferred results wait for
// another normal discovery pass without an ACK. Successful results repair the existing
// delivery acknowledgement even if an earlier CP acknowledgement was lost.
func (c *RuntimeController) MaintainIPsecRuntime(ctx context.Context, materials []RuntimeMaterial) ([]RuntimeMaintenanceResult, error) {
	return c.MaintainIPsecRuntimeObserved(ctx, materials, nil)
}

// MaintainIPsecRuntimeObserved publishes each fresh post-commit native status
// without waiting for other owners' status IO. This callback carries telemetry
// only; the complete result set still gates every Apply acknowledgement.
// The callback runs under the runtime owner lock and must not reenter it.
func (c *RuntimeController) MaintainIPsecRuntimeObserved(ctx context.Context, materials []RuntimeMaterial, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) ([]RuntimeMaintenanceResult, error) {
	return c.MaintainIPsecRuntimeRecoveryObserved(ctx, materials, publish, nil)
}

func (c *RuntimeController) MaintainIPsecRuntimeRecoveryObserved(ctx context.Context, materials []RuntimeMaterial, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error) ([]RuntimeMaintenanceResult, error) {
	if c == nil {
		return nil, ErrRuntimeController
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !supportedRuntimePlatform(runtime.GOOS, runtime.GOARCH) {
		c.deniedClassicTransports = nil
		return nil, ErrRuntimeController
	}
	for _, m := range materials {
		if m.Manifest.BGP != nil && !c.bgpQualificationCurrent() {
			c.deniedClassicTransports = nil
			return nil, ErrRuntimeController
		}
	}
	return c.maintainIPsecRuntimeRecoveryObserved(ctx, materials, NewPermitLeaseAuthority, c.bgpQualificationCurrent, publish, publishRecovery)
}

// The private core runs after the same platform/BGP qualification as Apply.
// The constructor is supplied only by the public boundary (or virtual-clock
// tests), and Begin starts its deadline BEFORE the normal CP request.
func (c *RuntimeController) maintainIPsecRuntime(ctx context.Context, materials []RuntimeMaterial, authority func() *PermitLeaseAuthority, bgpCurrent func() bool) ([]RuntimeMaintenanceResult, error) {
	return c.maintainIPsecRuntimeObserved(ctx, materials, authority, bgpCurrent, nil)
}

type maintenanceItem struct {
	RuntimeDelivery
	Entry                RuntimeJournalEntry
	Grants               []GuardGrant
	FQDNLeaseDescriptors []RuntimeFQDNGrant
	PolicyHash           string
	FQDNExpiryPriorHash  string
	FQDNPolicyPriorHash  string
	FQDNRestorePending   bool
}

func (c *RuntimeController) maintainIPsecRuntimeObserved(ctx context.Context, materials []RuntimeMaterial, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) ([]RuntimeMaintenanceResult, error) {
	return c.maintainIPsecRuntimeRecoveryObserved(ctx, materials, authority, bgpCurrent, publish, nil)
}

func (c *RuntimeController) maintainIPsecRuntimeRecoveryObserved(ctx context.Context, materials []RuntimeMaterial, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error) ([]RuntimeMaintenanceResult, error) {
	prepare := func(ns string, _ []RuntimeJournalEntry, stage *string, connection *uuid.UUID) ([]maintenanceItem, error) {
		var err error
		// Validate every secret-bearing normal material and its unique page identity
		// before requesting any lease. No PSK is retained in a candidate or result.
		input := make([]RuntimeJournalEntry, len(materials))
		grants := make([][]GuardGrant, len(materials))
		expiryPriorHashes := make([]string, len(materials))
		pendingNAT := make([]bool, len(materials))
		connections, deliveries := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
		*stage = "maintenance_material"
		for i, m := range materials {
			*connection = m.Manifest.ConnectionID
			*stage = "maintenance_material"
			input[i], grants[i], err = runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, ns)
			id := m.Manifest.ConnectionID
			if err != nil || connections[id] || deliveries[m.ID] {
				return nil, ErrRuntimeController
			}
			c.publishDesktopNAT(id, grants[i])
			*stage = "maintenance_desktop_observe"
			grants[i], err = c.observeDesktopGrants(ctx, grants[i])
			pendingNAT[i] = errors.Is(err, errDesktopNATPending)
			if err != nil && !pendingNAT[i] {
				return nil, ErrRuntimeController
			}
			if old, ok := c.active[id]; ok && old.Identity.PolicyHash != m.Policy.Hash && len(old.FQDNLeaseDescriptors) > 0 {
				if rollover, e := c.prepareFQDNExpiryMaterial(ctx, old, m); e == nil {
					expiryPriorHashes[i] = rollover.FQDNExpiryPriorHash
					grants[i] = rollover.Grants
				}
			}
			connections[id], deliveries[m.ID] = true, true
		}
		// Match ordinary Apply: revoke changed published DNS inputs before any
		// blocking environment/native/lease IO can leave an old query permission open.
		for i, m := range materials {
			*connection = m.Manifest.ConnectionID
			*stage = "maintenance_material_withdraw"
			c.withdrawChangedDNSMaterial(m, grants[i])
			if expiryPriorHashes[i] == "" {
				if err := c.withdrawChangedFQDNMaterial(ctx, m, grants[i]); err != nil {
					return nil, ErrRuntimeController
				}
			}
			*stage = "maintenance_material_current"
			if !c.fqdnGrantsCurrent(grants[i]) {
				return nil, &runtimeFQDNPolicyRetraction{connection: m.Manifest.ConnectionID}
			}
		}
		items := make([]maintenanceItem, len(materials))
		for i, m := range materials {
			items[i] = maintenanceItem{RuntimeDelivery: m.RuntimeDelivery, Entry: input[i], Grants: grants[i], FQDNLeaseDescriptors: runtimeFQDNLeaseDescriptors(m.Policy), PolicyHash: m.Policy.Hash, FQDNExpiryPriorHash: expiryPriorHashes[i], FQDNRestorePending: pendingNAT[i]}
		}
		return items, nil
	}
	// The RIB may converge after priority renewal but before this material page.
	// Reuse the same single reconciliation attempt; its retry remains fail closed.
	return c.maintainIPsecRuntimeItems(ctx, len(materials), prepare, authority, bgpCurrent, publish, publishRecovery, true)
}

func (c *RuntimeController) maintainIPsecRuntimeItems(ctx context.Context, count int, prepare func(string, []RuntimeJournalEntry, *string, *uuid.UUID) ([]maintenanceItem, error), authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error, reconcileRetainedBGP bool) ([]RuntimeMaintenanceResult, error) {
	return c.maintainIPsecRuntimeItemsAttempt(ctx, count, prepare, authority, bgpCurrent, publish, publishRecovery, reconcileRetainedBGP, true)
}

func (c *RuntimeController) maintainIPsecRuntimeItemsAttempt(ctx context.Context, count int, prepare func(string, []RuntimeJournalEntry, *string, *uuid.UUID) ([]maintenanceItem, error), authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error, reconcileRetainedBGP, allowFQDNCutoffRefresh bool) (resultOut []RuntimeMaintenanceResult, resultErr error) {
	started := time.Now()
	stage, connection := "maintenance_input", uuid.Nil
	defer func() { c.emitRuntimeDiagnostic(ctx, "maintenance", stage, connection, started, resultErr != nil) }()
	if !c.started || c.closed || ctx.Err() != nil || authority == nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !c.qualification.current() || count < 0 || count > 256 || prepare == nil {
		c.deniedClassicTransports = nil
		return nil, ErrRuntimeController
	}
	stage = "maintenance_journal"
	entries, err := c.journal.Entries()
	if err != nil {
		c.deniedClassicTransports = nil
		c.withdrawDNSOwnerView(uuid.Nil)
		c.active = nil
		return nil, ErrRuntimeController
	}
	fail := func() ([]RuntimeMaintenanceResult, error) {
		c.deniedClassicTransports = nil
		c.withdrawDNSOwnerView(uuid.Nil)
		c.active = nil
		_, _ = c.refuse(ctx, entries)
		return nil, ErrRuntimeController
	}
	nativeCommitted := false
	changed := false
	pulseFailure := func(err error) ([]RuntimeMaintenanceResult, error) {
		var conflict *runtimeRecoveryConflictWithdrawn
		if changed && errors.As(err, &conflict) {
			// Earlier ineligible owners may still await their native denial.
			// Target conflict isolation cannot abandon that pending duty.
			return fail()
		}
		var withdrawn *runtimeRecoveryOwnerWithdrawn
		if !nativeCommitted && ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive() && errors.As(err, &withdrawn) && withdrawn.connectionID != uuid.Nil {
			if _, present := c.active[withdrawn.connectionID]; !present {
				// Abort this collection: no staged/candidate owner or ACK can escape.
				// The independently verified target is already denied; unrelated
				// original finite native authority remains untouched for the next
				// ordinary renewal/Apply pass. No authority is cached or revived.
				return nil, err
			}
		}
		return fail()
	}
	failHAFreshness := func() ([]RuntimeMaintenanceResult, error) {
		hints := c.rememberDeniedClassicTransports(entries)
		c.withdrawDNSOwnerView(uuid.Nil)
		c.active = nil
		c.deniedClassicTransports = nil
		if _, err := c.refuse(ctx, entries); err == nil && ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive != nil && c.config.DaemonAlive() {
			c.deniedClassicTransports = hints
		}
		return nil, ErrRuntimeController
	}
	stage = "maintenance_startup_gate"
	if _, gateErr := os.Lstat(filepath.Join(c.config.JournalDir, "restoration-startup-gate")); !os.IsNotExist(gateErr) {
		return fail()
	}
	stage = "maintenance_namespace"
	ns, err := c.namespace()
	if err != nil {
		return fail()
	}
	stage = "maintenance_pending_fqdn_withdraw"
	if err := c.withdrawPendingFQDNPolicyLocked(ctx); err != nil {
		return fail()
	}
	preparedOwners := map[uuid.UUID]runtimeActive{}
	for id, a := range c.active {
		preparedOwners[id] = cloneMaintenanceActive(a)
	}
	stage, connection = "maintenance_prepare", uuid.Nil
	materials, prepareErr := prepare(ns, entries, &stage, &connection)
	if prepareErr != nil || len(materials) != count {
		if prepareErr == nil {
			stage, connection = "maintenance_prepare_count", uuid.Nil
		}
		var retraction *runtimeFQDNPolicyRetraction
		if errors.As(prepareErr, &retraction) {
			current := func() bool {
				return ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive() && bgpCurrent != nil && bgpCurrent()
			}
			if c.retractFQDNPreparation(ctx, retraction, preparedOwners, current) == nil {
				return nil, nil
			}
		}
		return fail()
	}
	if len(materials) == 0 {
		return nil, nil
	}
	// Only exact unchanged page deliveries can participate in active telemetry.
	pulseAllowed := map[uuid.UUID]bool{}
	for _, m := range materials {
		a, ok := c.active[m.Manifest.ConnectionID]
		pulseAllowed[m.Manifest.ConnectionID] = ok && reflect.DeepEqual(a.Delivery, m.RuntimeDelivery) && a.Identity.PolicyHash == m.PolicyHash && reflect.DeepEqual(a.Grants, m.Grants)
	}
	staged := make(map[uuid.UUID]runtimeActive, len(c.active))
	for id, a := range c.active {
		staged[id] = a
	}
	candidates := map[uuid.UUID]runtimeActive{}
	pending := map[uuid.UUID]runtimeActive{}
	maintained := make([]RuntimeDelivery, 0, len(materials))
	type eligibleOwner struct {
		index  int
		active runtimeActive
	}
	eligibleOwners := make([]eligibleOwner, 0, len(materials))
	// Complete all eligibility proof IO before beginning any fresh finite lease.
	for i, m := range materials {
		c.refreshMaintenanceRecovery(ctx)
		if pulseErr := c.refreshMaintenanceActiveRecoveryQualified(ctx, pulseAllowed, publishRecovery, bgpCurrent); pulseErr != nil {
			return pulseFailure(pulseErr)
		}
		id := m.Manifest.ConnectionID
		connection, stage = id, "maintenance_eligibility"
		eligibilityStarted := time.Now()
		old, ok := c.active[id]
		eligible := false
		eligibilityStage := "eligibility_active"
		if ok {
			// The complete journal is trusted; exact delivery must appear once and no
			// unresolved competing lineage may be hidden by the current active map.
			var current *RuntimeJournalEntry
			lineage := true
			for n := range entries {
				e := &entries[n]
				if e.Allocation.ConnectionID != id {
					continue
				}
				if e.DeliveryID == m.ID {
					if current != nil {
						return fail()
					}
					current = e
				} else if e.Phase != RuntimeRetainedRefusal || e.CleanupDesiredRevision >= m.DesiredRevision {
					lineage = false
				}
			}
			eligibilityStage = "eligibility_current"
			if current != nil {
				eligibilityStage = "eligibility_lineage"
			}
			if current != nil && lineage {
				env, observeErr := c.config.Environment.Observe(ctx, m.Entry.Allocation, m.Entry.Engines)
				c.refreshMaintenanceRecovery(ctx)
				if pulseErr := c.refreshMaintenanceActiveRecoveryQualified(ctx, pulseAllowed, publishRecovery, bgpCurrent); pulseErr != nil {
					return pulseFailure(pulseErr)
				}
				same := m.Entry
				for n := range same.Engines[:same.Allocation.activeTunnelCount()] {
					same.Engines[n].LocalAddress = env.Underlays[n].LocalAddress
				}
				same.Restoration, same.Allocation.Generation = current.Restoration, current.Allocation.Generation
				for n := range same.Allocation.Tunnels[:same.Allocation.activeTunnelCount()] {
					same.Allocation.Tunnels[n].Alias = current.Allocation.Tunnels[n].Alias
				}
				same.Phase, same.Observed = current.Phase, current.Observed
				if same.ContractVersion == 3 {
					same.BGPRoutes, same.BGPProcess, same.BGPProcessRetired, same.BGPProcessHistory = current.BGPRoutes, current.BGPProcess, current.BGPProcessRetired, current.BGPProcessHistory
				}
				if same.ContractVersion == 2 {
					same.Recovery = current.Recovery
				}
				identity := PermitLeaseIdentity{DeliveryID: m.ID, Binding: same.Engines[0].Binding, PolicyHash: m.PolicyHash}
				expiryRollover := m.FQDNExpiryPriorHash != "" && m.FQDNExpiryPriorHash == old.Identity.PolicyHash
				policyTransition := c.fqdnPolicyTransitionEligible(old, m)
				if m.FQDNRestorePending && !c.fqdnRestorationPendingEligible(old, m) {
					return fail()
				}
				priorIdentity := identity
				priorIdentity.PolicyHash = old.Identity.PolicyHash
				eligible = maintenanceEligibilityTerm(&eligibilityStage, "eligibility_observe", func() bool { return observeErr == nil }) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_namespace", func() bool { return env.Namespace == ns }) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_phase", func() bool { return same.Phase == RuntimeApplied }) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_contract", func() bool {
						return (same.ContractVersion == 2 || same.ContractVersion == 3 || (same.ContractVersion == 4 && same.Allocation.ProfileID == GCPClassicStaticProfile && validClassicJournal(same)))
					}) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_entry_current", func() bool { return reflect.DeepEqual(same, *current) }) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_active_entry", func() bool { return reflect.DeepEqual(old.Entry, same) }) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_delivery", func() bool { return reflect.DeepEqual(old.Delivery, m.RuntimeDelivery) }) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_environment", func() bool { return reflect.DeepEqual(old.Environment, env) }) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_grants", func() bool { return reflect.DeepEqual(old.Grants, m.Grants) || expiryRollover || policyTransition }) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_identity", func() bool {
						return old.Identity == identity || ((expiryRollover || policyTransition) && old.Identity == priorIdentity)
					}) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_authority", func() bool { return old.Authority != nil })
				if eligible {
					if same.ContractVersion == 2 {
						eligibilityStage = "eligibility_recovery"
						prepared, known := c.recoveryPrepared[m.ID]
						eligible = known && reflect.DeepEqual(prepared, env) && validJournalRecovery(same) && same.Recovery.Stage == "completed"
					}
					if same.ContractVersion == 3 {
						eligibilityStage = "eligibility_bgp"
						eligible = validJournalBGP(same) && same.BGPProcess != nil && same.BGPProcess.Stage == "ready" && same.BGPRoutes != nil && same.BGPRoutes.Stage == "completed"
					}
				}
				if eligible {
					stage = "maintenance_eligibility_proof"
					eligibilityStage = "eligibility_proof"
					proofErr := c.maintenanceCurrent(ctx, old, bgpCurrent)
					routeChanged := errors.Is(proofErr, errMaintenanceBGPRouteChanged)
					if routeChanged {
						decision := "route_change_ineligible"
						if reconcileRetainedBGP {
							decision = "route_change_reconcile_once"
						}
						c.emitRuntimeDiagnostic(ctx, "maintenance_bgp_route_change", decision, id, eligibilityStarted, !reconcileRetainedBGP)
					}
					if reconcileRetainedBGP && routeChanged {
						// Both renewal paths can observe a newly converged RIB. Let
						// that healthy change converge under its original finite lease
						// instead of withdrawing its owner and stopping desktop exports.
						stage = "maintenance_retained_bgp_reconcile"
						c.refreshMaintenanceRecovery(ctx)
						if pulseErr := c.refreshMaintenanceActiveRecoveryQualified(ctx, pulseAllowed, publishRecovery, bgpCurrent); pulseErr != nil {
							return pulseFailure(pulseErr)
						}
						if ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || bgpCurrent == nil || !bgpCurrent() {
							return fail()
						}
						// A permission-preserving selected-path switch need not replay
						// already completed eligibility IO for every other owner. Capture
						// only after the preceding publication callback has returned.
						beforeSwitch := map[uuid.UUID]runtimeActive{}
						for ownerID, a := range c.active {
							beforeSwitch[ownerID] = cloneMaintenanceActive(a)
						}
						beforeTemplates, _, templateErr := c.journal.guardTemplates()
						canContinue := templateErr == nil && !changed && reflect.DeepEqual(staged, beforeSwitch) && reflect.DeepEqual(old, beforeSwitch[id])
						reconcileCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
						reconcileErr := c.reconcileActiveBGP(reconcileCtx, entries)
						if reconcileErr == nil && (reconcileCtx.Err() != nil || !bgpCurrent()) {
							reconcileErr = ErrRuntimeController
						}
						cancel()
						if reconcileErr != nil {
							return fail()
						}
						latest, continued := c.bgpRouteSwitchMaintenanceCurrent(id, beforeSwitch, entries, beforeTemplates)
						if canContinue && continued {
							// No authority/native member changed. The reconciler supplied
							// the complete fresh native/desktop/RIB/SA proof for this owner;
							// collection and its canonical post-CP proofs still run below.
							entries, old = latest, c.active[id]
							staged[id] = old
							m.Entry, materials[i].Entry = old.Entry, old.Entry
							reconcileRetainedBGP, proofErr = false, nil
						} else {
							// Deny-first or another owner change requires the original full
							// rebuild. A second route change never reconciles recursively.
							return c.maintainIPsecRuntimeItemsAttempt(ctx, count, prepare, authority, bgpCurrent, publish, publishRecovery, false, allowFQDNCutoffRefresh)
						}
					}
					eligible = proofErr == nil
					c.refreshMaintenanceRecovery(ctx)
					if pulseErr := c.refreshMaintenanceActiveRecoveryQualified(ctx, pulseAllowed, publishRecovery, bgpCurrent); pulseErr != nil {
						return pulseFailure(pulseErr)
					}
				}
			}
		}
		c.emitRuntimeDiagnostic(ctx, "maintenance_eligibility", eligibilityStage, id, eligibilityStarted, !eligible)
		if !eligible {
			if ok {
				delete(staged, id)
				c.withdrawDNSOwnerView(id)
				changed = true
			}
			continue
		}
		if m.FQDNRestorePending {
			// Exact eligibility and native old-owner proof succeeded. Leave its
			// original deadline untouched and return no applied acknowledgement.
			if !c.fqdnRestorationPendingEligible(old, m) {
				return fail()
			}
			c.emitRuntimeDiagnostic(ctx, "maintenance", "maintenance_desktop_nat_pending", id, eligibilityStarted, true)
			pending[id] = old
			continue
		}
		if c.fqdnPolicyTransitionEligible(old, m) {
			m.FQDNPolicyPriorHash = old.Identity.PolicyHash
			materials[i] = m
		}
		eligibleOwners = append(eligibleOwners, eligibleOwner{index: i, active: old})
	}
	retryPublish, retryPublishRecovery := publish, publishRecovery
	deferral := c.beginMaintenancePulseDeferral(pulseAllowed, publishRecovery)
	if publishRecovery != nil {
		publishOriginal := publishRecovery
		publishRecovery = func(ctx context.Context, report RuntimeRecoveryHeartbeat) error {
			if !deferral.reportsCurrent(c) {
				return ErrRuntimeController
			}
			if err := publishOriginal(ctx, report); err != nil {
				return err
			}
			if !deferral.reportsCurrent(c) {
				return ErrRuntimeController
			}
			return nil
		}
	}
	if publish != nil {
		publishOriginal := publish
		publish = func(ctx context.Context, delivery RuntimeDelivery, report RuntimeStatusReport) error {
			if !deferral.reportsCurrent(c) {
				return ErrRuntimeController
			}
			if err := publishOriginal(ctx, delivery, report); err != nil {
				return err
			}
			if !deferral.reportsCurrent(c) {
				return ErrRuntimeController
			}
			return nil
		}
	}
	collectionPulse := func() error {
		if deferral.deferPulse(ctx, c) {
			return nil
		}
		return c.refreshMaintenanceActiveRecoveryQualified(ctx, pulseAllowed, publishRecovery, bgpCurrent)
	}
	refreshedFQDN := map[uuid.UUID]bool{}
	for _, owner := range eligibleOwners {
		m, old := materials[owner.index], owner.active
		id := m.Manifest.ConnectionID
		connection = id
		stage = "maintenance_authority"
		current, ok := c.active[id]
		if !ok || !reflect.DeepEqual(current, old) {
			return fail()
		}
		fresh := authority()
		if fresh == nil {
			return fail()
		}
		current, ok = c.active[id]
		if !ok || !reflect.DeepEqual(current, old) {
			return fail()
		}
		if _, err = old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
			delete(staged, id)
			c.withdrawDNSOwnerView(id)
			changed = true
			continue
		}
		if ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || (old.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent())) {
			return fail()
		}
		identity := old.Identity
		if m.FQDNExpiryPriorHash != "" || m.FQDNPolicyPriorHash != "" {
			if (m.FQDNExpiryPriorHash != "" && m.FQDNExpiryPriorHash != old.Identity.PolicyHash) || (m.FQDNPolicyPriorHash != "" && (m.FQDNPolicyPriorHash != old.Identity.PolicyHash || !c.fqdnPolicyTransitionEligible(old, m))) {
				return fail()
			}
			identity.PolicyHash = m.PolicyHash
		}
		if identity.PolicyHash != m.PolicyHash {
			return fail()
		}
		fqdnPolicy := retainedFQDNLeasePolicy(m.FQDNLeaseDescriptors)
		request, beginErr := fresh.BeginFQDN(identity, runtimeFQDNLeaseKeys(fqdnPolicy))
		if beginErr != nil {
			return fail()
		}
		stage = "maintenance_lease"
		lease, leaseErr := c.client.RenewIPsecLease(ctx, id, RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, PolicyHash: m.PolicyHash, Nonce: request.Nonce, FQDNGrants: runtimeFQDNLeaseDescriptors(fqdnPolicy)})
		// A normal page can race the same DNS publication as a priority pass.
		// Reuse exact expiry-only renewal or scoped removal/restoration once.
		// A conflict alone never authorizes content or extends the original lease.
		if leaseErr != nil && allowFQDNCutoffRefresh && (len(old.FQDNLeaseDescriptors) > 0 || (old.Entry.ContractVersion == 3 && len(c.bgpDesktopExports[old.Entry.DeliveryID]) > 0)) && maintenanceLeaseFailureStage(leaseErr) == "maintenance_lease_http_409_conflict" {
			stage = "maintenance_fqdn_expiry_material"
			updated, updatedOld, updateErr := c.refreshFQDNMaintenanceMaterial(ctx, old)
			if updateErr != nil {
				return fail()
			}
			if updated.FQDNRestorePending {
				if !reflect.DeepEqual(old, updatedOld) || !c.fqdnRestorationPendingEligible(old, updated) || c.maintenanceCurrent(ctx, old, bgpCurrent) != nil || !reflect.DeepEqual(c.active[id], old) || !c.fqdnRestorationPendingEligible(old, updated) {
					return fail()
				}
				c.emitRuntimeDiagnostic(ctx, "maintenance", "maintenance_desktop_nat_pending", id, started, true)
				pending[id] = old
				continue
			}
			refreshedFQDN[id] = true
			old = updatedOld
			staged[id] = old
			m = updated
			identity.PolicyHash = m.PolicyHash
			fqdnPolicy = retainedFQDNLeasePolicy(m.FQDNLeaseDescriptors)
			fresh = authority()
			if fresh == nil {
				return fail()
			}
			request, beginErr = fresh.BeginFQDN(identity, runtimeFQDNLeaseKeys(fqdnPolicy))
			if beginErr != nil {
				return fail()
			}
			stage = "maintenance_fqdn_expiry_lease"
			lease, leaseErr = c.client.RenewIPsecLease(ctx, id, RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, PolicyHash: m.PolicyHash, Nonce: request.Nonce, FQDNGrants: runtimeFQDNLeaseDescriptors(fqdnPolicy)})
		}
		if leaseErr != nil {
			stage = maintenanceLeaseFailureStage(leaseErr)
			if stage == "maintenance_lease_http_409_conflict" && !changed && !nativeCommitted && c.withdrawMaintenanceConflict(ctx, old, entries, bgpCurrent) == nil {
				return nil, &runtimeMaintenanceBatchAborted{}
			}
			return fail()
		}
		stage = "maintenance_lease_delivery"
		if lease.DeliveryID != m.ID {
			return fail()
		}
		stage = "maintenance_lease_revision"
		if lease.DesiredRevision != m.DesiredRevision {
			return fail()
		}
		stage = "maintenance_lease_policy"
		if lease.PolicyHash != m.PolicyHash {
			return fail()
		}
		stage = "maintenance_lease_nonce"
		if lease.Nonce != request.Nonce {
			return fail()
		}
		stage = "maintenance_lease_ttl"
		if fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: lease.TTLMS, FQDNPermits: lease.FQDNPermits}) != nil {
			return fail()
		}
		c.refreshMaintenanceRecovery(ctx)
		if pulseErr := collectionPulse(); pulseErr != nil {
			return pulseFailure(pulseErr)
		}
		stage = "maintenance_lease_active"
		current, ok = c.active[id]
		if !ok || !reflect.DeepEqual(current, old) {
			return fail()
		}
		// The old authority must still bridge this collection; a response arriving
		// after it expires cannot recreate a missing permit from cached transport.
		stage = "maintenance_bridge_proof"
		bridgeStarted := time.Now()
		// The combined installer supplies the fresh post-CP native/BGP proof.
		// This check still requires the original authority and complete guard.
		if c.maintenanceCurrentWithNativeProof(ctx, old, bgpCurrent, false) != nil {
			c.emitRuntimeDiagnostic(ctx, "maintenance", stage, id, bridgeStarted, true)
			delete(staged, id)
			c.withdrawDNSOwnerView(id)
			changed = true
			continue
		}
		c.refreshMaintenanceRecovery(ctx)
		if pulseErr := collectionPulse(); pulseErr != nil {
			return pulseFailure(pulseErr)
		}
		current, ok = c.active[id]
		if !ok || !reflect.DeepEqual(current, old) {
			return fail()
		}
		stage = "maintenance_fresh_authority"
		if _, err = fresh.RemainingForApply(identity, 5*time.Second); err != nil {
			return fail()
		}
		candidate := old
		candidate.Authority = fresh
		candidate.Identity = identity
		candidate.Grants = m.Grants
		candidate.FQDNLeaseDescriptors = runtimeFQDNLeaseDescriptors(fqdnPolicy)
		materials[owner.index] = m
		staged[id], candidates[id] = candidate, candidate
		maintained = append(maintained, m.RuntimeDelivery)
	}
	deferral.finishCollection(staged)
	pendingCurrent := func() bool {
		for id, old := range pending {
			if ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || bgpCurrent == nil || !bgpCurrent() || !reflect.DeepEqual(c.active[id], old) || !c.fqdnGrantsCurrent(old.Grants) {
				return false
			}
			if _, e := old.Authority.RemainingForApply(old.Identity, 5*time.Second); e != nil {
				return false
			}
		}
		return true
	}
	if !pendingCurrent() {
		return fail()
	}
	deferredResults := func() []RuntimeMaintenanceResult {
		out := make([]RuntimeMaintenanceResult, 0, len(pending))
		for _, old := range pending {
			delivery := cloneMaintenanceActive(old).Delivery
			out = append(out, RuntimeMaintenanceResult{Deferred: &delivery})
		}
		return out
	}
	if len(candidates) == 0 && !changed {
		return deferredResults(), nil
	}
	// Retained pending owners are required, but are not newly authorized
	// candidates or ACK results. Another owner's commit cannot omit them.
	required := make(map[uuid.UUID]runtimeActive, len(candidates)+len(pending))
	for id, a := range candidates {
		required[id] = a
	}
	for id, a := range pending {
		required[id] = a
	}

	// Original authorities remain untouched and externally visible until the
	// exact combined guard transaction and final native/lease checks succeed.
	stage, connection = "maintenance_bgp_freshness", uuid.Nil
	for _, a := range candidates {
		if a.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent()) {
			return failHAFreshness()
		}
	}
	// A candidate already refreshed after a 409 has consumed its one normal
	// material retry. The same bound applies to a cutoff recollection.
	cutoffCandidates := map[uuid.UUID]runtimeActive{}
	if allowFQDNCutoffRefresh {
		for id, candidate := range candidates {
			if !refreshedFQDN[id] {
				cutoffCandidates[id] = candidate
			}
		}
	}
	haFreshnessFailed := false
	stage, connection = "maintenance_combined_guard", uuid.Nil
	originalOwners := make(map[uuid.UUID]runtimeActive, len(c.active))
	for id, a := range c.active {
		originalOwners[id] = cloneMaintenanceActive(a)
	}
	var assemblyPulseErr error
	installErr := c.installActiveCandidatesFQDN(ctx, entries, staged, required, c.active, func() bool {
		if ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || !deferral.reportsCurrent(c) || !pendingCurrent() {
			return false
		}
		for _, a := range candidates {
			if a.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent()) {
				haFreshnessFailed = true
				return false
			}
		}
		return true
	}, cutoffCandidates, func(ctx context.Context) error {
		if len(candidates) == 0 {
			return nil
		}
		assemblyPulseErr = deferral.pulseBeforeAssembly(ctx, c, publishRecovery)
		return assemblyPulseErr
	})
	if installErr != nil {
		if assemblyPulseErr != nil {
			return pulseFailure(assemblyPulseErr)
		}
		var retraction *runtimeFQDNPolicyRetraction
		if !changed && !nativeCommitted && errors.As(installErr, &retraction) {
			stage = "maintenance_fqdn_retraction"
			if retraction.nativeReplaced {
				stage = "maintenance_fqdn_retraction_after_replace"
			}
			current := func() bool {
				return ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive() && deferral.reportsCurrent(c) && pendingCurrent() && bgpCurrent != nil && bgpCurrent()
			}
			if c.retractFQDNOnly(ctx, retraction, originalOwners, staged, current) == nil {
				// All fresh candidates are discarded. The ordinary caller may
				// retry its page, but receives no positive acknowledgement here.
				return nil, nil
			}
			return fail()
		}
		var cutoff *runtimeFQDNPrecommitCutoff
		if allowFQDNCutoffRefresh && errors.As(installErr, &cutoff) {
			stage = "maintenance_fqdn_cutoff_refresh"
			// No candidate has been installed or published. Discard every staged
			// lease and recollect once under the original finite authority.
			retryMaterials, retryErr := c.prepareFQDNCutoffRetry(ctx, materials, cutoff)
			if retryErr != nil || !deferral.reportsCurrent(c) {
				return fail()
			}
			retryPrepare := func(retryNS string, _ []RuntimeJournalEntry, _ *string, _ *uuid.UUID) ([]maintenanceItem, error) {
				if retryNS != ns {
					return nil, ErrRuntimeController
				}
				for _, m := range retryMaterials {
					if !c.fqdnGrantsCurrent(m.Grants) {
						return nil, ErrRuntimeController
					}
				}
				return retryMaterials, nil
			}
			return c.maintainIPsecRuntimeItemsAttempt(ctx, count, retryPrepare, authority, bgpCurrent, retryPublish, retryPublishRecovery, reconcileRetainedBGP, false)
		}
		if haFreshnessFailed && ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive() {
			return failHAFreshness()
		}
		return fail()
	}
	nativeCommitted = true
	c.refreshMaintenanceRecovery(ctx)
	if pulseErr := c.refreshMaintenanceActiveRecoveryQualified(ctx, pulseAllowed, publishRecovery, bgpCurrent); pulseErr != nil {
		return pulseFailure(pulseErr)
	}
	result := make([]RuntimeMaintenanceResult, 0, len(maintained))
	for _, m := range maintained {
		id := m.Manifest.ConnectionID
		connection, stage = id, "maintenance_candidate"
		candidate := candidates[id]
		current, ok := c.active[id]
		if !ok || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) {
			return fail()
		}
		stage = "maintenance_report_contract"
		bgp, bgpErr := runtimeBGPContract(m.Manifest)
		recovery, recoveryErr := runtimeRecoveryContract(m.Manifest)
		count, transportErr := runtimeTransportContract(m.Manifest)
		if transportErr != nil {
			return fail()
		}
		report := RuntimeStatusReport{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, ConfigurationRevision: m.Manifest.ConfigurationRevision}
		if count == 1 {
			version, tunnels := 1, 1
			report.TransportVersion = &version
			report.TunnelCount = &tunnels
		}
		for i, t := range m.Manifest.Tunnels[:count] {
			report.Tunnels[i] = RuntimeTunnelStatus{ID: t.ID, Slot: t.Slot, Status: "unknown", Selected: t.Selected}
		}
		c.refreshMaintenanceRecovery(ctx)
		if pulseErr := c.refreshMaintenanceActiveRecoveryQualified(ctx, pulseAllowed, publishRecovery, bgpCurrent); pulseErr != nil {
			return pulseFailure(pulseErr)
		}
		stage = "maintenance_status"
		report, err = c.observeIPsecStatusLocked(ctx, m, report, bgp, recovery)
		if err != nil || bgpErr != nil || recoveryErr != nil || (bgp && (bgpCurrent == nil || !bgpCurrent())) || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
			return fail()
		}
		c.refreshMaintenanceRecovery(ctx)
		stage = "maintenance_candidate_authority"
		if _, err = candidate.Authority.RemainingForApply(candidate.Identity, time.Millisecond); err != nil {
			return fail()
		}
		if publish != nil {
			stage = "maintenance_publish"
			if publish(ctx, m, report) != nil {
				return fail()
			}
			c.refreshMaintenanceRecovery(ctx)
			if pulseErr := c.refreshMaintenanceActiveRecoveryQualified(ctx, pulseAllowed, publishRecovery, bgpCurrent); pulseErr != nil {
				return pulseFailure(pulseErr)
			}
			// External report IO cannot turn a now-expired or replaced candidate
			// into an applied result. The full-set check below remains required.
			stage = "maintenance_publish_binding"
			current, ok = c.active[id]
			if !ok || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || (candidate.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent())) {
				return fail()
			}
			stage = "maintenance_candidate_authority"
			if _, err = candidate.Authority.RemainingForApply(candidate.Identity, time.Millisecond); err != nil {
				return fail()
			}
		}
		// Maintenance skips ordinary Apply for this exact completed delivery.
		// Reuse its bounded standby retry without preempting the selected path;
		// only fresh known-Up/Down evidence and the committed finite lease can
		// initiate the spare. The full-set check below still gates every ACK.
		if candidate.Entry.ContractVersion == 2 || candidate.Entry.ContractVersion == 3 {
			retryCtx, retryCancel := context.WithTimeout(ctx, 5*time.Second)
			if candidate.Entry.ContractVersion == 3 {
				c.retryMissingBGPChild(retryCtx, candidate.Entry)
			} else {
				c.retryDownStandby(retryCtx, candidate.Entry, candidate.Authority, candidate.Identity)
			}
			retryCancel()
		}
		result = append(result, RuntimeMaintenanceResult{Acknowledgement: RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}, Report: report})
	}

	// A later owner's status IO can consume an earlier candidate's remaining
	// deadline. Validate the complete result set once more before any external ACK.
	for _, m := range maintained {
		connection, stage = m.Manifest.ConnectionID, "maintenance_final_binding"
		candidate := candidates[m.Manifest.ConnectionID]
		current, ok := c.active[m.Manifest.ConnectionID]
		if !ok || !deferral.reportsCurrent(c) || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || (candidate.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent())) {
			return fail()
		}
		c.refreshMaintenanceRecovery(ctx)
		stage = "maintenance_candidate_authority"
		if _, err = candidate.Authority.RemainingForApply(candidate.Identity, time.Millisecond); err != nil {
			return fail()
		}
	}
	// The last inactive observation can consume report freshness too. No ACK
	// escapes after that final blocking sample without the same actual clock proof.
	if !deferral.reportsCurrent(c) || !pendingCurrent() {
		return fail()
	}
	return append(result, deferredResults()...), nil
}

var errMaintenanceBGPRouteChanged = errors.New("IPsec maintenance BGP routes changed")

// maintenanceCurrent is read-only: both original permit and scoped actual
// native guard remain required. Fresh learned duties must equal the completed
// BGP-owned tuples, otherwise ordinary Apply/reconciliation is required.
func (c *RuntimeController) maintenanceCurrent(ctx context.Context, old runtimeActive, bgpCurrent func() bool) error {
	return c.maintenanceCurrentWithNativeProof(ctx, old, bgpCurrent, true)
}

func (c *RuntimeController) maintenanceCurrentWithNativeProof(ctx context.Context, old runtimeActive, bgpCurrent func() bool, proveNative bool) (resultErr error) {
	started := time.Now()
	stage := "maintenance_current_authority_before"
	defer func() {
		c.emitRuntimeDiagnostic(ctx, "maintenance_current", stage, old.Entry.Allocation.ConnectionID, started, resultErr != nil)
	}()
	if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
		return ErrRuntimeController
	}
	proofCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if proveNative {
		stage = "maintenance_current_native"
		if c.proveCurrent(proofCtx, old.Entry, old.Environment) != nil {
			return ErrRuntimeController
		}
	}
	stage = "maintenance_current_guard"
	if c.maintenanceGuard(proofCtx, old.Entry) != nil {
		return ErrRuntimeController
	}
	stage = "maintenance_current_bgp_qualification"
	if proveNative && old.Entry.ContractVersion == 3 {
		if bgpCurrent == nil || !bgpCurrent() {
			return ErrRuntimeController
		}
		e := old.Entry
		stage = "maintenance_current_bgp_process"
		p := c.bgpProcesses[e.DeliveryID]
		if p == nil || !p.Alive() {
			return ErrRuntimeController
		}
		stage = "maintenance_current_bgp_status"
		status, err := p.Observe(proofCtx)
		if err != nil {
			return ErrRuntimeController
		}
		stage = "maintenance_current_bgp_routes"
		routes, err := p.ObserveRoutes(proofCtx, status)
		if err != nil {
			return ErrRuntimeController
		}
		stage = "maintenance_current_bgp_health"
		health := c.observeRecovery(proofCtx, e)
		for _, state := range health[:e.Allocation.activeTunnelCount()] {
			if state != "up" && state != "down" {
				return ErrRuntimeController
			}
		}
		target := []RuntimeBGPRouteTuple{}
		for _, r := range routes {
			if r.Slot >= 1 && r.Slot <= 2 && health[r.Slot-1] == "up" {
				target = append(target, RuntimeBGPRouteTuple{Prefix: r.Prefix, Slot: uint8(r.Slot), InterfaceIndex: e.Observed[r.Slot-1].InterfaceIndex, Table: 254, Protocol: 242, Metric: 50000 + uint32(r.Slot)})
			}
		}
		stage = "maintenance_current_bgp_process_after"
		if !p.Alive() {
			return ErrRuntimeController
		}
		stage = "maintenance_current_bgp_qualification_after"
		if !bgpCurrent() {
			return ErrRuntimeController
		}
		stage = "maintenance_current_bgp_route_changed"
		if !reflect.DeepEqual(target, e.BGPRoutes.Owned) {
			return errMaintenanceBGPRouteChanged
		}
	}
	stage = "maintenance_current_final_qualification"
	if proofCtx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
		return ErrRuntimeController
	}
	stage = "maintenance_current_authority_after"
	_, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second)
	return err
}

func (c *RuntimeController) maintenanceGuard(ctx context.Context, e RuntimeJournalEntry) error {
	if e.ContractVersion == 2 {
		return c.recoveryGuardPermitCheck(ctx, e)
	}
	if c.guard == nil || c.guard.reader == nil {
		return ErrGuardRead
	}
	templates, _, err := c.journal.guardTemplates()
	if err != nil || len(templates) != 1 || templates[0].Namespace != e.Allocation.Namespace {
		return ErrGuardRead
	}
	g := templates[0]
	return c.guard.reader.checkConnection(ctx, GuardManifest{Namespace: g.Namespace, ExpectedJSON: g.ExpectedJSON}, e.Allocation.ConnectionID)
}

// maintenanceEligibilityTerm records only the next predicate already being evaluated.
// Its caller retains the original short-circuit order; no predicate is repeated.
func maintenanceEligibilityTerm(stage *string, label string, predicate func() bool) bool {
	*stage = label
	return predicate()
}
