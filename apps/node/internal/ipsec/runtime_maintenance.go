package ipsec

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	"github.com/google/uuid"
)

// MaintainIPsecRuntime renews only exact process-local, already applied intent.
// It never performs first Apply, recreates transport or reconciles learned routes.
// Omitted results require ordinary Apply; successful results repair the existing
// delivery acknowledgement even if an earlier CP acknowledgement was lost.
func (c *RuntimeController) MaintainIPsecRuntime(ctx context.Context, materials []RuntimeMaterial) ([]RuntimeMaintenanceResult, error) {
	return c.MaintainIPsecRuntimeObserved(ctx, materials, nil)
}

// MaintainIPsecRuntimeObserved publishes each fresh post-commit native status
// without waiting for other owners' status IO. This callback carries telemetry
// only; the complete result set still gates every Apply acknowledgement.
// The callback runs under the runtime owner lock and must not reenter it.
func (c *RuntimeController) MaintainIPsecRuntimeObserved(ctx context.Context, materials []RuntimeMaterial, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) ([]RuntimeMaintenanceResult, error) {
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
	return c.maintainIPsecRuntimeObserved(ctx, materials, NewPermitLeaseAuthority, c.bgpQualificationCurrent, publish)
}

// The private core runs after the same platform/BGP qualification as Apply.
// The constructor is supplied only by the public boundary (or virtual-clock
// tests), and Begin starts its deadline BEFORE the normal CP request.
func (c *RuntimeController) maintainIPsecRuntime(ctx context.Context, materials []RuntimeMaterial, authority func() *PermitLeaseAuthority, bgpCurrent func() bool) ([]RuntimeMaintenanceResult, error) {
	return c.maintainIPsecRuntimeObserved(ctx, materials, authority, bgpCurrent, nil)
}

type maintenanceItem struct {
	RuntimeDelivery
	Entry      RuntimeJournalEntry
	Grants     []GuardGrant
	PolicyHash string
}

func (c *RuntimeController) maintainIPsecRuntimeObserved(ctx context.Context, materials []RuntimeMaterial, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) ([]RuntimeMaintenanceResult, error) {
	prepare := func(ns string, _ []RuntimeJournalEntry, stage *string, connection *uuid.UUID) ([]maintenanceItem, error) {
		var err error
		// Validate every secret-bearing normal material and its unique page identity
		// before requesting any lease. No PSK is retained in a candidate or result.
		input := make([]RuntimeJournalEntry, len(materials))
		grants := make([][]GuardGrant, len(materials))
		connections, deliveries := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
		*stage = "maintenance_material"
		for i, m := range materials {
			*connection = m.Manifest.ConnectionID
			input[i], grants[i], err = runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, ns)
			id := m.Manifest.ConnectionID
			if err != nil || connections[id] || deliveries[m.ID] {
				return nil, ErrRuntimeController
			}
			connections[id], deliveries[m.ID] = true, true
		}
		// Match ordinary Apply: revoke changed published DNS inputs before any
		// blocking environment/native/lease IO can leave an old query permission open.
		for i, m := range materials {
			*connection = m.Manifest.ConnectionID
			*stage = "maintenance_material_withdraw"
			c.withdrawChangedDNSMaterial(m, grants[i])
			if err := c.withdrawChangedFQDNMaterial(ctx, m, grants[i]); err != nil {
				return nil, ErrRuntimeController
			}
			*stage = "maintenance_material_current"
			if !c.fqdnGrantsCurrent(grants[i]) {
				return nil, ErrRuntimeController
			}
		}
		items := make([]maintenanceItem, len(materials))
		for i, m := range materials {
			items[i] = maintenanceItem{RuntimeDelivery: m.RuntimeDelivery, Entry: input[i], Grants: grants[i], PolicyHash: m.Policy.Hash}
		}
		return items, nil
	}
	return c.maintainIPsecRuntimeItems(ctx, len(materials), prepare, authority, bgpCurrent, publish)
}

func (c *RuntimeController) maintainIPsecRuntimeItems(ctx context.Context, count int, prepare func(string, []RuntimeJournalEntry, *string, *uuid.UUID) ([]maintenanceItem, error), authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) (resultOut []RuntimeMaintenanceResult, resultErr error) {
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
	materials, prepareErr := prepare(ns, entries, &stage, &connection)
	if prepareErr != nil || len(materials) != count {
		return fail()
	}
	if len(materials) == 0 {
		return nil, nil
	}
	staged := make(map[uuid.UUID]runtimeActive, len(c.active))
	for id, a := range c.active {
		staged[id] = a
	}
	candidates := map[uuid.UUID]runtimeActive{}
	maintained := make([]RuntimeDelivery, 0, len(materials))
	changed := false
	type eligibleOwner struct {
		index  int
		active runtimeActive
	}
	eligibleOwners := make([]eligibleOwner, 0, len(materials))
	// Complete all eligibility proof IO before beginning any fresh finite lease.
	for i, m := range materials {
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
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_grants", func() bool { return reflect.DeepEqual(old.Grants, m.Grants) }) &&
					maintenanceEligibilityTerm(&eligibilityStage, "eligibility_identity", func() bool { return old.Identity == identity }) &&
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
					eligible = c.maintenanceCurrent(ctx, old, bgpCurrent) == nil
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
		eligibleOwners = append(eligibleOwners, eligibleOwner{index: i, active: old})
	}
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
		request, beginErr := fresh.Begin(old.Identity)
		if beginErr != nil {
			return fail()
		}
		stage = "maintenance_lease"
		lease, leaseErr := c.client.RenewIPsecLease(ctx, id, RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, PolicyHash: m.PolicyHash, Nonce: request.Nonce})
		if leaseErr != nil {
			stage = maintenanceLeaseFailureStage(leaseErr)
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
		if fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: lease.TTLMS}) != nil {
			return fail()
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
		stage = "maintenance_fresh_authority"
		if _, err = fresh.RemainingForApply(old.Identity, 5*time.Second); err != nil {
			return fail()
		}
		candidate := old
		candidate.Authority = fresh
		staged[id], candidates[id] = candidate, candidate
		maintained = append(maintained, m.RuntimeDelivery)
	}
	if len(candidates) == 0 && !changed {
		return nil, nil
	}
	// Original authorities remain untouched and externally visible until the
	// exact combined guard transaction and final native/lease checks succeed.
	stage, connection = "maintenance_bgp_freshness", uuid.Nil
	for _, a := range candidates {
		if a.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent()) {
			return failHAFreshness()
		}
	}
	haFreshnessFailed := false
	stage, connection = "maintenance_combined_guard", uuid.Nil
	if c.installActiveCandidates(ctx, entries, staged, candidates, c.active, func() bool {
		if ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
			return false
		}
		for _, a := range candidates {
			if a.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent()) {
				haFreshnessFailed = true
				return false
			}
		}
		return true
	}) != nil {
		if haFreshnessFailed && ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive() {
			return failHAFreshness()
		}
		return fail()
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
		stage = "maintenance_status"
		report, err = c.observeIPsecStatusLocked(ctx, m, report, bgp, recovery)
		if err != nil || bgpErr != nil || recoveryErr != nil || (bgp && (bgpCurrent == nil || !bgpCurrent())) || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
			return fail()
		}
		stage = "maintenance_candidate_authority"
		if _, err = candidate.Authority.RemainingForApply(candidate.Identity, time.Millisecond); err != nil {
			return fail()
		}
		if publish != nil {
			stage = "maintenance_publish"
			if publish(ctx, m, report) != nil {
				return fail()
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
		result = append(result, RuntimeMaintenanceResult{Acknowledgement: RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}, Report: report})
	}

	// A later owner's status IO can consume an earlier candidate's remaining
	// deadline. Validate the complete result set once more before any external ACK.
	for _, m := range maintained {
		connection, stage = m.Manifest.ConnectionID, "maintenance_final_binding"
		candidate := candidates[m.Manifest.ConnectionID]
		current, ok := c.active[m.Manifest.ConnectionID]
		if !ok || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || (candidate.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent())) {
			return fail()
		}
		stage = "maintenance_candidate_authority"
		if _, err = candidate.Authority.RemainingForApply(candidate.Identity, time.Millisecond); err != nil {
			return fail()
		}
	}
	return result, nil
}

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
		for _, state := range health {
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
		stage = "maintenance_current_bgp_binding"
		if !p.Alive() || !bgpCurrent() || !reflect.DeepEqual(target, e.BGPRoutes.Owned) {
			return ErrRuntimeController
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
