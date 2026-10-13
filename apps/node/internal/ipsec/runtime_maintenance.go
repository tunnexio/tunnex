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
	return c.MaintainIPsecRuntimeRecoveryObserved(ctx, materials, publish, nil)
}

// The separate callback reports active static evidence only. It cannot satisfy
// a maintained result or acknowledge Apply; the original callback stays once/owner.
func (c *RuntimeController) MaintainIPsecRuntimeRecoveryObserved(ctx context.Context, materials []RuntimeMaterial, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error) ([]RuntimeMaintenanceResult, error) {
	if c == nil {
		return nil, ErrRuntimeController
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !supportedRuntimePlatform(runtime.GOOS, runtime.GOARCH) {
		return nil, ErrRuntimeController
	}
	for _, m := range materials {
		if m.Manifest.BGP != nil && !c.bgpQualificationCurrent() {
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

func (c *RuntimeController) maintainIPsecRuntimeObserved(ctx context.Context, materials []RuntimeMaterial, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) ([]RuntimeMaintenanceResult, error) {
	return c.maintainIPsecRuntimeRecoveryObserved(ctx, materials, authority, bgpCurrent, publish, nil)
}

// maintenanceItem contains only already validated public ownership and policy data.
// Neither the normal material path nor priority renewal retains a secret here.
type maintenanceItem struct {
	RuntimeDelivery
	Entry      RuntimeJournalEntry
	Grants     []GuardGrant
	PolicyHash string
}

func (c *RuntimeController) maintainIPsecRuntimeRecoveryObserved(ctx context.Context, materials []RuntimeMaterial, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error) ([]RuntimeMaintenanceResult, error) {
	prepare := func(ns string, _ []RuntimeJournalEntry) ([]maintenanceItem, error) {
		var err error
		// Validate every secret-bearing normal material and its unique page identity
		// before requesting any lease. No PSK is retained in a candidate or result.
		input := make([]RuntimeJournalEntry, len(materials))
		grants := make([][]GuardGrant, len(materials))
		connections, deliveries := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
		for i, m := range materials {
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
			c.withdrawChangedDNSMaterial(m, grants[i])
			if err := c.withdrawChangedFQDNMaterial(ctx, m, grants[i]); err != nil {
				return nil, ErrRuntimeController
			}
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
	return c.maintainIPsecRuntimeItems(ctx, len(materials), prepare, authority, bgpCurrent, publish, publishRecovery)
}

func (c *RuntimeController) maintainIPsecRuntimeItems(ctx context.Context, count int, prepare func(string, []RuntimeJournalEntry) ([]maintenanceItem, error), authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error) (reportsResult []RuntimeMaintenanceResult, resultErr error) {

	stage, connection := "input", uuid.Nil
	started := time.Now()
	defer func() {
		if resultErr != nil {
			c.emitRuntimeDiagnostic(ctx, "maintenance", stage, connection, started, true)
		}
	}()
	if !c.started || c.closed || ctx.Err() != nil || authority == nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !c.qualification.current() || count > 256 {
		return nil, ErrRuntimeController
	}
	entries, err := c.journal.Entries()
	if err != nil {
		c.withdrawDNSOwnerView(uuid.Nil)
		c.active = nil
		return nil, ErrRuntimeController
	}
	fail := func() ([]RuntimeMaintenanceResult, error) {
		c.withdrawDNSOwnerView(uuid.Nil)
		c.active = nil
		_, _ = c.refuse(ctx, entries)
		return nil, ErrRuntimeController
	}
	nativeCommitted := false
	pulseFailure := func(err error) ([]RuntimeMaintenanceResult, error) {
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
	if _, gateErr := os.Lstat(filepath.Join(c.config.JournalDir, "restoration-startup-gate")); !os.IsNotExist(gateErr) {
		return fail()
	}
	ns, err := c.namespace()
	if err != nil {
		return fail()
	}
	items, err := prepare(ns, entries)
	if err != nil || len(items) != count {
		return fail()
	}
	if count == 0 {
		return nil, nil
	}
	// Only exact unchanged page deliveries can participate in active telemetry.
	pulseAllowed := map[uuid.UUID]bool{}
	for _, m := range items {
		a, ok := c.active[m.Manifest.ConnectionID]
		pulseAllowed[m.Manifest.ConnectionID] = ok && reflect.DeepEqual(a.Delivery, m.RuntimeDelivery) && a.Identity.PolicyHash == m.PolicyHash && reflect.DeepEqual(a.Grants, m.Grants)
	}
	staged := make(map[uuid.UUID]runtimeActive, len(c.active))
	for id, a := range c.active {
		staged[id] = a
	}
	candidates := map[uuid.UUID]runtimeActive{}
	maintained := make([]RuntimeDelivery, 0, count)
	changed := false
	type eligibleOwner struct {
		index  int
		active runtimeActive
	}
	eligibleOwners := make([]eligibleOwner, 0, count)
	// Finish all unchanged-owner eligibility IO before starting a candidate's
	// finite lease. The original native permits must bridge both phases.
	for i, m := range items {
		connection = m.Manifest.ConnectionID
		stage = "maintenance_active_pulse"
		c.refreshMaintenanceRecovery(ctx)
		stage = "maintenance_active_pulse"
		if pulseErr := c.refreshMaintenanceActiveRecovery(ctx, pulseAllowed, publishRecovery); pulseErr != nil {
			return pulseFailure(pulseErr)
		}
		id := m.Manifest.ConnectionID
		old, ok := c.active[id]
		eligible := false
		if ok {
			// The complete journal is trusted; exact delivery must appear once and no
			// unresolved competing lineage may be hidden by the current active map.
			stage = "maintenance_journal_lineage"
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
			if current != nil && lineage {
				env, observeErr := c.config.Environment.Observe(ctx, m.Entry.Allocation, m.Entry.Engines)
				c.refreshMaintenanceRecovery(ctx)
				stage = "maintenance_active_pulse"
				if pulseErr := c.refreshMaintenanceActiveRecovery(ctx, pulseAllowed, publishRecovery); pulseErr != nil {
					return pulseFailure(pulseErr)
				}
				same := m.Entry
				for n := range same.Engines {
					same.Engines[n].LocalAddress = env.Underlays[n].LocalAddress
				}
				same.Restoration, same.Allocation.Generation = current.Restoration, current.Allocation.Generation
				for n := range same.Allocation.Tunnels {
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
				stage = "maintenance_exact_owner"
				eligible = observeErr == nil && env.Namespace == ns && same.Phase == RuntimeApplied && (same.ContractVersion == 2 || same.ContractVersion == 3) && reflect.DeepEqual(same, *current) && reflect.DeepEqual(old.Entry, same) && reflect.DeepEqual(old.Delivery, m.RuntimeDelivery) && reflect.DeepEqual(old.Environment, env) && reflect.DeepEqual(old.Grants, m.Grants) && old.Identity == identity && old.Authority != nil
				if eligible {
					if same.ContractVersion == 2 {
						stage = "maintenance_static_ready"
						prepared, known := c.recoveryPrepared[m.ID]
						eligible = known && reflect.DeepEqual(prepared, env) && validJournalRecovery(same) && same.Recovery.Stage == "completed"
					}
					if same.ContractVersion == 3 {
						stage = "maintenance_bgp_ready"
						eligible = validJournalBGP(same) && same.BGPProcess != nil && same.BGPProcess.Stage == "ready" && same.BGPRoutes != nil && same.BGPRoutes.Stage == "completed"
					}
				}
				if eligible {
					stage = "maintenance_current_before_fresh"
					eligible = c.maintenanceCurrent(ctx, old, bgpCurrent) == nil
					c.refreshMaintenanceRecovery(ctx)
					stage = "maintenance_active_pulse"
					if pulseErr := c.refreshMaintenanceActiveRecovery(ctx, pulseAllowed, publishRecovery); pulseErr != nil {
						return pulseFailure(pulseErr)
					}
					stage = "maintenance_current_before_fresh"
				}
			}
		}
		if !eligible {
			if ok {
				c.emitRuntimeDiagnostic(ctx, "maintenance", stage, id, started, true)
				delete(staged, id)
				c.withdrawDNSOwnerView(id)
				changed = true
			}
			continue
		}
		eligibleOwners = append(eligibleOwners, eligibleOwner{index: i, active: old})
	}
	for _, owner := range eligibleOwners {
		m, old := items[owner.index], owner.active
		id := m.Manifest.ConnectionID
		connection = id
		stage = "maintenance_captured_owner"
		current, ok := c.active[id]
		if !ok || !reflect.DeepEqual(current, old) {
			return fail()
		}
		stage = "maintenance_authority_factory"
		fresh := authority()
		if fresh == nil {
			return fail()
		}
		stage = "maintenance_captured_owner"
		current, ok = c.active[id]
		if !ok || !reflect.DeepEqual(current, old) {
			return fail()
		}
		stage = "maintenance_prior_reserve"
		if _, err = old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
			c.emitRuntimeDiagnostic(ctx, "maintenance", stage, id, started, true)
			delete(staged, id)
			c.withdrawDNSOwnerView(id)
			changed = true
			continue
		}
		stage = "maintenance_qualification"
		if ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || (old.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent())) {
			return fail()
		}
		stage = "maintenance_begin"
		request, beginErr := fresh.Begin(old.Identity)
		if beginErr != nil {
			return fail()
		}
		stage = "maintenance_fresh_lease"
		lease, leaseErr := c.client.RenewIPsecLease(ctx, id, RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, PolicyHash: m.PolicyHash, Nonce: request.Nonce})
		if leaseErr != nil {
			return fail()
		}
		stage = "maintenance_lease_binding"
		if lease.DeliveryID != m.ID || lease.DesiredRevision != m.DesiredRevision || lease.PolicyHash != m.PolicyHash || lease.Nonce != request.Nonce {
			return fail()
		}
		stage = "maintenance_lease_accept"
		if fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: lease.TTLMS}) != nil {
			return fail()
		}
		c.refreshMaintenanceRecovery(ctx)
		stage = "maintenance_active_pulse"
		if pulseErr := c.refreshMaintenanceActiveRecovery(ctx, pulseAllowed, publishRecovery); pulseErr != nil {
			return pulseFailure(pulseErr)
		}
		stage = "maintenance_captured_owner"
		current, ok = c.active[id]
		if !ok || !reflect.DeepEqual(current, old) {
			return fail()
		}
		// The old authority must still bridge this collection; a response arriving
		// after it expires cannot recreate a missing permit from cached transport.
		stage = "maintenance_current_after_fresh"
		// The mandatory combined install below freshly proves every candidate's
		// native ownership after CP renewal and before publishing authority.
		// Keep the original bridge and guard here. The required-candidate
		// installer proves BGP routes with its same fresh guard health sample.
		if c.maintenanceCurrentWithNativeProof(ctx, old, bgpCurrent, false) != nil {
			c.emitRuntimeDiagnostic(ctx, "maintenance", stage, id, started, true)
			delete(staged, id)
			c.withdrawDNSOwnerView(id)
			changed = true
			continue
		}
		c.refreshMaintenanceRecovery(ctx)
		stage = "maintenance_active_pulse"
		if pulseErr := c.refreshMaintenanceActiveRecovery(ctx, pulseAllowed, publishRecovery); pulseErr != nil {
			return pulseFailure(pulseErr)
		}
		stage = "maintenance_captured_owner"
		current, ok = c.active[id]
		if !ok || !reflect.DeepEqual(current, old) {
			return fail()
		}
		stage = "maintenance_candidate_reserve"
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
	for _, a := range candidates {
		connection = a.Entry.Allocation.ConnectionID
		stage = "maintenance_candidate_qualification"
		if a.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent()) {
			return fail()
		}
	}
	connection = uuid.Nil
	stage = "maintenance_combined_install"
	if c.installActiveCandidates(ctx, entries, staged, candidates, c.active, func() bool {
		if ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
			return false
		}
		for _, a := range candidates {
			if a.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent()) {
				return false
			}
		}
		return true
	}) != nil {
		return fail()
	}
	nativeCommitted = true
	c.refreshMaintenanceRecovery(ctx)
	stage = "maintenance_active_pulse"
	if pulseErr := c.refreshMaintenanceActiveRecovery(ctx, pulseAllowed, publishRecovery); pulseErr != nil {
		return pulseFailure(pulseErr)
	}
	result := make([]RuntimeMaintenanceResult, 0, len(maintained))
	for _, m := range maintained {
		id := m.Manifest.ConnectionID
		candidate := candidates[id]
		connection = id
		stage = "maintenance_candidate_binding"
		current, ok := c.active[id]
		if !ok || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) {
			return fail()
		}
		bgp, bgpErr := runtimeBGPContract(m.Manifest)
		recovery, recoveryErr := runtimeRecoveryContract(m.Manifest)
		report := RuntimeStatusReport{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, ConfigurationRevision: m.Manifest.ConfigurationRevision}
		for i, t := range m.Manifest.Tunnels {
			report.Tunnels[i] = RuntimeTunnelStatus{ID: t.ID, Slot: t.Slot, Status: "unknown", Selected: t.Selected}
		}
		// Do not advance this owner's sequence between its captured report and
		// the corresponding callback; every transmitted report stays ordered.
		stage = "maintenance_active_pulse"
		if pulseErr := c.refreshMaintenanceActiveRecovery(ctx, pulseAllowed, publishRecovery); pulseErr != nil {
			return pulseFailure(pulseErr)
		}
		stage = "maintenance_status"
		report, err = c.observeIPsecStatusLocked(ctx, m, report, bgp, recovery)
		if err != nil || bgpErr != nil || recoveryErr != nil || (bgp && (bgpCurrent == nil || !bgpCurrent())) || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
			return fail()
		}
		c.refreshMaintenanceRecovery(ctx)
		stage = "maintenance_candidate_report_reserve"
		if _, err = candidate.Authority.RemainingForApply(candidate.Identity, time.Millisecond); err != nil {
			return fail()
		}
		if publish != nil {
			stage = "maintenance_publish"
			if publish(ctx, m, report) != nil {
				return fail()
			}
			c.refreshMaintenanceRecovery(ctx)
			stage = "maintenance_active_pulse"
			if pulseErr := c.refreshMaintenanceActiveRecovery(ctx, pulseAllowed, publishRecovery); pulseErr != nil {
				return pulseFailure(pulseErr)
			}
			// External report IO cannot turn a now-expired or replaced candidate
			// into an applied result. The full-set check below remains required.
			stage = "maintenance_candidate_after_publish"
			current, ok = c.active[id]
			if !ok || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || (candidate.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent())) {
				return fail()
			}
			if _, err = candidate.Authority.RemainingForApply(candidate.Identity, time.Millisecond); err != nil {
				return fail()
			}
		}
		// Maintenance skips ordinary Apply for this exact completed delivery.
		// Reuse its bounded standby retry without preempting the selected path;
		// only fresh known-Up/Down evidence and the committed finite lease can
		// initiate the spare. The full-set check below still gates every ACK.
		if candidate.Entry.ContractVersion == 2 {
			retryCtx, retryCancel := context.WithTimeout(ctx, 5*time.Second)
			c.retryDownStandby(retryCtx, candidate.Entry, candidate.Authority, candidate.Identity)
			retryCancel()
		}
		result = append(result, RuntimeMaintenanceResult{Acknowledgement: RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}, Report: report})
	}

	// A later owner's status IO can consume an earlier candidate's remaining
	// deadline. Validate the complete result set once more before any external ACK.
	for _, m := range maintained {
		candidate := candidates[m.Manifest.ConnectionID]
		connection = m.Manifest.ConnectionID
		stage = "maintenance_candidate_final"
		current, ok := c.active[m.Manifest.ConnectionID]
		if !ok || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || (candidate.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent())) {
			return fail()
		}
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
	stage := "maintenance_prior_reserve"
	started := time.Now()
	diagnosed := false
	defer func() {
		if resultErr != nil && !diagnosed {
			c.emitRuntimeDiagnostic(ctx, "maintenance_current", stage, old.Entry.Allocation.ConnectionID, started, true)
		}
	}()
	if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
		return ErrRuntimeController
	}
	proofCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer func() {
		if resultErr != nil {
			c.emitRuntimeDiagnostic(proofCtx, "maintenance_current", stage, old.Entry.Allocation.ConnectionID, started, true)
			diagnosed = true
		}
		cancel()
	}()
	if proveNative {
		stage = "maintenance_native_proof"
		if c.proveCurrent(proofCtx, old.Entry, old.Environment) != nil {
			return ErrRuntimeController
		}
	}
	stage = "maintenance_native_guard"
	if c.maintenanceGuard(proofCtx, old.Entry) != nil {
		return ErrRuntimeController
	}
	if proveNative && old.Entry.ContractVersion == 3 {
		stage = "maintenance_bgp_qualification"
		if bgpCurrent == nil || !bgpCurrent() {
			return ErrRuntimeController
		}
		e := old.Entry
		stage = "maintenance_bgp_process"
		p := c.bgpProcesses[e.DeliveryID]
		if p == nil || !p.Alive() {
			return ErrRuntimeController
		}
		stage = "maintenance_bgp_status"
		status, err := p.Observe(proofCtx)
		if err != nil {
			return ErrRuntimeController
		}
		stage = "maintenance_bgp_routes"
		routes, err := p.ObserveRoutes(proofCtx, status)
		if err != nil {
			return ErrRuntimeController
		}
		stage = "maintenance_bgp_native_status"
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
		stage = "maintenance_bgp_target"
		if !p.Alive() || !bgpCurrent() || !reflect.DeepEqual(target, e.BGPRoutes.Owned) {
			return ErrRuntimeController
		}
	}
	stage = "maintenance_final_context"
	if proofCtx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
		return ErrRuntimeController
	}
	stage = "maintenance_final_prior_reserve"
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
