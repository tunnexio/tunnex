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

func (c *RuntimeController) maintainIPsecRuntimeObserved(ctx context.Context, materials []RuntimeMaterial, authority func() *PermitLeaseAuthority, bgpCurrent func() bool, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) ([]RuntimeMaintenanceResult, error) {
	if !c.started || c.closed || ctx.Err() != nil || authority == nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !c.qualification.current() || len(materials) > 256 {
		c.deniedClassicTransports = nil
		return nil, ErrRuntimeController
	}
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
	if _, gateErr := os.Lstat(filepath.Join(c.config.JournalDir, "restoration-startup-gate")); !os.IsNotExist(gateErr) {
		return fail()
	}
	ns, err := c.namespace()
	if err != nil {
		return fail()
	}
	// Validate every secret-bearing normal material and its unique page identity
	// before requesting any lease. No PSK is retained in a candidate or result.
	input := make([]RuntimeJournalEntry, len(materials))
	grants := make([][]GuardGrant, len(materials))
	connections, deliveries := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
	for i, m := range materials {
		input[i], grants[i], err = runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, ns)
		id := m.Manifest.ConnectionID
		if err != nil || connections[id] || deliveries[m.ID] {
			return fail()
		}
		connections[id], deliveries[m.ID] = true, true
	}
	// Match ordinary Apply: revoke changed published DNS inputs before any
	// blocking environment/native/lease IO can leave an old query permission open.
	for i, m := range materials {
		c.withdrawChangedDNSMaterial(m, grants[i])
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
	for i, m := range materials {
		id := m.Manifest.ConnectionID
		old, ok := c.active[id]
		eligible := false
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
			if current != nil && lineage {
				env, observeErr := c.config.Environment.Observe(ctx, input[i].Allocation, input[i].Engines)
				same := input[i]
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
				identity := PermitLeaseIdentity{DeliveryID: m.ID, Binding: same.Engines[0].Binding, PolicyHash: m.Policy.Hash}
				eligible = observeErr == nil && env.Namespace == ns && same.Phase == RuntimeApplied && (same.ContractVersion == 2 || same.ContractVersion == 3 || (same.ContractVersion == 4 && same.Allocation.ProfileID == GCPClassicStaticProfile && validClassicJournal(same))) && reflect.DeepEqual(same, *current) && reflect.DeepEqual(old.Entry, same) && reflect.DeepEqual(old.Delivery, m.RuntimeDelivery) && reflect.DeepEqual(old.Environment, env) && reflect.DeepEqual(old.Grants, grants[i]) && old.Identity == identity && old.Authority != nil
				if eligible {
					if same.ContractVersion == 2 {
						prepared, known := c.recoveryPrepared[m.ID]
						eligible = known && reflect.DeepEqual(prepared, env) && validJournalRecovery(same) && same.Recovery.Stage == "completed"
					}
					if same.ContractVersion == 3 {
						eligible = validJournalBGP(same) && same.BGPProcess != nil && same.BGPProcess.Stage == "ready" && same.BGPRoutes != nil && same.BGPRoutes.Stage == "completed"
					}
				}
				if eligible {
					eligible = c.maintenanceCurrent(ctx, old, bgpCurrent) == nil
				}
			}
		}
		if !eligible {
			if ok {
				delete(staged, id)
				c.withdrawDNSOwnerView(id)
				changed = true
			}
			continue
		}
		fresh := authority()
		if fresh == nil {
			return fail()
		}
		request, beginErr := fresh.Begin(old.Identity)
		if beginErr != nil {
			return fail()
		}
		lease, leaseErr := c.client.RenewIPsecLease(ctx, id, RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, PolicyHash: m.Policy.Hash, Nonce: request.Nonce})
		if leaseErr != nil || lease.DeliveryID != m.ID || lease.DesiredRevision != m.DesiredRevision || lease.PolicyHash != m.Policy.Hash || lease.Nonce != request.Nonce || fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: lease.TTLMS}) != nil {
			return fail()
		}
		// The old authority must still bridge this collection; a response arriving
		// after it expires cannot recreate a missing permit from cached transport.
		if c.maintenanceCurrent(ctx, old, bgpCurrent) != nil {
			delete(staged, id)
			c.withdrawDNSOwnerView(id)
			changed = true
			continue
		}
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
		if a.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent()) {
			return failHAFreshness()
		}
	}
	haFreshnessFailed := false
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
		candidate := candidates[id]
		current, ok := c.active[id]
		if !ok || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) {
			return fail()
		}
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
		report, err = c.observeIPsecStatusLocked(ctx, m, report, bgp, recovery)
		if err != nil || bgpErr != nil || recoveryErr != nil || (bgp && (bgpCurrent == nil || !bgpCurrent())) || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
			return fail()
		}
		if _, err = candidate.Authority.RemainingForApply(candidate.Identity, time.Millisecond); err != nil {
			return fail()
		}
		if publish != nil {
			if publish(ctx, m, report) != nil {
				return fail()
			}
			// External report IO cannot turn a now-expired or replaced candidate
			// into an applied result. The full-set check below remains required.
			current, ok = c.active[id]
			if !ok || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() || (candidate.Entry.ContractVersion == 3 && (bgpCurrent == nil || !bgpCurrent())) {
				return fail()
			}
			if _, err = candidate.Authority.RemainingForApply(candidate.Identity, time.Millisecond); err != nil {
				return fail()
			}
		}
		result = append(result, RuntimeMaintenanceResult{Acknowledgement: RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}, Report: report})
	}

	// A later owner's status IO can consume an earlier candidate's remaining
	// deadline. Validate the complete result set once more before any external ACK.
	for _, m := range maintained {
		candidate := candidates[m.Manifest.ConnectionID]
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
	if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
		return ErrRuntimeController
	}
	proofCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if c.proveCurrent(proofCtx, old.Entry, old.Environment) != nil || c.maintenanceGuard(proofCtx, old.Entry) != nil {
		return ErrRuntimeController
	}
	if old.Entry.ContractVersion == 3 {
		if bgpCurrent == nil || !bgpCurrent() {
			return ErrRuntimeController
		}
		e := old.Entry
		p := c.bgpProcesses[e.DeliveryID]
		if p == nil || !p.Alive() {
			return ErrRuntimeController
		}
		status, err := p.Observe(proofCtx)
		if err != nil {
			return ErrRuntimeController
		}
		routes, err := p.ObserveRoutes(proofCtx, status)
		if err != nil {
			return ErrRuntimeController
		}
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
		if !p.Alive() || !bgpCurrent() || !reflect.DeepEqual(target, e.BGPRoutes.Owned) {
			return ErrRuntimeController
		}
	}
	if proofCtx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
		return ErrRuntimeController
	}
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
