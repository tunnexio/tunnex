package ipsec

import (
	"context"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"reflect"
	"time"
)

type runtimeBGPSession interface {
	Alive() bool
	Close() error
	Observe(context.Context) (bgpengine.Status, error)
	ObserveRoutes(context.Context, bgpengine.Status) ([]bgpengine.LearnedRoute, error)
}

func runtimeBGPProcessConfig(e RuntimeJournalEntry) (bgpengine.Config, error) {
	if !validJournalBGP(e) || e.ContractVersion != 3 {
		return bgpengine.Config{}, ErrRuntimeController
	}
	router, e2 := netip.ParseAddr(e.BGP.RouterID)
	if e2 != nil {
		return bgpengine.Config{}, ErrRuntimeController
	}
	c := bgpengine.Config{LocalASN: e.BGP.LocalASN, RemoteASN: e.BGP.RemoteASN, RouterID: router, MaximumPrefixes: e.BGP.MaximumPrefixes, LocalPrefixes: e.Engines[0].LocalPrefixes, RemotePrefixes: e.Engines[0].RemotePrefixes}
	for i, t := range e.Allocation.Tunnels {
		c.Peers[i] = bgpengine.Peer{Slot: int(t.Slot), Local: t.InsideAddress.Addr(), Remote: t.BGP.Peer, LinkName: t.Name, XFRMID: t.XFRMID}
	}
	return c, nil
}
func (c *RuntimeController) startBGPSession(ctx context.Context, e RuntimeJournalEntry) error {
	if c.bgpProcesses == nil {
		c.bgpProcesses = map[uuid.UUID]runtimeBGPSession{}
	}
	if existing := c.bgpProcesses[e.DeliveryID]; existing != nil {
		if existing.Alive() {
			return nil
		}
		return ErrRuntimeController
	}
	cfg, err := runtimeBGPProcessConfig(e)
	if err != nil {
		return err
	}
	var process runtimeBGPSession
	if c.bgpStart != nil {
		process, err = c.bgpStart(ctx, e, cfg)
	} else {
		generation := historyCount(e.BGPProcessHistory) + uint64(len(e.BGPProcessRetired)+1)
		if e.BGPProcess != nil {
			if (e.BGPProcess.Stage != "cleaned" && proveUncertainRuntimeBGPProcess(*e.BGPProcess) != nil) || e.BGPProcess.Generation == ^uint64(0) {
				return ErrRuntimeController
			}
			generation = e.BGPProcess.Generation + 1
		}
		checkpoint := func(identity bgpengine.ProcessIdentity) error {
			identity.Generation = generation
			if c.bgpCheckpointBeforeSave != nil {
				if err := c.bgpCheckpointBeforeSave(identity); err != nil {
					return err
				}
			}
			entries, err := c.journal.Entries()
			if err != nil {
				return err
			}
			for i := range entries {
				if entries[i].DeliveryID == e.DeliveryID {
					if identity.Stage == "reserved" && entries[i].BGPProcess != nil {
						old := *entries[i].BGPProcess
						if compactBGPProcessHistory(&entries[i]) != nil || (old.Stage != "cleaned" && proveUncertainRuntimeBGPProcess(old) != nil) {
							return ErrRuntimeJournal
						}
						if old.Stage != "cleaned" {
							old.Stage = "retired-uncertain"
						}
						entries[i].BGPProcessRetired = append(entries[i].BGPProcessRetired, old)
					}
					entries[i].BGPProcess = &identity
					return c.journal.Save(entries)
				}
			}
			return ErrRuntimeJournal
		}
		process, err = startRuntimeBGPSession(ctx, c.config.JournalDir, e.DeliveryID, generation, cfg, checkpoint)
	}
	if err != nil || process == nil {
		return ErrRuntimeController
	}
	c.bgpProcesses[e.DeliveryID] = process
	return nil
}
func (c *RuntimeController) observedBGPStatus(ctx context.Context, e RuntimeJournalEntry) (*bgpengine.Status, error) {
	if e.ContractVersion != 3 || !validJournalBGP(e) || e.Phase != RuntimeApplied {
		return nil, ErrRuntimeController
	}
	p := c.bgpProcesses[e.DeliveryID]
	if p == nil || !p.Alive() {
		return nil, ErrRuntimeController
	}
	ns, err := c.namespace()
	if err != nil || ns != e.Allocation.Namespace {
		return nil, ErrRuntimeController
	}
	status, err := p.Observe(ctx)
	if err != nil {
		return nil, err
	}
	healthy := c.observeRecovery(ctx, e)
	for i := range status.Peers {
		if status.Peers[i].State == "established" && healthy[i] != "up" {
			return nil, ErrRuntimeController
		}
	}
	return &status, nil
}

// Native package, transport, routing, crash and trusted restoration gates passed.
// Actual current receipts and fresh forwarding leases remain independently required.
const bgpLifecycleAccepted = true

// AttachBGPQualification binds actual no-peer engine proof to the already
// qualified managed IPsec daemon and namespace. It grants no forwarding lease.
func (c *RuntimeController) AttachBGPQualification(q *bgpengine.PreflightQualification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.started || c.bgpQualification != nil || !q.Current() || !c.qualification.current() || c.config.Daemon == nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return ErrRuntimeController
	}
	ns, err := c.namespace()
	if err != nil || ns != q.Namespace() || ns != c.qualification.namespace {
		return ErrRuntimeController
	}
	c.bgpQualification = q
	return nil
}
func (c *RuntimeController) bgpQualificationCurrent() bool {
	if !bgpLifecycleAccepted || c.closed || !c.started || !c.bgpQualification.Current() || !c.qualification.current() || c.config.Daemon == nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return false
	}
	ns, err := c.namespace()
	return err == nil && ns == c.bgpQualification.Namespace() && ns == c.qualification.namespace
}
func (c *RuntimeController) BGPCapability() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bgpQualificationCurrent() {
		return 1
	}
	return 0
}

func (c *RuntimeController) proveBGPCurrent(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
	if !validJournalBGP(e) || !validBGPRoutes(e) || e.ContractVersion != 3 || (e.BGPRoutes != nil && e.BGPRoutes.Stage != "completed") {
		return ErrRuntimeController
	}
	if c.kernel.verifyBGPRoutes(ctx, e.Allocation, e.Observed, bgpRouteUnion(e.BGPRoutes), true) != nil {
		return ErrRuntimeController
	}
	statuses := c.observeRecovery(ctx, e)
	up := false
	for _, state := range statuses {
		if state != "up" && state != "down" {
			return ErrRuntimeController
		}
		up = up || state == "up"
	}
	if !up {
		return ErrRuntimeController
	}
	current, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
	if err != nil || !reflect.DeepEqual(current, env) {
		return ErrRuntimeController
	}
	return nil
}
func (c *RuntimeController) bgpGuard(ctx context.Context, a runtimeActive, remaining time.Duration) (GuardConnection, error) {
	return c.bgpGuardWithStatuses(ctx, a, remaining, c.observeRecovery(ctx, a.Entry))
}

func (c *RuntimeController) bgpGuardWithStatuses(ctx context.Context, a runtimeActive, remaining time.Duration, statuses [2]string) (GuardConnection, error) {
	e := a.Entry
	g := GuardConnection{ID: e.Allocation.ConnectionID, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, Tunnels: e.Observed, LocalIngressIndices: a.Environment.LocalIngressIndices, Grants: a.Grants, PermitFor: remaining}
	for i, t := range e.Allocation.Tunnels {
		peer := GuardBGPPeer{Local: t.InsideAddress.Addr(), Remote: t.BGP.Peer}
		if statuses[i] == "up" {
			peer.InterfaceIndex = e.Observed[i].InterfaceIndex
			g.PermittedInterfaceIndices = append(g.PermittedInterfaceIndices, peer.InterfaceIndex)
			g.ReplyIngressIndices = append(g.ReplyIngressIndices, peer.InterfaceIndex)
			g.EncryptedEgress = append(g.EncryptedEgress, GuardEncryptedEgress{TunnelInterfaceIndex: peer.InterfaceIndex, ReqID: e.Engines[i].ReqID, Peer: e.Engines[i].RemoteAddress, UnderlayInterfaceIndex: a.Environment.Underlays[i].InterfaceIndex})
		} else if statuses[i] != "down" {
			return GuardConnection{}, ErrRuntimeController
		}
		g.BGPPeers = append(g.BGPPeers, peer)
	}
	if len(g.PermittedInterfaceIndices) == 0 {
		return GuardConnection{}, ErrRuntimeController
	}
	if len(g.Grants) > 0 {
		var err error
		g.TunnelMTUs, err = c.guardTunnelMTUs(ctx, e, a.Environment, g.PermittedInterfaceIndices, g.ReplyIngressIndices)
		if err != nil {
			return GuardConnection{}, err
		}
	}
	return g, nil
}

// maintenanceBGPGuard is only for required renewal candidates. The original
// post-CP route proof and guard assembly share one fresh same-owner health sample
// within the caller's bounded assembly context; no observation is retained.
func (c *RuntimeController) maintenanceBGPGuard(ctx context.Context, a, old runtimeActive, remaining time.Duration, current func() bool) (GuardConnection, error) {
	fail := func() (GuardConnection, error) { return GuardConnection{}, ErrRuntimeController }
	if old.Authority == nil || current == nil || !current() {
		return fail()
	}
	if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
		return fail()
	}
	e := a.Entry
	p := c.bgpProcesses[e.DeliveryID]
	if p == nil || !p.Alive() {
		return fail()
	}
	status, err := p.Observe(ctx)
	if err != nil {
		return fail()
	}
	routes, err := p.ObserveRoutes(ctx, status)
	if err != nil {
		return fail()
	}
	health := c.observeRecovery(ctx, e)
	for _, state := range health {
		if state != "up" && state != "down" {
			return fail()
		}
	}
	target := []RuntimeBGPRouteTuple{}
	for _, route := range routes {
		if route.Slot >= 1 && route.Slot <= 2 && health[route.Slot-1] == "up" {
			target = append(target, RuntimeBGPRouteTuple{Prefix: route.Prefix, Slot: uint8(route.Slot), InterfaceIndex: e.Observed[route.Slot-1].InterfaceIndex, Table: 254, Protocol: 242, Metric: 50000 + uint32(route.Slot)})
		}
	}
	if !p.Alive() || !current() || !reflect.DeepEqual(target, e.BGPRoutes.Owned) {
		return fail()
	}
	if ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
		return fail()
	}
	if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
		return fail()
	}
	return c.bgpGuardWithStatuses(ctx, a, remaining, health)
}

// reconcileActiveBGP never renews a CP lease. It withdraws grants before an
// observed route change and restores them only after durable exact readback.
func (c *RuntimeController) reconcileActiveBGP(ctx context.Context, entries []RuntimeJournalEntry) (resultErr error) {
	stage := "input"
	connection := uuid.Nil
	started := time.Now()
	defer func() { c.emitRuntimeDiagnostic(ctx, "bgp_reconcile", stage, connection, started, resultErr != nil) }()
	for id, active := range c.active {
		e := active.Entry
		if e.ContractVersion != 3 {
			continue
		}
		connection = id
		stage = "permit_freshness"
		permitStarted := time.Now()
		permit := func() error { _, err := active.Authority.RemainingForApply(active.Identity, 5*time.Second); return err }
		p := c.bgpProcesses[e.DeliveryID]
		target := []RuntimeBGPRouteTuple{}
		fresh := permit() == nil && p != nil && p.Alive()
		c.emitRuntimeDiagnostic(ctx, "bgp_reconcile", stage, id, permitStarted, !fresh)
		if fresh {
			stage = "peer_summary_observation"
			observedStarted := time.Now()
			status, err := p.Observe(ctx)
			c.emitRuntimeDiagnostic(ctx, "bgp_reconcile", stage, id, observedStarted, err != nil)
			if err != nil {
				fresh = false
			} else {
				stage = "route_observation"
				routeStarted := time.Now()
				routes, err := p.ObserveRoutes(ctx, status)
				c.emitRuntimeDiagnostic(ctx, "bgp_reconcile", stage, id, routeStarted, err != nil)
				if err != nil {
					fresh = false
				} else {
					stage = "transport_status"
					transportStarted := time.Now()
					health := c.observeRecovery(ctx, e)
					for _, state := range health {
						if state != "up" && state != "down" {
							fresh = false
						}
					}
					c.emitRuntimeDiagnostic(ctx, "bgp_reconcile", stage, id, transportStarted, !fresh)
					if fresh {
						for _, r := range routes {
							if r.Slot >= 1 && r.Slot <= 2 && health[r.Slot-1] == "up" {
								target = append(target, RuntimeBGPRouteTuple{Prefix: r.Prefix, Slot: uint8(r.Slot), InterfaceIndex: e.Observed[r.Slot-1].InterfaceIndex, Table: 254, Protocol: 242, Metric: 50000 + uint32(r.Slot)})
							}
						}
					}
				}
			}
		}
		var closeErr error

		stage = "route_journal_binding"
		current := []RuntimeBGPRouteTuple{}
		if e.BGPRoutes != nil {
			if e.BGPRoutes.Stage != "completed" {
				return ErrRuntimeController
			}
			current = e.BGPRoutes.Owned
		}
		if reflect.DeepEqual(current, target) && fresh {
			continue
		}
		grants := active.Grants
		c.withdrawDNSOwnerView(id)
		active.Grants = nil
		c.active[id] = active
		stage = "route_guard_withdrawal"
		if c.installActive(ctx, entries) != nil {
			delete(c.active, id)
			_, _ = c.refuse(ctx, entries)
			if !fresh && p != nil {
				_ = c.finishKnownBGPSession(e)
			}
			return ErrRuntimeController
		}
		stage = "session_cleanup"
		if !fresh && p != nil {
			closeErr = c.finishKnownBGPSession(e)
		}
		stage = "final_binding"
		if fresh {
			current, ok := c.active[id]
			if !ok || current.Identity != active.Identity || permit() != nil {
				delete(c.active, id)
				return ErrRuntimeController
			}
		}
		stage = "route_commit_readback"
		if reconcileBGPRoutesPermit(ctx, c.journal, c.kernel, e.DeliveryID.String(), target, permit) != nil {
			delete(c.active, id)
			return ErrRuntimeController
		}
		stage = "journal_inventory"
		latest, err := c.journal.Entries()
		if err != nil {
			delete(c.active, id)
			return err
		}
		for _, entry := range latest {
			if entry.DeliveryID == e.DeliveryID {
				active.Entry = entry
			}
		}
		if !fresh {
			delete(c.active, id)
			if closeErr != nil {
				return ErrRuntimeController
			}
			delete(c.bgpProcesses, e.DeliveryID)
			continue
		}
		stage = "final_permit"
		if permit() != nil {
			delete(c.active, id)
			return ErrRuntimeController
		}
		active.Grants = grants
		c.active[id] = active
		entries = latest
	}
	return nil
}

// bgpUnchangedActive permits only continuity of the old, unextended lease.
// Fresh RIB reconciliation still precedes publishing the replacement authority.
func (c *RuntimeController) bgpUnchangedActive(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, identity PermitLeaseIdentity, grants []GuardGrant) (runtimeActive, bool) {
	old, ok := c.active[e.Allocation.ConnectionID]
	p := c.bgpProcesses[e.DeliveryID]
	if !ok || old.Identity != identity || !reflect.DeepEqual(old.Entry, e) || !reflect.DeepEqual(old.Environment, env) || !reflect.DeepEqual(old.Grants, grants) || e.Phase != RuntimeApplied || e.BGPProcess == nil || e.BGPProcess.Stage != "ready" || p == nil || !p.Alive() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || e.BGPRoutes == nil || e.BGPRoutes.Stage != "completed" {
		return runtimeActive{}, false
	}
	if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil || c.proveCurrent(ctx, e, env) != nil || c.kernel.verifyBGPRoutes(ctx, e.Allocation, e.Observed, e.BGPRoutes.Owned, true) != nil {
		return runtimeActive{}, false
	}
	return old, true
}

func (c *RuntimeController) prepareBGPApplyActive(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, identity PermitLeaseIdentity, authority *PermitLeaseAuthority, grants []GuardGrant, entries []RuntimeJournalEntry) (runtimeActive, bool, error) {
	id := e.Allocation.ConnectionID
	active, continuous := c.bgpUnchangedActive(ctx, e, env, identity, grants)
	if !continuous {
		active = runtimeActive{Entry: e, Environment: env, Identity: identity, Authority: authority}
		c.active[id] = active
		if c.installActive(ctx, entries) != nil {
			return runtimeActive{}, false, ErrRuntimeController
		}
	}
	// A changed/absent process can never retain the continuity exception.
	if continuous && !c.bgpProcesses[e.DeliveryID].Alive() {
		active.Grants = nil
		c.active[id] = active
		if c.installActive(ctx, entries) != nil {
			return runtimeActive{}, false, ErrRuntimeController
		}
		continuous = false
	}
	return active, continuous, nil
}

func (c *RuntimeController) applyBGP(ctx context.Context, m RuntimeMaterial, entries []RuntimeJournalEntry, pos int, env RuntimeEnvironment, grants []GuardGrant) (ackResult RuntimeAcknowledgement, resultErr error) {
	stage := "qualification"
	started := time.Now()
	defer func() {
		c.emitRuntimeDiagnostic(ctx, "bgp_apply", stage, m.Manifest.ConnectionID, started, resultErr != nil)
	}()
	e := entries[pos]
	id := e.Allocation.ConnectionID
	fail := func() (RuntimeAcknowledgement, error) {
		delete(c.active, id)
		_, _ = c.refuse(ctx, entries)
		return RuntimeAcknowledgement{}, ErrRuntimeController
	}
	if !c.bgpQualificationCurrent() || !validJournalBGP(e) || e.AbsenceOnly || (e.BGPRoutes != nil && e.BGPRoutes.Stage != "completed") {
		return fail()
	}
	if c.active == nil {
		c.active = map[uuid.UUID]runtimeActive{}
	}
	stage = "permit_lease"
	authority, identity, err := c.recoveryLease(ctx, e, m.Policy.Hash)
	if err != nil {
		return fail()
	}
	if c.bgpStaged == nil {
		c.bgpStaged = map[uuid.UUID]bool{}
	}
	stage = "restored_transport"
	recreate, missingTransport, err := c.bgpRestoredTransportAbsent(ctx, e, entries, authority, identity)
	if err != nil {
		return fail()
	}
	stage = "transport_stage"
	if (e.Phase != RuntimeApplied || recreate) && !c.bgpStaged[e.DeliveryID] {
		delete(c.active, id)
		if c.installActive(ctx, entries) != nil {
			return fail()
		}
		if e.Phase != RuntimeApplied {
			e.Phase = RuntimeApplying
		}
		entries[pos] = e
		if c.journal.Save(entries) != nil {
			return fail()
		}
		previous := e.Observed
		if missingTransport {
			previous = [2]Ownership{}
		}
		owned, err := c.kernel.Apply(ctx, e.Allocation, previous)
		if err != nil {
			return fail()
		}
		e.Observed = owned
		entries[pos] = e
		if c.journal.Save(entries) != nil {
			return fail()
		}
		for i, t := range e.Engines {
			if c.config.Daemon.removeTunnel(ctx, t) != nil {
				return fail()
			}
			secret := []byte(m.Secrets[i].PSK)
			err = c.config.Daemon.stageTunnel(ctx, t, secret)
			for i := range secret {
				secret[i] = 0
			}
			if err != nil {
				return fail()
			}
		}
		// Configurations are staged even when negotiation fails or times out.
		// A later poll must not remove a healthy peer to retry the other one.
		c.bgpStaged[e.DeliveryID] = true
	}
	stage = "transport_initiate"
	if e.Phase != RuntimeApplied || recreate {
		if c.initiateStagedBGPChildren(ctx, e, env, authority, identity) != nil {
			return fail()
		}
	}
	stage = "transport_retry"
	if allDown, err := c.retryAllDownBGPChildren(ctx, e, env, authority, identity, entries); allDown || err != nil {
		return fail()
	}
	stage = "native_current_proof"
	if c.proveCurrent(ctx, e, env) != nil {
		return fail()
	}
	stage = "remaining_authority"
	if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
		return fail()
	}
	stage = "journal_commit"
	e.Phase = RuntimeApplied
	entries[pos] = e
	if c.journal.Save(entries) != nil {
		return fail()
	}
	// A changed physical ceiling withdraws grants before exact owned MTU lowering.
	// Unchanged ceilings preserve the prior lease and uninterrupted forwarding.
	stage = "underlay_mtu"
	if _, err := c.ensureUnderlayMTUs(ctx, e, env, entries); err != nil {
		return fail()
	}
	// Transport-only leased guard permits exact peer sessions, with no application
	// grants until fresh RIB reconciliation and exact route readback complete.
	stage = "active_continuity"
	active, continuous, err := c.prepareBGPApplyActive(ctx, e, env, identity, authority, grants, entries)
	if err != nil {
		return fail()
	}
	stage = "session_cleanup"
	if p := c.bgpProcesses[e.DeliveryID]; (p != nil && !p.Alive()) || (p == nil && e.BGPProcess != nil && e.BGPProcess.Stage != "cleaned") {
		// Alive can change after the continuity checks. Revoke the retained
		// application grant and prove denial before any dead-session cleanup.
		continuous = false
		active, err = c.denyBGPApplySessionCleanup(ctx, active, identity, authority, entries)
		if err != nil {
			return fail()
		}

		if cleanupErr := c.finishKnownBGPSession(e); cleanupErr != nil {
			// An absent in-memory process can be a durably bounded startup
			// gap. Preserve its immutable uncertainty only after the original
			// supervisor and generation daemons are independently absent.
			if p != nil || cleanupErr != ErrRuntimeController || e.BGPProcess == nil || proveUncertainRuntimeBGPProcess(*e.BGPProcess) != nil {
				return fail()
			}
		}
		entries, err = c.journal.Entries()
		if err != nil {
			return fail()
		}
		for i, entry := range entries {
			if entry.DeliveryID == e.DeliveryID {
				e = entry
				pos = i
				active.Entry = entry
			}
		}
	}
	stage = "session_start"
	if c.startBGPSession(ctx, e) != nil {
		return fail()
	}
	entries, err = c.journal.Entries()
	if err != nil {
		return fail()
	}
	for _, entry := range entries {
		if entry.DeliveryID == e.DeliveryID {
			e = entry
			active.Entry = entry
		}
	}
	stage = "route_initialization"
	if e.BGPRoutes == nil {
		if reconcileBGPRoutesPermit(ctx, c.journal, c.kernel, e.DeliveryID.String(), []RuntimeBGPRouteTuple{}, func() error { _, err := authority.RemainingForApply(identity, 5*time.Second); return err }) != nil {
			return fail()
		}
		entries, err = c.journal.Entries()
		if err != nil {
			return fail()
		}
		for _, entry := range entries {
			if entry.DeliveryID == e.DeliveryID {
				active.Entry = entry
			}
		}
	}
	active.Grants = grants
	c.active[id] = active
	stage = "bgp_reconcile"
	if c.reconcileActiveBGP(ctx, entries) != nil {
		return fail()
	}
	entries, err = c.finishBGPApplyContinuity(ctx, entries, active, continuous, authority, identity, c.bgpQualificationCurrent)
	if err != nil {
		return RuntimeAcknowledgement{}, err
	}
	stage = "combined_guard"
	if err != nil || c.installActive(ctx, entries) != nil {
		return fail()
	}
	if c.rememberAppliedBGPDelivery(ctx, m.RuntimeDelivery, m.Policy.Hash, c.bgpQualificationCurrent) != nil {
		return fail()
	}
	currentEntries, retryErr := c.journal.Entries()
	if retryErr == nil {
		for _, current := range currentEntries {
			if current.DeliveryID == e.DeliveryID {
				c.retryMissingBGPChild(ctx, current)
			}
		}
	}
	return RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}, nil
}

// finishBGPApplyContinuity is the existing post-reconcile publication boundary.
// The caller reaches it only after successful reconciliation, and supplies a
// fresh BGP qualification observation. Tests exercise this boundary without
// manufacturing a native BGP platform qualification for public Apply.
func (c *RuntimeController) finishBGPApplyContinuity(ctx context.Context, entries []RuntimeJournalEntry, active runtimeActive, continuous bool, authority *PermitLeaseAuthority, identity PermitLeaseIdentity, bgpCurrent func() bool) ([]RuntimeJournalEntry, error) {
	id := active.Entry.Allocation.ConnectionID
	fail := func() ([]RuntimeJournalEntry, error) {
		delete(c.active, id)
		_, _ = c.refuse(ctx, entries)
		return nil, ErrRuntimeController
	}
	latest, err := c.journal.Entries()
	if err != nil {
		return fail()
	}
	if continuous {
		current, ok := c.active[id]
		if !ok || current.Identity != active.Identity {
			// A successful reconciliation can remove this exact exhausted owner,
			// close its known session and commit empty owned routes. Refuse this
			// Apply without touching other owners only after that full proof.
			if !ok && c.expiredBGPContinuityDenied(ctx, active, latest, authority, identity, bgpCurrent) {
				c.withdrawDNSOwnerView(id)
				if c.guard != nil && c.guard.withdrawConnection(ctx, active.Entry.Allocation.Namespace, id) == nil && ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive() && bgpCurrent() {
					if _, err := authority.RemainingForApply(identity, 5*time.Second); err == nil {
						return nil, ErrRuntimeController
					}
				}
			}
			return fail()
		}
		// Reconciliation used the old lease, including denial-before-route changes.
		// Only now may a fresh lease replace its authority and extend NFT timeouts.
		current.Identity, current.Authority = identity, authority
		c.active[id] = current
	}
	return latest, nil
}

// expiredBGPContinuityDenied classifies only the exact completed withdrawal
// reached after successful reconciliation. It adds no authority and cannot turn
// a different identity, still-valid reserve, unknown route/process or revoked
// platform qualification into a connection-local refusal.
func (c *RuntimeController) expiredBGPContinuityDenied(ctx context.Context, old runtimeActive, latest []RuntimeJournalEntry, authority *PermitLeaseAuthority, identity PermitLeaseIdentity, bgpCurrent func() bool) bool {
	e := old.Entry
	if ctx.Err() != nil || (bgpCurrent == nil || !bgpCurrent()) || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !validJournalBGP(e) || !validBGPRoutes(e) || e.ContractVersion != 3 || e.Phase != RuntimeApplied || e.AbsenceOnly || e.BGPProcess == nil || e.BGPProcess.Stage != "ready" || e.BGPRoutes == nil || e.BGPRoutes.Stage != "completed" || e.BGPRoutes.Sequence == ^uint64(0) || old.Identity != identity || identity.Binding != e.Engines[0].Binding || identity.DeliveryID != e.DeliveryID || identity.Binding.OrgID != c.config.OrgID || identity.Binding.GatewayID != c.config.GatewayID || old.Authority == nil || authority == nil || authority == old.Authority || c.bgpProcesses[e.DeliveryID] != nil {
		return false
	}
	ns, err := c.namespace()
	if err != nil || ns != e.Allocation.Namespace || old.Environment.Namespace != ns {
		return false
	}
	// Inspect only the original identity/deadline under its own lock. A revoked
	// identity or backwards clock is unknown. Exhaustion includes the exact
	// five-second commit reserve enforced by RemainingForApply, without extending
	// the original lease or admitting the fresh candidate.
	old.Authority.mu.Lock()
	now, clockOK := old.Authority.nowLocked()
	expired := clockOK && old.Authority.identity == identity && old.Authority.deadline > 0 && old.Authority.deadline-now <= 5*time.Second
	old.Authority.mu.Unlock()
	if !expired {
		return false
	}
	if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
		return false
	}
	found := false
	for _, current := range latest {
		if current.DeliveryID != e.DeliveryID {
			continue
		}
		if found || current.BGPProcess == nil || current.BGPProcess.Stage != "cleaned" || current.BGPRoutes == nil || current.BGPRoutes.Stage != "completed" || current.BGPRoutes.Sequence != e.BGPRoutes.Sequence+1 || len(current.BGPRoutes.Owned) != 0 || len(current.BGPRoutes.Target) != 0 {
			return false
		}
		// These are the only two legitimate durable changes made by this
		// successful reconciliation. All owner/native/configuration/history
		// inputs remain exact; no namespace or restoration identity is adopted.
		wanted := copyDNSEntry(e)
		wanted.BGPProcess.Stage = "cleaned"
		wanted.BGPRoutes = current.BGPRoutes
		if !reflect.DeepEqual(wanted, current) {
			return false
		}
		found = true
	}
	return found && ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive()
}

// bgpRestoredTransportAbsent keeps trusted reset intent Applied while proving
// whether its deliberately cleared ownership can be recreated. It grants no
// authority and writes no kernel object or journal entry.
func (c *RuntimeController) bgpRestoredTransportAbsent(ctx context.Context, e RuntimeJournalEntry, entries []RuntimeJournalEntry, authority *PermitLeaseAuthority, identity PermitLeaseIdentity) (bool, bool, error) {
	if e.Phase != RuntimeApplied || c.bgpStaged[e.DeliveryID] {
		return false, false, nil
	}
	if e.Restoration == nil {
		if e.Observed == ([2]Ownership{}) {
			return false, false, ErrRuntimeController
		}
		return false, false, nil
	}
	if e.Restoration.Epoch == 0 || !validRestoration(e) {
		return false, false, ErrRuntimeController
	}
	delete(c.active, e.Allocation.ConnectionID)
	if c.installActive(ctx, entries) != nil {
		return false, false, ErrRuntimeController
	}
	missing, err := c.restartNeedsRecreation(ctx, e)
	if err != nil {
		return false, false, ErrRuntimeController
	}
	if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
		return false, false, ErrRuntimeController
	}
	again, err := c.restartNeedsRecreation(ctx, e)
	if err != nil || again != missing {
		return false, false, ErrRuntimeController
	}
	// Both complete absence and exact surviving checkpointed links require fresh
	// daemon staging. A crash after Observed Save cannot turn Applied into proof.
	return true, missing, nil
}

// rememberAppliedBGPDelivery records only secret-free normal material after the
// successful ordinary BGP guard commit. It never grants or extends authority.
func (c *RuntimeController) rememberAppliedBGPDelivery(ctx context.Context, delivery RuntimeDelivery, hash string, bgpCurrent func() bool) error {
	a, ok := c.active[delivery.Manifest.ConnectionID]
	if !ok || !runtimeDeliveryValid(delivery, c.config.OrgID, c.config.GatewayID, "apply") || ctx.Err() != nil || delivery.Kind != "apply" || a.Entry.Phase != RuntimeApplied || a.Entry.ContractVersion != 3 || a.Entry.DeliveryID != delivery.ID || a.Entry.OwnershipDigest != delivery.OwnershipDigest || a.Identity != (PermitLeaseIdentity{DeliveryID: delivery.ID, Binding: a.Entry.Engines[0].Binding, PolicyHash: hash}) || a.Entry.Engines[0].Binding.DesiredRevision != delivery.DesiredRevision || a.Entry.Engines[0].Binding.ConfigurationRevision != delivery.Manifest.ConfigurationRevision || bgpCurrent == nil || !bgpCurrent() {
		return ErrRuntimeController
	}
	entries, err := c.journal.Entries()
	if err != nil {
		return ErrRuntimeController
	}
	found := false
	for _, e := range entries {
		if e.DeliveryID == delivery.ID {
			if found || !reflect.DeepEqual(e, a.Entry) {
				return ErrRuntimeController
			}
			found = true
		}
	}
	if !found {
		return ErrRuntimeController
	}
	if _, err = a.Authority.RemainingForApply(a.Identity, time.Millisecond); err != nil {
		return ErrRuntimeController
	}
	a.Delivery = delivery
	c.active[delivery.Manifest.ConnectionID] = a
	return nil
}
