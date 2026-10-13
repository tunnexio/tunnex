package ipsec

import (
	"context"
	"errors"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var ErrRuntimeController = errors.New("IPsec runtime operation refused")

type RuntimeUnderlay struct {
	InterfaceIndex int
	LocalAddress   netip.Addr
	OuterMTU       uint32
}
type RuntimeEnvironment struct {
	Namespace           string
	LocalIngressIndices []int
	Underlays           [2]RuntimeUnderlay
}

// RuntimeEnvironmentInspector must derive these facts from independent local
// observations, including hook compatibility. No CP assertion qualifies a host.
type RuntimeEnvironmentInspector interface {
	Observe(context.Context, KernelAllocation, [2]EngineTunnel) (RuntimeEnvironment, error)
	Drain(context.Context, []RuntimeJournalEntry) error
}
type RuntimeLeaseClient interface {
	RenewIPsecLease(context.Context, uuid.UUID, RuntimeLeaseRequest) (RuntimeLease, error)
}
type RuntimeControllerConfig struct {
	FQDNPolicy                  *RuntimeFQDNPolicySource
	Diagnostic                  func(RuntimeDiagnostic)
	OrgID, GatewayID            uuid.UUID
	JournalDir, IPPath, NFTPath string
	Daemon                      *DaemonClient
	DaemonAlive                 func() bool
	Environment                 RuntimeEnvironmentInspector
}
type runtimeActive struct {
	Delivery    RuntimeDelivery // secret-free, authenticated normal Apply context for telemetry
	Entry       RuntimeJournalEntry
	Environment RuntimeEnvironment
	Grants      []GuardGrant
	Identity    PermitLeaseIdentity
	Authority   *PermitLeaseAuthority
}

type RuntimeController struct {
	bgpStaged               map[uuid.UUID]bool
	bgpProcesses            map[uuid.UUID]runtimeBGPSession
	bgpCheckpointBeforeSave func(bgpengine.ProcessIdentity) error
	bgpRecover              func(bgpengine.ProcessIdentity) error
	bgpStart                func(context.Context, RuntimeJournalEntry, bgpengine.Config) (runtimeBGPSession, error)
	bgpQualification        *bgpengine.PreflightQualification
	recoveryStatusSequence  map[uuid.UUID]uint64
	recoveryReportClocks    map[uuid.UUID]runtimeRecoveryReportClock
	standbyRetries          map[uuid.UUID]runtimeStandbyRetry
	bgpRetries              map[uuid.UUID][2]runtimeBGPRetry
	recoveryInitiate        func(context.Context, EngineTunnel) error
	recoveryMetrics         RecoveryMetrics
	qualification           *RuntimePlatformQualification
	prove                   func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error
	active                  map[uuid.UUID]runtimeActive
	recoveryHistory         map[uuid.UUID]*recoveryDecision
	recoveryPrepared        map[uuid.UUID]RuntimeEnvironment
	recoveryClock           func() time.Duration
	recoveryObserve         func(context.Context, RuntimeJournalEntry) [2]string
	recoverySwitch          func(context.Context, KernelAllocation, [2]Ownership, uint8) error
	mu                      sync.Mutex
	dnsView                 atomic.Pointer[runtimeDNSOwnerView]
	dnsGuardCommit          atomic.Pointer[runtimeDNSGuardCommit]
	dnsDiagnosticAfter      atomic.Int64
	config                  RuntimeControllerConfig
	journal                 *RuntimeJournal
	guard                   *RuntimeGuard
	kernel                  *KernelApplier
	client                  RuntimeLeaseClient
	started, closed         bool
	namespace               func() (string, error)
	replace                 func(context.Context, GuardIntent) (GuardManifest, error)
}

func NewRuntimeController(cfg RuntimeControllerConfig, client RuntimeLeaseClient) (*RuntimeController, error) {
	if cfg.OrgID == uuid.Nil || cfg.GatewayID == uuid.Nil || cfg.Environment == nil || client == nil {
		return nil, ErrRuntimeController
	}
	j, e := OpenRuntimeJournal(cfg.JournalDir, cfg.GatewayID)
	if e != nil {
		return nil, ErrRuntimeController
	}
	g, e := NewRuntimeGuard(j, cfg.NFTPath)
	if e != nil {
		j.Close()
		return nil, ErrRuntimeController
	}
	k, e := NewKernelApplier(cfg.IPPath)
	if e != nil {
		j.Close()
		return nil, ErrRuntimeController
	}
	g.diagnostic = cfg.Diagnostic
	return &RuntimeController{config: cfg, journal: j, guard: g, kernel: k, client: client, namespace: func() (string, error) { return os.Readlink("/proc/self/ns/net") }, replace: g.Replace}, nil
}

// Capability advertises the natively qualified host protocol profile, not
// connection activation or transport health. Per-connection guard, policy lease
// and complete independent observations are still mandatory in Apply.
func (c *RuntimeController) Capability() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.capabilityFor(runtime.GOOS, runtime.GOARCH)
}

// Platform inputs are compile-time runtime facts at the sole production call
// site; no environment/config override can manufacture qualification.
func (c *RuntimeController) capabilityFor(goos, goarch string) int {
	if !supportedRuntimePlatform(goos, goarch) || !c.started || c.closed || c.config.Daemon == nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !c.qualification.current() {
		return 0
	}
	return 1
}
func (c *RuntimeController) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.withdrawDNSOwnerView(uuid.Nil)
	c.closed = true
	c.started = false
	c.active = nil
	c.recoveryReportClocks = nil
	failed := false
	for _, p := range c.bgpProcesses {
		failed = p.Close() != nil || failed
	}
	journalErr := c.journal.Close()
	if failed {
		return ErrRuntimeController
	}
	return journalErr
}
func (c *RuntimeController) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || ctx.Err() != nil {
		return ErrRuntimeController
	}
	if c.started {
		return nil
	}
	entries, e := c.journal.Entries()
	if e != nil {
		return ErrRuntimeController
	}
	if len(entries) > 0 {
		if _, e = c.refuse(ctx, entries); e != nil {
			return ErrRuntimeController
		}
	} else if c.guard != nil {
		// A table without durable obligations is foreign, even when its name matches.
		raw, e := c.guard.reader.run(ctx, "-j", "list", "tables")
		if e != nil {
			return ErrRuntimeController
		}
		present, e := guardTablePresent(raw)
		if e != nil || present {
			return ErrRuntimeController
		}
	}
	for _, entry := range entries {
		if entry.ContractVersion == 3 {
			ns, err := c.namespace()
			if err != nil {
				return ErrRuntimeController
			}
			if entry.Allocation.Namespace != ns {
				continue
			}
			if c.cleanupBGPDuties(ctx, entry) != nil {
				return ErrRuntimeController
			}
		}
	}
	c.started = true
	return nil
}
func (c *RuntimeController) refuse(ctx context.Context, entries []RuntimeJournalEntry) (GuardManifest, error) {
	c.withdrawDNSOwnerView(uuid.Nil)
	c.recoveryReportClocks = nil
	ns, e := c.namespace()
	if e != nil {
		return GuardManifest{}, ErrRuntimeController
	}
	_, seq, e := c.journal.guardTemplates()
	if e != nil || seq >= uint64(1<<63-1) {
		return GuardManifest{}, ErrRuntimeController
	}
	projected, retired, projectionErr := runtimeGuardProjection(entries)
	if projectionErr != nil {
		return GuardManifest{}, ErrRuntimeController
	}
	in := GuardIntent{Namespace: ns, OwnerID: c.config.GatewayID, Revision: int64(seq) + 1, RetainedLeaseIDs: retired}
	seen := map[uuid.UUID]GuardConnection{}
	for _, entry := range projected {
		if entry.Engines[0].Binding.OrgID != c.config.OrgID || entry.Engines[0].Binding.GatewayID != c.config.GatewayID {
			return GuardManifest{}, ErrRuntimeController
		}
		g := GuardConnection{BGPPeers: bgpRefusalPeers(entry), ID: entry.Allocation.ConnectionID, PrefixOnly: true, Local: entry.Engines[0].LocalPrefixes, Remote: entry.Engines[0].RemotePrefixes}
		if old, ok := seen[g.ID]; ok {
			if !reflect.DeepEqual(old, g) {
				return GuardManifest{}, ErrRuntimeController
			}
			continue
		}
		seen[g.ID] = g
		in.Connections = append(in.Connections, g)
	}
	return c.replace(ctx, in)
}
func (c *RuntimeController) Apply(ctx context.Context, m RuntimeMaterial) (ackResult RuntimeAcknowledgement, resultErr error) {
	stage := "input"
	started := time.Now()
	defer func() {
		c.emitRuntimeDiagnostic(ctx, "apply", stage, m.Manifest.ConnectionID, started, resultErr != nil)
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	fail := func() (RuntimeAcknowledgement, error) { return RuntimeAcknowledgement{}, ErrRuntimeController }
	if !c.started || c.closed || ctx.Err() != nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return fail()
	}
	stage = "qualification"
	if !c.qualification.current() {
		stage = "journal_inventory"
		entries, e := c.journal.Entries()
		if e == nil && len(entries) > 0 {
			c.withdrawDNSOwnerView(uuid.Nil)
			c.active = nil
			_, _ = c.refuse(ctx, entries)
		}
		return fail()
	}
	if !supportedRuntimePlatform(runtime.GOOS, runtime.GOARCH) {
		return fail()
	}
	ns, e := c.namespace()
	if e != nil {
		return fail()
	}
	stage = "material_contract"
	entry, grants, e := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, ns)
	if e != nil {
		return fail()
	}
	c.withdrawChangedDNSMaterial(m, grants)
	if err := c.withdrawChangedFQDNMaterial(ctx, m, grants); err != nil {
		return fail()
	}
	if !c.fqdnGrantsCurrent(grants) {
		return RuntimeAcknowledgement{}, ErrRuntimeController
	}
	if entry.ContractVersion == 3 && !c.bgpQualificationCurrent() {
		return fail()
	} // BGP transport alone never grants runtime capability.
	entries, e := c.journal.Entries()
	if e != nil {
		return fail()
	}
	// A trusted lifecycle supervisor holds this gate from before stop until the
	// exact new-runtime receipt is durable. This also prevents inode-reuse from
	// taking the ordinary same-namespace recreation path before proof arrives.
	stage = "startup_gate"
	if _, gateErr := os.Lstat(filepath.Join(c.config.JournalDir, "restoration-startup-gate")); !os.IsNotExist(gateErr) {
		c.withdrawDNSOwnerView(uuid.Nil)
		c.active = nil
		_, _ = c.refuse(ctx, entries)
		return fail()
	}
	stage = "delivery_lineage"
	pos := -1
	for i, old := range entries {
		if old.Allocation.ConnectionID != entry.Allocation.ConnectionID {
			continue
		}
		if old.DeliveryID == entry.DeliveryID {
			pos = i
			continue
		}
		if old.Phase != RuntimeRetainedRefusal || old.CleanupDesiredRevision >= m.DesiredRevision {
			return fail()
		}
	}
	// Read-only physical/census discovery precedes reservation; never accept a
	// public/NAT identity as the actual local socket address.
	stage = "environment"
	env, e := c.config.Environment.Observe(ctx, entry.Allocation, entry.Engines)
	if e != nil || env.Namespace != ns {
		return fail()
	}
	for i := range entry.Engines {
		entry.Engines[i].LocalAddress = env.Underlays[i].LocalAddress
		if env.Underlays[i].InterfaceIndex <= 0 || !validEngineTunnel(entry.Engines[i]) {
			return fail()
		}
	}
	stage = "journal_continuity"
	if pos < 0 {
		if c.admitRetainedGuardHandoff(ctx, entries, entry) != nil {
			return fail()
		}
		entries = append(entries, entry)
		pos = len(entries) - 1
		if c.journal.Save(entries) != nil {
			return fail()
		}
	} else {
		old := entries[pos]
		if entry.ContractVersion == 2 || entry.ContractVersion == 3 {
			boot, err := resetBootID()
			if err != nil {
				return fail()
			}
			resetNeeded := old.Allocation.Namespace != ns || (old.Restoration != nil && old.Restoration.BootID != boot)
			if !resetNeeded {
				// Namespace inode numbers may be reused. An exact fresh receipt
				// proves the retired runtime even when the number did not change.
				_, _, proofErr := c.restorationProof(old, boot, ns)
				resetNeeded = proofErr == nil
			}
			if resetNeeded {
				if c.reserveRestoration(ctx, m, entries, pos, entry, boot) != nil {
					return fail()
				}
				old = entries[pos]
			}
		}
		same := entry
		same.Restoration = old.Restoration
		same.Allocation.Generation = old.Allocation.Generation
		for i := range same.Allocation.Tunnels {
			same.Allocation.Tunnels[i].Alias = old.Allocation.Tunnels[i].Alias
		}
		same.Phase = old.Phase
		same.Observed = old.Observed
		if entry.ContractVersion == 3 {
			same.BGPRoutes = old.BGPRoutes
			same.BGPProcess = old.BGPProcess
			same.BGPProcessRetired = old.BGPProcessRetired
			same.BGPProcessHistory = old.BGPProcessHistory
		}
		if entry.ContractVersion == 2 {
			same.Recovery = old.Recovery
		}
		if old.Phase == RuntimeCleanupPending || old.Phase == RuntimeRetainedRefusal || !reflect.DeepEqual(old, same) {
			return fail()
		}
	}
	if entry.ContractVersion == 3 {
		stage = "bgp_apply"
		ack, err := c.applyBGP(ctx, m, entries, pos, env, grants)
		if err == nil && c.recordRuntimeBoot(ctx, entry.DeliveryID) != nil {
			c.withdrawDNSOwnerView(uuid.Nil)
			c.active = nil
			fresh, _ := c.journal.Entries()
			_, _ = c.refuse(ctx, fresh)
			for _, e := range fresh {
				if e.DeliveryID == entry.DeliveryID {
					_ = c.cleanupBGPDuties(ctx, e)
				}
			}
			return fail()
		}
		return ack, err
	}
	if entry.ContractVersion == 2 {
		stage = "static_apply"
		ack, err := c.applyRecovery(ctx, m, entries, pos, env, grants)
		if err == nil && c.recordRuntimeBoot(ctx, entry.DeliveryID) != nil {
			c.withdrawDNSOwnerView(uuid.Nil)
			c.active = nil
			_, _ = c.refuse(ctx, entries)
			return fail()
		}
		return ack, err
	}
	if c.active == nil {
		c.active = map[uuid.UUID]runtimeActive{}
	}
	prior, known := c.active[entry.Allocation.ConnectionID]
	unchanged := known && prior.Entry.DeliveryID == entry.DeliveryID && reflect.DeepEqual(prior.Environment, env)
	if unchanged && prior.Identity.PolicyHash != m.Policy.Hash {
		delete(c.active, entry.Allocation.ConnectionID)
		if c.installActive(ctx, entries) != nil {
			return fail()
		}
	}
	if !unchanged {
		delete(c.active, entry.Allocation.ConnectionID)
		if c.installActive(ctx, entries) != nil {
			return fail()
		}
		if entries[pos].Phase == RuntimeReserved {
			entries[pos].Phase = RuntimeApplying
		}
		if c.journal.Save(entries) != nil {
			return fail()
		}
		owned, e := c.kernel.Apply(ctx, entry.Allocation, entries[pos].Observed)
		if e != nil {
			return fail()
		}
		entries[pos].Observed = owned
		if c.journal.Save(entries) != nil {
			return fail()
		}
		for i, t := range entry.Engines {
			if c.config.Daemon.removeTunnel(ctx, t) != nil {
				return fail()
			}
			secret := []byte(m.Secrets[i].PSK)
			e = c.config.Daemon.stageTunnel(ctx, t, secret)
			for j := range secret {
				secret[j] = 0
			}
			if e != nil {
				return fail()
			}
		}
	}
	authority := NewPermitLeaseAuthority()
	identity := PermitLeaseIdentity{PolicyHash: m.Policy.Hash, Binding: entry.Engines[0].Binding, DeliveryID: entry.DeliveryID}
	request, e := authority.Begin(identity)
	if e != nil {
		return fail()
	}
	lease, e := c.client.RenewIPsecLease(ctx, entry.Allocation.ConnectionID, RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, PolicyHash: m.Policy.Hash, Nonce: request.Nonce})
	if e != nil || lease.DeliveryID != m.ID || lease.DesiredRevision != m.DesiredRevision || lease.PolicyHash != m.Policy.Hash || lease.Nonce != request.Nonce || authority.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: lease.TTLMS}) != nil {
		return fail()
	}
	if !unchanged {
		for _, t := range entry.Engines {
			if c.config.Daemon.initiateTunnel(ctx, t) != nil {
				return fail()
			}
		}
	}
	// Both tunnel observations are required; selection remains explicit slot 1.
	if e = c.proveCurrent(ctx, entries[pos], env); e != nil {
		delete(c.active, entry.Allocation.ConnectionID)
		_ = c.installActive(ctx, entries)
		return fail()
	}
	if _, err := c.ensureUnderlayMTUs(ctx, entries[pos], env, entries); err != nil {
		return fail()
	}
	c.active[entry.Allocation.ConnectionID] = runtimeActive{Entry: entries[pos], Environment: env, Grants: grants, Identity: identity, Authority: authority}
	if c.installActive(ctx, entries) != nil {
		delete(c.active, entry.Allocation.ConnectionID)
		_, _ = c.refuse(ctx, entries)
		return fail()
	}
	if _, ok := c.active[entry.Allocation.ConnectionID]; !ok {
		return fail()
	}
	entries[pos].Phase = RuntimeApplied
	if c.journal.Save(entries) != nil {
		_, _ = c.refuse(ctx, entries)
		return fail()
	}
	return RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}, nil
}

func (c *RuntimeController) Cleanup(ctx context.Context, cleanup RuntimeCleanup) (RuntimeAcknowledgement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fail := func() (RuntimeAcknowledgement, error) { return RuntimeAcknowledgement{}, ErrRuntimeController }
	if !c.started || c.closed || ctx.Err() != nil || !cleanup.RetainGuard || !runtimeCleanupValid(cleanup, c.config.OrgID, c.config.GatewayID) || cleanup.CoversDeliveryRevision <= 0 || cleanup.CoversDeliveryRevision >= cleanup.DesiredRevision || len(cleanup.Lineage) == 0 || len(cleanup.Lineage) > 256 {
		return fail()
	}
	c.withdrawDNSOwnerView(cleanup.Manifest.ConnectionID)
	entries, e := c.journal.Entries()
	if e != nil {
		return fail()
	}
	lineage := map[uuid.UUID]RuntimeDelivery{}
	for _, d := range cleanup.Lineage {
		if !runtimeDeliveryValid(d, c.config.OrgID, c.config.GatewayID, "apply") || d.Manifest.ConnectionID != cleanup.Manifest.ConnectionID || d.DesiredRevision > cleanup.CoversDeliveryRevision {
			return fail()
		}
		if _, ok := lineage[d.ID]; ok {
			return fail()
		}
		lineage[d.ID] = d
	}
	// A CP checkpoint may have committed while its response was lost before
	// this node reserved anything. Persist its denial obligation, but never
	// promote that manifest into permission to adopt or remove matching objects.
	known := map[uuid.UUID]bool{}
	for _, entry := range entries {
		known[entry.DeliveryID] = true
	}
	for _, d := range cleanup.Lineage {
		if known[d.ID] {
			continue
		}
		ns, e := c.namespace()
		if e != nil {
			return fail()
		}
		entry, _, e := runtimeBuildEntry(RuntimeMaterial{RuntimeDelivery: d}, c.config.OrgID, c.config.GatewayID, ns, false)
		if e != nil {
			return fail()
		}
		entry.AbsenceOnly = true
		entries = append(entries, entry)
	}
	if c.journal.Save(entries) != nil {
		return fail()
	}
	positions := []int{}
	covered := []RuntimeJournalEntry{}
	for i, entry := range entries {
		if entry.Allocation.ConnectionID != cleanup.Manifest.ConnectionID {
			continue
		}
		d, ok := lineage[entry.DeliveryID]
		if !ok || d.OwnershipDigest != entry.OwnershipDigest || d.DesiredRevision != entry.Engines[0].Binding.DesiredRevision {
			return fail()
		}
		delete(lineage, entry.DeliveryID)
		if entry.Phase == RuntimeRetainedRefusal {
			if entry.CleanupDesiredRevision > cleanup.DesiredRevision || (entry.CleanupDesiredRevision == cleanup.DesiredRevision && entry.CleanupID != cleanup.ID) {
				return fail()
			}
			positions = append(positions, i)
			covered = append(covered, entry)
			continue
		}
		entry.Phase = RuntimeCleanupPending
		entry.CleanupID = cleanup.ID
		entry.CleanupDesiredRevision = cleanup.DesiredRevision
		entry.CoveredDeliveryRevision = cleanup.CoversDeliveryRevision
		entries[i] = entry
		positions = append(positions, i)
		covered = append(covered, entry)
	}
	// Missing lineage cannot be adopted from a name. Recovery needs its persisted
	// ownership or a separately qualified exact orphan recovery path.
	if len(lineage) != 0 || len(positions) == 0 || c.journal.Save(entries) != nil {
		return fail()
	}
	delete(c.recoveryHistory, cleanup.Manifest.ConnectionID)
	delete(c.recoveryReportClocks, cleanup.Manifest.ConnectionID)
	delete(c.active, cleanup.Manifest.ConnectionID)
	if e = c.installActive(ctx, entries); e != nil {
		return fail()
	}
	if c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return fail()
	}
	currentNamespace, e := c.namespace()
	if e != nil {
		return fail()
	}
	var resetProof *RuntimeResetCleanup
	for _, entry := range covered {
		if entry.Phase != RuntimeRetainedRefusal && entry.Allocation.Namespace != currentNamespace {
			resetProof, e = c.resetCleanupReceipt(cleanup, covered)
			if e != nil {
				return fail()
			}
			break
		}
	}
	// Reserve the supervisor receipt durably before any reset cleanup. The
	// previous allocation is never rewritten to match today's namespace.
	if resetProof != nil {
		for n, i := range positions {
			if covered[n].Phase == RuntimeRetainedRefusal || covered[n].Allocation.Namespace == currentNamespace {
				continue
			}
			if entries[i].ResetCleanup != nil && *entries[i].ResetCleanup != *resetProof {
				return fail()
			}
			entries[i].ResetCleanup = resetProof
			covered[n].ResetCleanup = resetProof
		}
		if c.journal.Save(entries) != nil {
			return fail()
		}
	}
	drainEntries := make([]RuntimeJournalEntry, 0, len(covered))
	for _, entry := range covered {
		if entry.Phase == RuntimeRetainedRefusal {
			continue
		}
		if entry.Allocation.Namespace != currentNamespace {
			if c.proveResetAbsent(ctx, entry, resetProof) != nil {
				return fail()
			}
			projected := entry
			projected.Allocation.Namespace = currentNamespace
			drainEntries = append(drainEntries, projected)
			// Never remove a daemon object by an old name in the new runtime.
			continue
		}
		drainEntries = append(drainEntries, entry)
		if entry.AbsenceOnly {
			if c.proveAbsent(ctx, entry) != nil {
				return fail()
			}
			continue
		}
		if entry.ContractVersion == 3 {
			if c.cleanupBGPDuties(ctx, entry) != nil {
				return fail()
			}
			refreshed, err := c.journal.Entries()
			if err != nil {
				return fail()
			}
			for _, updated := range refreshed {
				if updated.DeliveryID == entry.DeliveryID {
					for i := range entries {
						if entries[i].DeliveryID == entry.DeliveryID {
							entries[i] = updated
						}
					}
				}
			}
		}
		for _, t := range entry.Engines {
			if c.config.Daemon.removeTunnel(ctx, t) != nil {
				return fail()
			}
		}
		if entry.ContractVersion == 2 {
			if c.kernel.RemoveRecovery(ctx, entry.Allocation, entry.Observed) != nil {
				return fail()
			}
		} else if _, e = c.kernel.Remove(ctx, entry.Allocation, entry.Observed); e != nil {
			return fail()
		}
	}
	if len(drainEntries) > 0 && c.config.Environment.Drain(ctx, drainEntries) != nil {
		return fail()
	}
	if resetProof != nil {
		for _, entry := range covered {
			if entry.Phase != RuntimeRetainedRefusal && entry.Allocation.Namespace != currentNamespace && c.proveResetAbsent(ctx, entry, resetProof) != nil {
				return fail()
			}
		}
	}
	delete(c.recoveryHistory, cleanup.Manifest.ConnectionID)
	delete(c.recoveryReportClocks, cleanup.Manifest.ConnectionID)
	delete(c.active, cleanup.Manifest.ConnectionID)
	if e = c.installActive(ctx, entries); e != nil {
		return fail()
	}
	for _, i := range positions {
		entries[i].Phase = RuntimeRetainedRefusal
	}
	if c.journal.Save(entries) != nil {
		return fail()
	}
	return RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: cleanup.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}, nil
}

// installActive rebuilds one combined table from process-local live authority.
// Other connections keep only their original remaining deadlines; neither a
// journal template nor this replacement renews their authority.
func (c *RuntimeController) installActive(ctx context.Context, entries []RuntimeJournalEntry) error {
	return c.installActiveCandidates(ctx, entries, c.active, nil, nil, nil)
}

// installActiveCandidates uses the original collection and atomic commit. A
// maintenance overlay remains owner-private until every required candidate
// survives the complete native proof and final lease checks.
func (c *RuntimeController) installActiveCandidates(ctx context.Context, entries []RuntimeJournalEntry, active map[uuid.UUID]runtimeActive, required map[uuid.UUID]runtimeActive, prior map[uuid.UUID]runtimeActive, candidateQualification func() bool) (resultErr error) {
	c.reconcileDNSOwnerView()
	stage := "input"
	connection := uuid.Nil
	started := time.Now()
	defer func() { c.emitRuntimeDiagnostic(ctx, "install_active", stage, connection, started, resultErr != nil) }()
	ns, e := c.namespace()
	if e != nil {
		return ErrRuntimeController
	}
	if !c.qualification.current() {
		c.withdrawDNSOwnerView(uuid.Nil)
		active = nil
		c.active = nil
	}
	for id, a := range active {
		connection = id
		stage = "entry_current_proof"
		proofStarted := time.Now()
		proofCtx, proofCancel := context.WithTimeout(ctx, 5*time.Second)
		proofErr := c.proveCurrent(proofCtx, a.Entry, a.Environment)
		c.emitRuntimeDiagnostic(proofCtx, "install_active", stage, id, proofStarted, a.Entry.Allocation.Namespace != ns || proofErr != nil)
		proofCancel()
		if a.Entry.Allocation.Namespace != ns || proofErr != nil || !c.fqdnGrantsCurrent(a.Grants) {
			c.withdrawDNSOwnerView(id)
			delete(active, id)
			continue
		}
		stage = "entry_lease_remaining"
		leaseStarted := time.Now()
		_, e = a.Authority.RemainingForApply(a.Identity, 5*time.Second)
		c.emitRuntimeDiagnostic(ctx, "install_active", stage, id, leaseStarted, e != nil)
		if e != nil {
			c.withdrawDNSOwnerView(id)
			delete(active, id)
		}
	}
	connection = uuid.Nil
	stage = "journal_inventory"
	_, seq, e := c.journal.guardTemplates()
	if e != nil || seq >= uint64(1<<63-1) {
		return ErrRuntimeController
	}
	stage = "guard_projection"
	projected, retired, projectionErr := runtimeGuardProjection(entries)
	if projectionErr != nil {
		return ErrRuntimeController
	}
	intent := GuardIntent{Namespace: ns, OwnerID: c.config.GatewayID, Revision: int64(seq) + 1, RetainedLeaseIDs: retired}
	seen := map[uuid.UUID]bool{}
	for _, entry := range projected {
		id := entry.Allocation.ConnectionID
		connection = id
		if seen[id] {
			continue
		}
		seen[id] = true
		g := GuardConnection{BGPPeers: bgpRefusalPeers(entry), ID: id, PrefixOnly: true, Local: entry.Engines[0].LocalPrefixes, Remote: entry.Engines[0].RemotePrefixes}
		if a, ok := active[id]; ok {
			assemblyCtx, assemblyCancel := context.WithTimeout(ctx, 5*time.Second)
			defer assemblyCancel()
			stage = "entry_lease_remaining"
			remaining, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second)
			if assemblyCtx.Err() != nil {
				return ErrRuntimeController
			}
			if err != nil {
				c.withdrawDNSOwnerView(id)
				delete(active, id)
			} else {
				if a.Entry.ContractVersion == 3 {
					observeCtx, observeCancel := context.WithTimeout(assemblyCtx, 5*time.Second)
					stage = "entry_bgp_observation"
					if _, candidate := required[id]; candidate {
						g, err = c.maintenanceBGPGuard(observeCtx, a, prior[id], remaining, candidateQualification)
					} else {
						g, err = c.bgpGuard(observeCtx, a, remaining)
					}
					observeCancel()
					if err != nil {
						c.withdrawDNSOwnerView(id)
						delete(active, id)
						_, _ = c.refuse(ctx, entries)
						return ErrRuntimeController
					}
					intent.Connections = append(intent.Connections, g)
					continue
				}
				g.PrefixOnly = false
				g.Tunnels = a.Entry.Observed
				g.Grants = a.Grants
				g.LocalIngressIndices = a.Environment.LocalIngressIndices
				g.PermitFor = remaining
				slot := selectedRuntimeSlot(a.Entry)
				if slot == 0 {
					return ErrRuntimeController
				}
				index := int(slot) - 1
				g.PermittedInterfaceIndices = []int{a.Entry.Observed[index].InterfaceIndex}
				observeCtx, observeCancel := context.WithTimeout(assemblyCtx, 5*time.Second)
				stage = "entry_static_observation"
				statuses := c.observeRecovery(observeCtx, a.Entry)
				observeCancel()
				// The installation observation can disagree with the earlier recovery
				// decision. Withdraw existing authority before returning; empty reply
				// observations must never fall back to selected-path permission.
				if statuses[index] != "up" || (statuses[1-index] != "up" && statuses[1-index] != "down") {
					c.withdrawDNSOwnerView(id)
					delete(active, id)
					_, _ = c.refuse(ctx, entries)
					return ErrRuntimeController
				}
				stage = "entry_lease_remaining"
				remaining, err = a.Authority.RemainingForApply(a.Identity, 5*time.Second)
				if err != nil {
					return ErrRuntimeController
				}
				g.PermitFor = remaining
				for i, status := range statuses {
					if status == "up" {
						g.ReplyIngressIndices = append(g.ReplyIngressIndices, a.Entry.Observed[i].InterfaceIndex)
					}
				}
				g.EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: a.Entry.Observed[index].InterfaceIndex, ReqID: a.Entry.Engines[index].ReqID, Peer: a.Entry.Engines[index].RemoteAddress, UnderlayInterfaceIndex: a.Environment.Underlays[index].InterfaceIndex}}
				if len(g.Grants) > 0 {
					mtuCtx, mtuCancel := context.WithTimeout(assemblyCtx, 5*time.Second)
					stage = "entry_tunnel_mtu"
					g.TunnelMTUs, err = c.guardTunnelMTUs(mtuCtx, a.Entry, a.Environment, g.PermittedInterfaceIndices, g.ReplyIngressIndices)
					mtuCancel()
					if err != nil {
						c.withdrawDNSOwnerView(id)
						delete(active, id)
						_, _ = c.refuse(ctx, entries)
						return ErrRuntimeController
					}
				}
			}
		}
		intent.Connections = append(intent.Connections, g)
	}
	connection = uuid.Nil
	stage = "combined_guard_context"
	if ctx.Err() != nil {
		_, _ = c.refuse(ctx, entries)
		return ErrRuntimeController
	}
	commitCtx, commitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer commitCancel()
	// Native collection does not consume the atomic replacement budget. Never
	// install a duration captured before another connection's observations.
	for i := range intent.Connections {
		g := &intent.Connections[i]
		connection = g.ID
		stage = "combined_guard_authority"
		if g.PrefixOnly {
			continue
		}
		a, ok := active[g.ID]
		if !ok {
			_, _ = c.refuse(ctx, entries)
			return ErrRuntimeController
		}
		if !c.fqdnGrantsCurrent(a.Grants) {
			c.withdrawDNSOwnerView(g.ID)
			delete(active, g.ID)
			_, _ = c.refuse(ctx, entries)
			return ErrRuntimeController
		}
		stage = "entry_dns_source"
		for _, grant := range g.Grants {
			if grant.DNSResolver != (DNSResolverBinding{}) {
				if _, err := observeDNSSource(grant.Source.Addr(), a.Environment.LocalIngressIndices); err != nil {
					c.withdrawDNSOwnerView(g.ID)
					delete(active, g.ID)
					_, _ = c.refuse(ctx, entries)
					return ErrRuntimeController
				}
			}
		}
		remaining, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second)
		if err != nil {
			c.withdrawDNSOwnerView(g.ID)
			delete(active, g.ID)
			_, _ = c.refuse(ctx, entries)
			return ErrRuntimeController
		}
		g.PermitFor = remaining
	}
	connection = uuid.Nil
	stage = "combined_guard_qualification"
	if len(active) > 0 && (!c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive()) {
		_, _ = c.refuse(ctx, entries)
		return ErrRuntimeController
	}
	for _, g := range intent.Connections {
		if g.PrefixOnly {
			continue
		}
		connection = g.ID
		stage = "entry_bgp_process"
		a := active[g.ID]
		if a.Entry.ContractVersion == 3 && len(g.Grants) > 0 {
			process := c.bgpProcesses[a.Entry.DeliveryID]
			if process == nil || !process.Alive() {
				c.withdrawDNSOwnerView(g.ID)
				delete(active, g.ID)
				_, _ = c.refuse(ctx, entries)
				return ErrRuntimeController
			}
		}
	}
	connection = uuid.Nil
	stage = "combined_guard_context"
	if commitCtx.Err() != nil {
		_, _ = c.refuse(ctx, entries)
		return ErrRuntimeController
	}
	for id, candidate := range required {
		connection = id
		stage = "combined_guard_required_binding"
		current, ok := active[id]
		if !ok || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) {
			return ErrRuntimeController
		}
	}
	for id := range required {
		connection = id
		stage = "combined_guard_prior_binding"
		original, ok := prior[id]
		if !ok || original.Authority == nil {
			return ErrRuntimeController
		}
		stage = "combined_guard_prior_reserve"
		if _, err := original.Authority.RemainingForApply(original.Identity, 5*time.Second); err != nil {
			return ErrRuntimeController
		}
	}
	connection = uuid.Nil
	stage = "combined_guard_candidate_qualification"
	if candidateQualification != nil && !candidateQualification() {
		return ErrRuntimeController
	}
	stage = "combined_guard_replace"
	// A native replacement can precede its immutable DNS publication. This
	// token conveys only an in-flight owner commit, never packet authority.
	guardCommit := c.beginDNSGuardCommit()
	if guardCommit == nil {
		return ErrRuntimeController
	}
	defer c.finishDNSGuardCommit(guardCommit)
	manifest, replaceErr := c.replace(commitCtx, intent)
	if replaceErr != nil {
		return ErrRuntimeController
	}
	stage = "combined_guard_final_binding"
	if len(active) > 0 && !c.qualification.current() {
		c.withdrawDNSOwnerView(uuid.Nil)
		active = nil
		c.active = nil
		_, _ = c.refuse(ctx, entries)
		return ErrRuntimeController
	}
	for id, a := range active {
		connection = id
		stage = "combined_guard_final_lease"
		if !c.fqdnGrantsCurrent(a.Grants) {
			_, _ = c.refuse(ctx, entries)
			return ErrRuntimeController
		}
		if _, e = a.Authority.RemainingForApply(a.Identity, time.Millisecond); e != nil {
			_, _ = c.refuse(ctx, entries)
			return ErrRuntimeController
		}
	}
	for id, candidate := range required {
		connection = id
		stage = "combined_guard_required_binding"
		current, ok := active[id]
		if !ok || current.Authority != candidate.Authority || !reflect.DeepEqual(current, candidate) {
			return ErrRuntimeController
		}
	}
	for id := range required {
		connection = id
		stage = "combined_guard_final_prior_reserve"
		original := prior[id]
		if _, err := original.Authority.RemainingForApply(original.Identity, time.Millisecond); err != nil {
			return ErrRuntimeController
		}
	}
	connection = uuid.Nil
	stage = "combined_guard_candidate_qualification"
	if candidateQualification != nil && !candidateQualification() {
		return ErrRuntimeController
	}
	c.active = active
	c.publishDNSOwnerView(manifest)
	guardCommit.published = c.dnsView.Load()
	return nil
}

// AttachDaemon is separate from Start so durable refusal is restored before a
// stale daemon artifact or supervisor startup failure can stop recovery.
func (c *RuntimeController) AttachDaemon(client *DaemonClient, alive func() bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.started || client == nil || alive == nil || !alive() || c.config.Daemon != nil {
		return ErrRuntimeController
	}
	c.config.Daemon = client
	c.config.DaemonAlive = alive
	return nil
}

func (c *RuntimeController) proveCurrent(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
	if c.prove != nil {
		return c.prove(ctx, e, env)
	}
	if e.ContractVersion == 3 {
		return c.proveBGPCurrent(ctx, e, env)
	}
	return c.proveRuntime(ctx, e, env)
}

// AttachQualification adds independently observed process/platform facts. It is
// necessary but not sufficient for production capability, and cannot be renewed
// after discontinuity without restarting the controller and restoring refusal.
func (c *RuntimeController) AttachQualification(q *RuntimePlatformQualification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.started || c.qualification != nil || !q.current() {
		return ErrRuntimeController
	}
	ns, e := c.namespace()
	if e != nil || ns != q.namespace {
		return ErrRuntimeController
	}
	c.qualification = q
	return nil
}

func supportedRuntimePlatform(goos, goarch string) bool {
	return goos == "linux" && (goarch == "arm64" || goarch == "amd64")
}

// Validate runs even when the CP has no pending work or is unreachable. It may
// withdraw authority and preserve its existing deadline, but never renew it.
func (c *RuntimeController) Validate(ctx context.Context) (resultErr error) {
	stage := "input"
	started := time.Now()
	defer func() { c.emitRuntimeDiagnostic(ctx, "validate", stage, uuid.Nil, started, resultErr != nil) }()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.started || ctx.Err() != nil {
		return ErrRuntimeController
	}
	stage = "journal_inventory"
	entries, e := c.journal.Entries()
	if e != nil {
		c.withdrawDNSOwnerView(uuid.Nil)
		c.active = nil
		return ErrRuntimeController
	}
	stage = "qualification"
	if !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		c.withdrawDNSOwnerView(uuid.Nil)
		c.active = nil
		if len(entries) > 0 {
			if _, err := c.refuse(ctx, entries); err != nil {
				return ErrRuntimeController
			}
			for _, entry := range entries {
				if entry.ContractVersion == 3 {
					if c.cleanupBGPDuties(ctx, entry) != nil {
						return ErrRuntimeController
					}
				}
			}
		}
		return ErrRuntimeController
	}
	if len(entries) == 0 {
		return nil
	}
	stage = "bgp_qualification"
	if !c.bgpQualificationCurrent() {
		var staleBGP []RuntimeJournalEntry
		for _, entry := range entries {
			if entry.ContractVersion == 3 {
				staleBGP = append(staleBGP, entry)
			}
		}
		for connection, active := range c.active {
			if active.Entry.ContractVersion == 3 {
				c.withdrawDNSOwnerView(connection)
				delete(c.active, connection)
			}
		}
		if len(staleBGP) > 0 {
			// Preserve qualified static grants, but prove BGP denial before
			// stopping exports or consuming exact owned route obligations.
			if c.installActive(ctx, entries) != nil {
				return ErrRuntimeController
			}
			refused := false
			for _, entry := range staleBGP {
				if c.cleanupBGPDuties(ctx, entry) != nil {
					refused = true
				}
			}
			if refused {
				return ErrRuntimeController
			}
			return ErrRuntimeController
		}
	}
	stage = "bgp_reconcile"
	if c.reconcileActiveBGP(ctx, entries) != nil {
		return ErrRuntimeController
	}
	entries, e = c.journal.Entries()
	if e != nil {
		return e
	}
	stage = "combined_guard"
	return c.installActive(ctx, entries)
}
