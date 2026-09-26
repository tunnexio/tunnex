package ipsec

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"
)

var ErrRuntimeController = errors.New("IPsec runtime operation refused")

type RuntimeUnderlay struct {
	InterfaceIndex int
	LocalAddress   netip.Addr
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
	OrgID, GatewayID            uuid.UUID
	JournalDir, IPPath, NFTPath string
	Daemon                      *DaemonClient
	DaemonAlive                 func() bool
	Environment                 RuntimeEnvironmentInspector
}
type runtimeActive struct {
	Entry       RuntimeJournalEntry
	Environment RuntimeEnvironment
	Grants      []GuardGrant
	Identity    PermitLeaseIdentity
	Authority   *PermitLeaseAuthority
}

type RuntimeController struct {
	standbyRetries   map[uuid.UUID]runtimeStandbyRetry
	recoveryInitiate func(context.Context, EngineTunnel) error
	recoveryMetrics  RecoveryMetrics
	qualification    *RuntimePlatformQualification
	prove            func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error
	active           map[uuid.UUID]runtimeActive
	recoveryHistory  map[uuid.UUID]*recoveryDecision
	recoveryPrepared map[uuid.UUID]RuntimeEnvironment
	recoveryClock    func() time.Duration
	recoveryObserve  func(context.Context, RuntimeJournalEntry) [2]string
	recoverySwitch   func(context.Context, KernelAllocation, [2]Ownership, uint8) error
	mu               sync.Mutex
	config           RuntimeControllerConfig
	journal          *RuntimeJournal
	guard            *RuntimeGuard
	kernel           *KernelApplier
	client           RuntimeLeaseClient
	started, closed  bool
	namespace        func() (string, error)
	replace          func(context.Context, GuardIntent) (GuardManifest, error)
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
	c.closed = true
	c.started = false
	c.active = nil
	return c.journal.Close()
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
	c.started = true
	return nil
}
func (c *RuntimeController) refuse(ctx context.Context, entries []RuntimeJournalEntry) (GuardManifest, error) {
	ns, e := c.namespace()
	if e != nil {
		return GuardManifest{}, ErrRuntimeController
	}
	_, seq, e := c.journal.guardTemplates()
	if e != nil || seq >= uint64(1<<63-1) {
		return GuardManifest{}, ErrRuntimeController
	}
	in := GuardIntent{Namespace: ns, OwnerID: c.config.GatewayID, Revision: int64(seq) + 1}
	seen := map[uuid.UUID]GuardConnection{}
	for _, entry := range entries {
		if entry.Engines[0].Binding.OrgID != c.config.OrgID || entry.Engines[0].Binding.GatewayID != c.config.GatewayID {
			return GuardManifest{}, ErrRuntimeController
		}
		g := GuardConnection{ID: entry.Allocation.ConnectionID, PrefixOnly: true, Local: entry.Engines[0].LocalPrefixes, Remote: entry.Engines[0].RemotePrefixes}
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
func (c *RuntimeController) Apply(ctx context.Context, m RuntimeMaterial) (RuntimeAcknowledgement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fail := func() (RuntimeAcknowledgement, error) { return RuntimeAcknowledgement{}, ErrRuntimeController }
	if !c.started || c.closed || ctx.Err() != nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return fail()
	}
	if !c.qualification.current() {
		entries, e := c.journal.Entries()
		if e == nil && len(entries) > 0 {
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
	entry, grants, e := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, ns)
	if e != nil {
		return fail()
	}
	entries, e := c.journal.Entries()
	if e != nil {
		return fail()
	}
	// A trusted lifecycle supervisor holds this gate from before stop until the
	// exact new-runtime receipt is durable. This also prevents inode-reuse from
	// taking the ordinary same-namespace recreation path before proof arrives.
	if _, gateErr := os.Lstat(filepath.Join(c.config.JournalDir, "restoration-startup-gate")); !os.IsNotExist(gateErr) {
		c.active = nil
		_, _ = c.refuse(ctx, entries)
		return fail()
	}
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
	if pos < 0 {
		entries = append(entries, entry)
		pos = len(entries) - 1
		if c.journal.Save(entries) != nil {
			return fail()
		}
	} else {
		old := entries[pos]
		if entry.ContractVersion == 2 {
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
		if entry.ContractVersion == 2 {
			same.Recovery = old.Recovery
		}
		if old.Phase == RuntimeCleanupPending || old.Phase == RuntimeRetainedRefusal || !reflect.DeepEqual(old, same) {
			return fail()
		}
	}
	if entry.ContractVersion == 2 {
		ack, err := c.applyRecovery(ctx, m, entries, pos, env, grants)
		if err == nil && c.recordRuntimeBoot(ctx, entry.DeliveryID) != nil {
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
	ns, e := c.namespace()
	if e != nil {
		return ErrRuntimeController
	}
	if !c.qualification.current() {
		c.active = nil
	}
	for id, a := range c.active {
		if a.Entry.Allocation.Namespace != ns || c.proveCurrent(ctx, a.Entry, a.Environment) != nil {
			delete(c.active, id)
			continue
		}
		if _, e = a.Authority.RemainingForApply(a.Identity, 5*time.Second); e != nil {
			delete(c.active, id)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, seq, e := c.journal.guardTemplates()
	if e != nil || seq >= uint64(1<<63-1) {
		return ErrRuntimeController
	}
	intent := GuardIntent{Namespace: ns, OwnerID: c.config.GatewayID, Revision: int64(seq) + 1}
	seen := map[uuid.UUID]bool{}
	for _, entry := range entries {
		id := entry.Allocation.ConnectionID
		if seen[id] {
			continue
		}
		seen[id] = true
		g := GuardConnection{ID: id, PrefixOnly: true, Local: entry.Engines[0].LocalPrefixes, Remote: entry.Engines[0].RemotePrefixes}
		if a, ok := c.active[id]; ok {
			remaining, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second)
			if err != nil {
				delete(c.active, id)
			} else {
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
				statuses := c.observeRecovery(ctx, a.Entry)
				// The installation observation can disagree with the earlier recovery
				// decision. Withdraw existing authority before returning; empty reply
				// observations must never fall back to selected-path permission.
				if statuses[index] != "up" || (statuses[1-index] != "up" && statuses[1-index] != "down") {
					delete(c.active, id)
					_, _ = c.refuse(ctx, entries)
					return ErrRuntimeController
				}
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
			}
		}
		intent.Connections = append(intent.Connections, g)
	}
	if ctx.Err() != nil {
		return ErrRuntimeController
	}
	if _, e = c.replace(ctx, intent); e != nil {
		return ErrRuntimeController
	}
	if len(c.active) > 0 && !c.qualification.current() {
		c.active = nil
		_, _ = c.refuse(ctx, entries)
		return ErrRuntimeController
	}
	for _, a := range c.active {
		if _, e = a.Authority.RemainingForApply(a.Identity, time.Millisecond); e != nil {
			_, _ = c.refuse(ctx, entries)
			return ErrRuntimeController
		}
	}
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
func (c *RuntimeController) Validate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.started || ctx.Err() != nil {
		return ErrRuntimeController
	}
	entries, e := c.journal.Entries()
	if e != nil {
		c.active = nil
		return ErrRuntimeController
	}
	if !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		c.active = nil
		if len(entries) > 0 {
			_, _ = c.refuse(ctx, entries)
		}
		return ErrRuntimeController
	}
	if len(entries) == 0 {
		return nil
	}
	return c.installActive(ctx, entries)
}
