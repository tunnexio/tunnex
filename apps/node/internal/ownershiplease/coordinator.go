package ownershiplease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

var (
	ErrDomainReadbackMismatch       = errors.New("ownership full-domain readback mismatch")
	ErrProductionAdapterUnavailable = errors.New("ownership production adapter unavailable")
)

// Stage names the existing owner that must converge one projection of the same
// full DesiredState. Implementations must not create a second OS writer.
type Stage string

const (
	StageDNS       Stage = "dns"
	StageDNAT      Stage = "dnat"
	StageOVPN      Stage = "ovpn"
	StageRoutes    Stage = "routes"
	StageWireGuard Stage = "wireguard"
)

var activationOrder = []Stage{StageDNS, StageDNAT, StageOVPN, StageRoutes, StageWireGuard}
var withdrawalOrder = []Stage{StageWireGuard, StageRoutes, StageOVPN, StageDNAT, StageDNS}

// WGAppliedPeer is the readback projection needed from the existing WireGuard
// owner. Endpoint and roaming metadata are deliberately outside ownership.
type WGAppliedPeer struct {
	PublicKey  string
	AllowedIPs []string
}

type K8sDNSAnswer struct {
	Name string
	VIP  string
}

// OVPNDerivedState is the exact config derived by the current main wiring. It
// is included in readback because Kubernetes VIP and DNS routes are pushed to
// OpenVPN clients too.
type OVPNDerivedState struct {
	Enabled              bool
	Serving              bool
	PoolCIDR             string
	ServerMaterialDigest string
	Clients              []reconcile.OVPNClient
	Routes               []string
	DNS                  []string
}

// AppliedDomainState is actual state read from the current owners after all
// stages run. Returning a cached desired-state echo violates this contract.
type AppliedDomainState struct {
	WGPeers      []WGAppliedPeer
	Routes       []string
	ReturnRules  []reconcile.ReturnRule
	VIPMappings  []nodepolicy.VIPMapping
	DNSZones     []nodepolicy.K8sDNSZone
	DNSAnswers   []K8sDNSAnswer
	DNSVIPs      []string
	DNSListeners []string
	OVPN         OVPNDerivedState
}

// DomainSurface adapts the current WG, route, egress, dnsforward, and OVPN
// owners. ApplyStage always receives the same cloned full state; Readback must
// observe what is actually active after those owners finish.
type DomainSurface interface {
	ApplyStage(ctx context.Context, stage Stage, desired reconcile.DesiredState) error
	Readback(ctx context.Context) (AppliedDomainState, error)
}

type EmergencyDomainSurface interface {
	EmergencyWithdraw(context.Context, []PoolFence) error
}

type desiredStateObserver interface {
	ObserveDesired(reconcile.DesiredState)
}

// Coordinator is the one serialized v3 full-domain apply/readback point. It is
// intentionally not wired into main until every existing owner exposes the
// typed readback needed by DomainSurface.
type Coordinator struct {
	mu        sync.Mutex
	projector *Projector
	domain    DomainSurface
	store     FenceStore
	authority BaseAuthorityStateStore
	loaded    bool
	fences    []PoolFence
}

func NewCoordinator(projector *Projector, domain DomainSurface, store FenceStore) *Coordinator {
	return &Coordinator{projector: projector, domain: domain, store: store}
}

func (c *Coordinator) WithBaseAuthorityStateStore(store BaseAuthorityStateStore) *Coordinator {
	if c != nil {
		c.authority = store
	}
	return c
}

// UpdateBase installs the latest ordinary state. Explicit unfences are made
// durable before the newly-unfenced base can become visible.
func (c *Coordinator) UpdateBase(ctx context.Context, base reconcile.DesiredState, authority BaseAuthority) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.configured(); err != nil {
		return err
	}
	if err := c.ensureLoaded(ctx); err != nil {
		return err
	}
	next := append([]PoolFence(nil), c.fences...)
	baseHash, err := BaseStateHash(base)
	if err != nil {
		return err
	}
	var authorityFingerprint string
	if authority.Present || authority.WireVersion != 0 || authority.AuthorityRevision != 0 {
		var err error
		authority, authorityFingerprint, err = canonicalBaseAuthority(base, authority)
		if err != nil {
			return err
		}
	}
	byPool := make(map[string]PoolClassification, len(authority.Classifications))
	unfencedByPool := make(map[string]PoolScope, len(authority.UnfencedPools))
	for _, scope := range authority.UnfencedPools {
		unfencedByPool[scope.PoolID] = scope
	}
	for _, classification := range authority.Classifications {
		fields := classification.Fields
		if reflect.DeepEqual(fields, PoolOwnedBaseFields{}) && !reflect.DeepEqual(classification.Ownership, EffectiveOwnership{}) {
			legacy, err := fenceFor(classification.Ownership)
			if err != nil || legacy.Scope != classification.Scope {
				return fmt.Errorf("invalid scope-complete pool classification")
			}
			fields = legacy.Suppressed
			classification.Fields = fields
			if classification.Disposition == "" {
				classification.Disposition = PoolClassificationMaintainFence
			}
		}
		if _, err := fenceForClassification(classification.Scope, fields); err != nil {
			return fmt.Errorf("invalid scope-complete pool classification")
		}
		if _, duplicate := byPool[classification.Scope.PoolID]; duplicate {
			return fmt.Errorf("duplicate pool classification")
		}
		byPool[classification.Scope.PoolID] = classification
	}
	for poolID, classification := range byPool {
		if classification.Disposition != PoolClassificationMaintainFence {
			continue
		}
		found := false
		for _, fence := range next {
			if fence.Scope.PoolID == poolID && fence.ReleasedAtBaseVersion == 0 {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("maintain_fence classification requires an armed pool")
		}
	}
	// arm_fence may create a durable standby tombstone without a serving lease.
	for poolID, classification := range byPool {
		if classification.Disposition != PoolClassificationArmFence {
			continue
		}
		classifiedFence, _ := fenceForClassification(classification.Scope, classification.Fields)
		classifiedFence.ArmedAtBaseVersion, classifiedFence.ArmedAtBaseHash = base.Version, baseHash
		found := false
		for i := range next {
			if next[i].Scope.PoolID != poolID {
				continue
			}
			merged, err := mergeFence(next[i], classifiedFence)
			if err != nil {
				return err
			}
			next[i], found = merged, true
			next[i].ArmedAtBaseVersion, next[i].ArmedAtBaseHash = base.Version, baseHash
		}
		if !found {
			next = append(next, classifiedFence)
		}
	}
	for i, fence := range next {
		if fence.ReleasedAtBaseVersion != 0 {
			continue
		}
		if scope, requested := unfencedByPool[fence.Scope.PoolID]; requested && scope == fence.Scope {
			continue
		}
		classified, ok := byPool[fence.Scope.PoolID]
		if !ok {
			if fence.ArmedAtBaseHash == baseHash && fence.ArmedAtBaseVersion == base.Version {
				continue
			}
			return fmt.Errorf("scope-complete ownership classification is required for fenced pool %s", fence.Scope.PoolID)
		}
		if classified.Disposition != PoolClassificationArmFence && classified.Disposition != PoolClassificationMaintainFence {
			return fmt.Errorf("invalid pool classification disposition")
		}
		classifiedFence, _ := fenceForClassification(classified.Scope, classified.Fields)
		merged, err := mergeFence(fence, classifiedFence)
		if err != nil {
			return err
		}
		next[i] = merged
		next[i].ArmedAtBaseVersion = base.Version
		next[i].ArmedAtBaseHash = baseHash
	}
	if len(authority.UnfencedPools) > 0 {
		if c.projector.Active() {
			return fmt.Errorf("cannot unfence while ownership is serving")
		}
		hash := baseHash
		if authority.BaseVersion != base.Version || authority.BaseHash != hash {
			return fmt.Errorf("explicit ownership unfence is not bound to the authoritative base version/hash")
		}
		for _, scope := range authority.UnfencedPools {
			if !validScope(scope) {
				return fmt.Errorf("invalid explicit unfence scope")
			}
			found := false
			for i := range next {
				if next[i].Scope == scope {
					next[i].ReleasedAtBaseVersion = base.Version
					next[i].ReleasedAtBaseHash = hash
					found = true
				}
			}
			if !found {
				return fmt.Errorf("explicit ownership unfence scope is not armed")
			}
		}
	}
	next, err = canonicalFences(next)
	if err != nil {
		return err
	}
	probe := NewProjector()
	if err := probe.ReplaceBaseAndFences(base, next); err != nil {
		return err
	}
	// Only semantically valid authority is accepted, but its monotonic replay
	// state is durable before either fence/base persistence or substrate apply.
	if authorityFingerprint != "" {
		if err := c.acceptBaseAuthority(ctx, authority, authorityFingerprint); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(next, c.fences) {
		if err := c.store.SaveFences(ctx, next); err != nil {
			return fmt.Errorf("persist ownership fence/base transition: %w", err)
		}
	}
	if err := c.projector.ReplaceBaseAndFences(base, next); err != nil {
		return err
	}
	c.fences = next
	return nil
}

func (c *Coordinator) acceptBaseAuthority(ctx context.Context, authority BaseAuthority, fingerprint string) error {
	if c.authority == nil {
		return fmt.Errorf("base-authority state store is unavailable")
	}
	current, found, err := c.authority.LoadBaseAuthorityState(ctx)
	if err != nil {
		return err
	}
	if found {
		current, err = canonicalBaseAuthorityState(current)
		if err != nil {
			return err
		}
		switch {
		case authority.AuthorityRevision < current.AuthorityRevision:
			return ErrBaseAuthorityStale
		case authority.AuthorityRevision == current.AuthorityRevision && fingerprint != current.Fingerprint:
			return ErrBaseAuthorityChangedReplay
		case authority.AuthorityRevision == current.AuthorityRevision:
			return nil
		}
	}
	return c.authority.SaveBaseAuthorityState(ctx, BaseAuthorityState{Version: BaseAuthorityStateVersion, AuthorityRevision: authority.AuthorityRevision, Fingerprint: fingerprint})
}

// UpdateBaseAndSnapshot installs one authoritative ordinary snapshot and
// returns the fence-filtered projection that the normal reconcile owner may
// apply. Raw legacy Kubernetes fields never bypass an armed durable fence.
func (c *Coordinator) UpdateBaseAndSnapshot(ctx context.Context, base reconcile.DesiredState, authority BaseAuthority) (reconcile.DesiredState, error) {
	if err := c.UpdateBase(ctx, base, authority); err != nil {
		return reconcile.DesiredState{}, err
	}
	effective, found, err := c.projector.Snapshot()
	if err != nil {
		return reconcile.DesiredState{}, err
	}
	if !found {
		return reconcile.DesiredState{}, ErrBaseDesiredUnavailable
	}
	if observer, ok := c.domain.(desiredStateObserver); ok {
		observer.ObserveDesired(effective)
	}
	return effective, nil
}

// ApplyAndReadback implements AtomicDataplane. A serving transition arms its
// durable fence before any activation. Withdrawal never removes that fence.
func (c *Coordinator) ApplyAndReadback(ctx context.Context, desired EffectiveOwnership) (EffectiveOwnership, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.configured(); err != nil {
		return EffectiveOwnership{}, err
	}
	if err := c.ensureLoaded(ctx); err != nil {
		return EffectiveOwnership{}, err
	}
	serving := !isZeroEffective(desired)
	want, err := canonicalEffective(desired, serving)
	if err != nil {
		return EffectiveOwnership{}, err
	}
	if serving {
		if err := c.armFence(ctx, want); err != nil {
			return EffectiveOwnership{}, err
		}
	}
	if err := c.projector.SetOwnership(want); err != nil {
		return EffectiveOwnership{}, err
	}
	effective, found, err := c.projector.Snapshot()
	if err != nil {
		return EffectiveOwnership{}, errors.Join(ErrBaseDesiredUnavailable, err)
	}
	if !found {
		if serving {
			return EffectiveOwnership{}, ErrBaseDesiredUnavailable
		}
		emergency, ok := c.domain.(EmergencyDomainSurface)
		if !ok {
			return EffectiveOwnership{}, fmt.Errorf("%w: emergency withdrawal is unavailable", ErrProductionAdapterUnavailable)
		}
		recoveryCtx, cancel := context.WithTimeout(context.Background(), recoveryTimeout)
		defer cancel()
		if err := emergency.EmergencyWithdraw(recoveryCtx, append([]PoolFence(nil), c.fences...)); err != nil {
			return EffectiveOwnership{}, fmt.Errorf("startup emergency ownership withdrawal: %w", err)
		}
		return EffectiveOwnership{}, nil
	}
	order := activationOrder
	if !serving {
		order = withdrawalOrder
	}
	if err := c.apply(ctx, order, effective); err != nil {
		if serving {
			return EffectiveOwnership{}, errors.Join(err, c.compensate(ctx))
		}
		return EffectiveOwnership{}, c.withdrawAll(ctx, effective, err)
	}
	actual, err := c.domain.Readback(ctx)
	if err != nil {
		if serving {
			return EffectiveOwnership{}, errors.Join(err, c.compensate(ctx))
		}
		return EffectiveOwnership{}, c.withdrawAll(ctx, effective, err)
	}
	if !reflect.DeepEqual(canonicalDomainState(actual), expectedDomainState(effective)) {
		if serving {
			return EffectiveOwnership{}, errors.Join(ErrDomainReadbackMismatch, c.compensate(ctx))
		}
		return EffectiveOwnership{}, c.withdrawAll(ctx, effective, ErrDomainReadbackMismatch)
	}
	return want, nil
}

// VerifyCurrent performs a fresh full-domain readback without changing the
// active projection. It is the replay path for v3 delivery ACKs: persisted ACK
// state is never trusted unless the current substrates still match exactly.
func (c *Coordinator) VerifyCurrent(ctx context.Context, expected EffectiveOwnership) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.configured(); err != nil {
		return err
	}
	if err := c.ensureLoaded(ctx); err != nil {
		return err
	}
	want, err := canonicalEffective(expected, !isZeroEffective(expected))
	if err != nil {
		return err
	}
	active, err := c.projector.ActiveOwnership()
	if err != nil || !reflect.DeepEqual(active, want) {
		return ErrDomainReadbackMismatch
	}
	effective, found, err := c.projector.Snapshot()
	if err != nil {
		return err
	}
	if !found {
		if !isZeroEffective(want) {
			return ErrBaseDesiredUnavailable
		}
		emergency, ok := c.domain.(EmergencyDomainSurface)
		if !ok {
			return fmt.Errorf("%w: emergency withdrawal verification is unavailable", ErrProductionAdapterUnavailable)
		}
		return emergency.EmergencyWithdraw(ctx, append([]PoolFence(nil), c.fences...))
	}
	actual, err := c.domain.Readback(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(canonicalDomainState(actual), expectedDomainState(effective)) {
		return ErrDomainReadbackMismatch
	}
	return nil
}

// PrepareBaseAuthorityAck proves the exact projected base against live owners
// and durably records the receipt before transport. Transport loss therefore
// replays the same ACK instead of inventing a later success.
func (c *Coordinator) PrepareBaseAuthorityAck(ctx context.Context, base reconcile.DesiredState, appliedAt time.Time) (reconcile.KubernetesOwnershipBaseAuthorityAck, bool, error) {
	if c == nil {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, ErrBaseAuthorityInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if base.KubernetesOwnershipBaseAuthority == nil {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, nil
	}
	if err := c.configured(); err != nil {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, err
	}
	if err := c.ensureLoaded(ctx); err != nil {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, err
	}
	if c.authority == nil {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, ErrBaseAuthorityInvalid
	}
	authority, fingerprint, err := canonicalBaseAuthority(base, BaseAuthorityFromWire(base.KubernetesOwnershipBaseAuthority))
	if err != nil {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, err
	}
	state, found, err := c.authority.LoadBaseAuthorityState(ctx)
	if err != nil || !found {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, errors.Join(ErrBaseAuthorityInvalid, err)
	}
	if state.AuthorityRevision != authority.AuthorityRevision || state.Fingerprint != fingerprint {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, ErrBaseAuthorityChangedReplay
	}
	effective, found, err := c.projector.Snapshot()
	if err != nil || !found {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, errors.Join(ErrBaseDesiredUnavailable, err)
	}
	actual, err := c.domain.Readback(ctx)
	if err != nil {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, err
	}
	if !reflect.DeepEqual(canonicalDomainState(actual), expectedDomainState(effective)) {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, ErrDomainReadbackMismatch
	}
	if state.PendingAck != nil {
		return *state.PendingAck, true, nil
	}
	if appliedAt.IsZero() {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, ErrBaseAuthorityInvalid
	}
	ack := reconcile.KubernetesOwnershipBaseAuthorityAck{
		WireVersion: reconcile.KubernetesOwnershipBaseAuthorityWireVersion, AuthorityRevision: authority.AuthorityRevision,
		NodeID: authority.NodeID, OrgID: authority.OrgID, SiteID: authority.SiteID, BaseVersion: authority.BaseVersion,
		BaseHash: authority.BaseHash, AuthorityDigest: fingerprint, AppliedAt: appliedAt.UTC().Format(time.RFC3339Nano),
	}
	state.PendingAck = &ack
	if err := c.authority.SaveBaseAuthorityState(ctx, state); err != nil {
		return reconcile.KubernetesOwnershipBaseAuthorityAck{}, false, err
	}
	return ack, true, nil
}

func (c *Coordinator) MarkBaseAuthorityAckDelivered(ctx context.Context, ack reconcile.KubernetesOwnershipBaseAuthorityAck) error {
	if c == nil {
		return ErrBaseAuthorityInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authority == nil {
		return ErrBaseAuthorityInvalid
	}
	state, found, err := c.authority.LoadBaseAuthorityState(ctx)
	if err != nil || !found || state.PendingAck == nil {
		return errors.Join(ErrBaseAuthorityInvalid, err)
	}
	if !baseAuthorityAckMatches(*state.PendingAck, ack) {
		return ErrBaseAuthorityChangedReplay
	}
	state.PendingAck = nil
	return c.authority.SaveBaseAuthorityState(ctx, state)
}

func (c *Coordinator) configured() error {
	if c == nil || c.projector == nil || c.domain == nil || c.store == nil {
		return fmt.Errorf("ownership coordinator is not configured")
	}
	return nil
}

func (c *Coordinator) ensureLoaded(ctx context.Context) error {
	if c.loaded {
		return nil
	}
	fences, err := c.store.LoadFences(ctx)
	if err != nil {
		return fmt.Errorf("load durable ownership fences: %w", err)
	}
	if err := c.projector.ReplaceFences(fences); err != nil {
		return err
	}
	c.fences = fences
	c.loaded = true
	return nil
}

func (c *Coordinator) armFence(ctx context.Context, desired EffectiveOwnership) error {
	fence, err := fenceFor(desired)
	if err != nil {
		return err
	}
	base, found := c.projector.Base()
	if !found {
		return ErrBaseDesiredUnavailable
	}
	fence.ArmedAtBaseVersion = base.Version
	fence.ArmedAtBaseHash, err = baseStateHash(base)
	if err != nil {
		return err
	}
	next := make([]PoolFence, 0, len(c.fences)+1)
	for _, existing := range c.fences {
		if existing.Scope.PoolID == fence.Scope.PoolID {
			fence, err = mergeFence(existing, fence)
			if err != nil {
				return err
			}
			continue
		}
		next = append(next, existing)
	}
	next = append(next, fence)
	next, err = canonicalFences(next)
	if err != nil {
		return err
	}
	if err := c.store.SaveFences(ctx, next); err != nil {
		return fmt.Errorf("persist armed ownership fence: %w", err)
	}
	if err := c.projector.ReplaceFences(next); err != nil {
		return err
	}
	c.fences = next
	return nil
}

func (c *Coordinator) apply(ctx context.Context, order []Stage, desired reconcile.DesiredState) error {
	for _, stage := range order {
		if err := c.domain.ApplyStage(ctx, stage, cloneDesiredState(desired)); err != nil {
			return fmt.Errorf("apply ownership stage %s: %w", stage, err)
		}
	}
	return nil
}

func (c *Coordinator) applyAll(ctx context.Context, order []Stage, desired reconcile.DesiredState) error {
	var joined error
	for _, stage := range order {
		if err := c.domain.ApplyStage(ctx, stage, cloneDesiredState(desired)); err != nil {
			joined = errors.Join(joined, fmt.Errorf("apply ownership stage %s: %w", stage, err))
		}
	}
	return joined
}

// withdrawAll uses a request-independent bounded context and never stops at the
// first failed reverse stage. A second complete sweep is attempted whenever the
// first pass or its readback is uncertain; success means the final readback is
// exact, not merely that the retry commands returned nil.
func (c *Coordinator) withdrawAll(_ context.Context, desired reconcile.DesiredState, first error) error {
	recoveryCtx, cancel := context.WithTimeout(context.Background(), recoveryTimeout)
	defer cancel()
	passErr := c.applyAll(recoveryCtx, withdrawalOrder, desired)
	actual, readErr := c.domain.Readback(recoveryCtx)
	want := expectedDomainState(desired)
	if passErr == nil && readErr == nil && reflect.DeepEqual(canonicalDomainState(actual), want) {
		return nil
	}
	retryErr := c.applyAll(recoveryCtx, withdrawalOrder, desired)
	actual, finalReadErr := c.domain.Readback(recoveryCtx)
	if retryErr == nil && finalReadErr == nil && reflect.DeepEqual(canonicalDomainState(actual), want) {
		return nil
	}
	if finalReadErr == nil && !reflect.DeepEqual(canonicalDomainState(actual), want) {
		finalReadErr = ErrDomainReadbackMismatch
	}
	return errors.Join(first, passErr, readErr, retryErr, finalReadErr)
}

func (c *Coordinator) compensate(_ context.Context) error {
	recoveryCtx, cancel := context.WithTimeout(context.Background(), recoveryTimeout)
	defer cancel()
	if err := c.projector.SetOwnership(EffectiveOwnership{}); err != nil {
		return fmt.Errorf("prepare non-serving compensation: %w", err)
	}
	base, found, err := c.projector.Snapshot()
	if err != nil || !found {
		return errors.Join(ErrBaseDesiredUnavailable, err)
	}
	var compensation error
	compensation = c.applyAll(recoveryCtx, withdrawalOrder, base)
	actual, readErr := c.domain.Readback(recoveryCtx)
	if compensation == nil && readErr == nil && reflect.DeepEqual(canonicalDomainState(actual), expectedDomainState(base)) {
		return nil
	}
	retryErr := c.applyAll(recoveryCtx, withdrawalOrder, base)
	actual, finalReadErr := c.domain.Readback(recoveryCtx)
	if retryErr == nil && finalReadErr == nil && reflect.DeepEqual(canonicalDomainState(actual), expectedDomainState(base)) {
		return nil
	}
	if finalReadErr == nil && !reflect.DeepEqual(canonicalDomainState(actual), expectedDomainState(base)) {
		finalReadErr = fmt.Errorf("%w after non-serving compensation", ErrDomainReadbackMismatch)
	}
	return errors.Join(compensation, readErr, retryErr, finalReadErr)
}

func expectedDomainState(desired reconcile.DesiredState) AppliedDomainState {
	state := AppliedDomainState{}
	for _, peer := range desired.Peers {
		if peer.PublicKey != "" {
			state.WGPeers = append(state.WGPeers, WGAppliedPeer{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)})
		}
	}
	if desired.Policy != nil {
		for _, route := range desired.Policy.Routes {
			state.Routes = append(state.Routes, route.DstCIDR)
		}
		state.VIPMappings = append([]nodepolicy.VIPMapping(nil), desired.Policy.VIPMappings...)
		state.DNSZones = append([]nodepolicy.K8sDNSZone(nil), desired.Policy.K8sDNSZones...)
		for _, mapping := range desired.Policy.VIPMappings {
			if mapping.DNSName != "" && mapping.VIP != "" {
				state.DNSAnswers = append(state.DNSAnswers, K8sDNSAnswer{Name: mapping.DNSName, VIP: mapping.VIP})
			}
		}
		for _, zone := range desired.Policy.K8sDNSZones {
			if zone.ListenVIP != "" {
				state.DNSVIPs = append(state.DNSVIPs, zone.ListenVIP)
				state.DNSListeners = append(state.DNSListeners, zone.ListenVIP)
			}
		}
	}
	state.ReturnRules = expectedReturnRules(desired)
	state.OVPN.Enabled = desired.OVPNEnabled
	if desired.OVPNEnabled {
		state.OVPN.Serving = true
		state.OVPN.PoolCIDR = desired.InterfaceAddress
		state.OVPN.ServerMaterialDigest = ovpnMaterialDigest(desired.OVPNServer)
		state.OVPN.Clients = append([]reconcile.OVPNClient(nil), desired.OVPNClients...)
		state.OVPN.Routes = reconcile.OVPNPushRoutes(desired.Policy)
		if desired.Policy != nil {
			for _, forward := range desired.Policy.DNSForwards {
				state.OVPN.DNS = append(state.OVPN.DNS, forward.ResolverIP)
			}
			for _, zone := range desired.Policy.K8sDNSZones {
				if zone.ListenVIP != "" {
					state.OVPN.DNS = append(state.OVPN.DNS, zone.ListenVIP)
				}
			}
		}
	}
	return canonicalDomainState(state)
}

func canonicalDomainState(state AppliedDomainState) AppliedDomainState {
	state = cloneDomainState(state)
	for i := range state.WGPeers {
		sort.Strings(state.WGPeers[i].AllowedIPs)
	}
	sort.Slice(state.WGPeers, func(i, j int) bool { return state.WGPeers[i].PublicKey < state.WGPeers[j].PublicKey })
	sort.Strings(state.Routes)
	sort.Slice(state.ReturnRules, func(i, j int) bool {
		a, b := state.ReturnRules[i], state.ReturnRules[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		return a.Lookup < b.Lookup
	})
	sort.Slice(state.VIPMappings, func(i, j int) bool {
		a, b := state.VIPMappings[i], state.VIPMappings[j]
		return fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d", a.ServiceID, a.VIP, a.Protocol, a.PortLow, a.PortHigh) <
			fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d", b.ServiceID, b.VIP, b.Protocol, b.PortLow, b.PortHigh)
	})
	sort.Slice(state.DNSZones, func(i, j int) bool {
		return state.DNSZones[i].ListenVIP+"\x00"+state.DNSZones[i].Zone < state.DNSZones[j].ListenVIP+"\x00"+state.DNSZones[j].Zone
	})
	sort.Slice(state.DNSAnswers, func(i, j int) bool {
		return state.DNSAnswers[i].Name+"\x00"+state.DNSAnswers[i].VIP < state.DNSAnswers[j].Name+"\x00"+state.DNSAnswers[j].VIP
	})
	sort.Strings(state.DNSVIPs)
	sort.Strings(state.DNSListeners)
	sort.Slice(state.OVPN.Clients, func(i, j int) bool { return state.OVPN.Clients[i].CommonName < state.OVPN.Clients[j].CommonName })
	sort.Strings(state.OVPN.Routes)
	sort.Strings(state.OVPN.DNS)
	if len(state.WGPeers) == 0 {
		state.WGPeers = nil
	}
	if len(state.Routes) == 0 {
		state.Routes = nil
	}
	if len(state.ReturnRules) == 0 {
		state.ReturnRules = nil
	}
	if len(state.VIPMappings) == 0 {
		state.VIPMappings = nil
	}
	if len(state.DNSZones) == 0 {
		state.DNSZones = nil
	}
	if len(state.DNSAnswers) == 0 {
		state.DNSAnswers = nil
	}
	if len(state.DNSVIPs) == 0 {
		state.DNSVIPs = nil
	}
	if len(state.DNSListeners) == 0 {
		state.DNSListeners = nil
	}
	if len(state.OVPN.Clients) == 0 {
		state.OVPN.Clients = nil
	}
	if len(state.OVPN.Routes) == 0 {
		state.OVPN.Routes = nil
	}
	if len(state.OVPN.DNS) == 0 {
		state.OVPN.DNS = nil
	}
	return state
}

func cloneDomainState(value AppliedDomainState) AppliedDomainState {
	out := value
	out.WGPeers = make([]WGAppliedPeer, len(value.WGPeers))
	for i, peer := range value.WGPeers {
		out.WGPeers[i] = peer
		out.WGPeers[i].AllowedIPs = append([]string(nil), peer.AllowedIPs...)
	}
	out.Routes = append([]string(nil), value.Routes...)
	out.ReturnRules = append([]reconcile.ReturnRule(nil), value.ReturnRules...)
	out.VIPMappings = append([]nodepolicy.VIPMapping(nil), value.VIPMappings...)
	out.DNSZones = append([]nodepolicy.K8sDNSZone(nil), value.DNSZones...)
	out.DNSAnswers = append([]K8sDNSAnswer(nil), value.DNSAnswers...)
	out.DNSVIPs = append([]string(nil), value.DNSVIPs...)
	out.DNSListeners = append([]string(nil), value.DNSListeners...)
	out.OVPN.Clients = append([]reconcile.OVPNClient(nil), value.OVPN.Clients...)
	out.OVPN.Routes = append([]string(nil), value.OVPN.Routes...)
	out.OVPN.DNS = append([]string(nil), value.OVPN.DNS...)
	return out
}

func ovpnMaterialDigest(material *reconcile.OVPNServerMaterial) string {
	if material == nil {
		return ""
	}
	b, err := json.Marshal(material)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ProductionReadbackBlocker names the current owner seams that must exist
// before a concrete DomainSurface is safe to construct.
type ProductionReadbackBlocker string

const (
	BlockRouteKernelReadback     ProductionReadbackBlocker = "reconcile.route_kernel_readback"
	BlockVIPDNATReadback         ProductionReadbackBlocker = "egress.vip_dnat_kernel_readback"
	BlockDNSVIPReadback          ProductionReadbackBlocker = "egress.dns_vip_kernel_readback"
	BlockDNSForwarderReadback    ProductionReadbackBlocker = "dnsforward.k8s_table_listener_readback"
	BlockOVPNAppliedReadback     ProductionReadbackBlocker = "ovpnserver.applied_config_ccd_process_readback"
	BlockSingleWriterMainHandoff ProductionReadbackBlocker = "main.single_writer_handoff"
)

type ProductionAdapterError struct {
	Missing []ProductionReadbackBlocker
}

func (e *ProductionAdapterError) Error() string {
	return fmt.Sprintf("%v: missing %v", ErrProductionAdapterUnavailable, e.Missing)
}

func (e *ProductionAdapterError) Unwrap() error { return ErrProductionAdapterUnavailable }

func CurrentProductionAdapterError() error {
	return &ProductionAdapterError{Missing: []ProductionReadbackBlocker{
		BlockSingleWriterMainHandoff,
	}}
}
