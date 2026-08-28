package ownershiplease

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

var (
	ErrBaseDesiredUnavailable = errors.New("ownership base desired state is unavailable")
	ErrBasePolicyUnavailable  = errors.New("ownership base policy is unavailable")
	ErrOwnershipPeerMissing   = errors.New("ownership WireGuard peer is absent from base desired state")
	ErrOwnershipCollision     = errors.New("ownership overlay collides with base desired state")
)

// Projector is the single pure composition point for ordinary desired state
// and one pool-owned serving overlay. It performs no OS writes. Every input and
// output is deep-cloned so callers cannot mutate the stored baseline or active
// lease through retained slices or pointers.
type Projector struct {
	mu     sync.RWMutex
	base   *reconcile.DesiredState
	active EffectiveOwnership
	fences map[string]PoolFence
}

func NewProjector() *Projector { return &Projector{fences: map[string]PoolFence{}} }

// UpdateBase stores the latest ordinary desired state even when the current
// lease now conflicts with it. The error makes that conflict fail closed; a
// later withdrawal still reveals this newest baseline instead of stale state.
func (p *Projector) UpdateBase(base reconcile.DesiredState) error {
	if p == nil {
		return ErrBaseDesiredUnavailable
	}
	cloned := cloneDesiredState(base)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.base = &cloned
	if isZeroEffective(p.active) {
		return nil
	}
	_, err := projectDesiredState(filterFencedBase(cloned, p.fences), p.active)
	return err
}

func (p *Projector) Active() bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return !isZeroEffective(p.active)
}

func (p *Projector) Base() (reconcile.DesiredState, bool) {
	if p == nil {
		return reconcile.DesiredState{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.base == nil {
		return reconcile.DesiredState{}, false
	}
	return cloneDesiredState(*p.base), true
}

// ReplaceBaseAndFences prevalidates and installs both values under one lock so
// an unfence can never expose a partially-mutated in-memory transition.
func (p *Projector) ReplaceBaseAndFences(base reconcile.DesiredState, values []PoolFence) error {
	if p == nil {
		return ErrBaseDesiredUnavailable
	}
	canonical, err := canonicalFences(values)
	if err != nil {
		return err
	}
	next := make(map[string]PoolFence, len(canonical))
	for _, value := range canonical {
		next[value.Scope.PoolID] = value
	}
	cloned := cloneDesiredState(base)
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := projectDesiredState(filterFencedBase(cloned, next), p.active); err != nil {
		return err
	}
	p.base = &cloned
	p.fences = next
	return nil
}

// ReplaceFences restores the complete durable fence set. It is intentionally
// separate from UpdateBase: callers must persist this set before exposing it to
// the projector.
func (p *Projector) ReplaceFences(values []PoolFence) error {
	if p == nil {
		return ErrBaseDesiredUnavailable
	}
	canonical, err := canonicalFences(values)
	if err != nil {
		return err
	}
	next := make(map[string]PoolFence, len(canonical))
	for _, value := range canonical {
		next[value.Scope.PoolID] = value
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fences = next
	if p.base != nil && !isZeroEffective(p.active) {
		_, err = projectDesiredState(filterFencedBase(*p.base, p.fences), p.active)
	}
	return err
}

func (p *Projector) Fences() []PoolFence {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]PoolFence, 0, len(p.fences))
	for _, value := range p.fences {
		out = append(out, value)
	}
	out, _ = canonicalFences(out)
	return out
}

// SetOwnership installs only a valid, collision-free serving overlay. The zero
// value is prepared/withdrawn/expired and clears the overlay. A failed serving
// candidate never replaces the last accepted active ownership.
func (p *Projector) SetOwnership(value EffectiveOwnership) error {
	if p == nil {
		return ErrBaseDesiredUnavailable
	}
	canonical, err := canonicalEffective(value, !isZeroEffective(value))
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if isZeroEffective(canonical) {
		p.active = EffectiveOwnership{}
		return nil
	}
	if p.base == nil {
		return ErrBaseDesiredUnavailable
	}
	if _, err := projectDesiredState(filterFencedBase(*p.base, p.fences), canonical); err != nil {
		return err
	}
	p.active = canonical
	return nil
}

func (p *Projector) ActiveOwnership() (EffectiveOwnership, error) {
	if p == nil {
		return EffectiveOwnership{}, ErrBaseDesiredUnavailable
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return canonicalEffective(p.active, !isZeroEffective(p.active))
}

// Snapshot returns the current effective desired state. found=false means no
// ordinary control-plane baseline has arrived; an ownership overlay is never
// projected in that state.
func (p *Projector) Snapshot() (state reconcile.DesiredState, found bool, err error) {
	if p == nil {
		return reconcile.DesiredState{}, false, ErrBaseDesiredUnavailable
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.base == nil {
		return reconcile.DesiredState{}, false, nil
	}
	state, err = projectDesiredState(filterFencedBase(*p.base, p.fences), p.active)
	return state, true, err
}

func filterFencedBase(base reconcile.DesiredState, fences map[string]PoolFence) reconcile.DesiredState {
	out := cloneDesiredState(base)
	for _, fence := range fences {
		if fenceReleasedForBase(fence, base) {
			continue
		}
		suppressed := fence.Suppressed
		routes := make(map[string]struct{}, len(suppressed.Routes))
		for _, route := range suppressed.Routes {
			routes[route] = struct{}{}
		}
		if out.Policy != nil {
			keptRoutes := out.Policy.Routes[:0]
			for _, route := range out.Policy.Routes {
				if _, remove := routes[route.DstCIDR]; !remove {
					keptRoutes = append(keptRoutes, route)
				}
			}
			out.Policy.Routes = keptRoutes
			keptVIPs := out.Policy.VIPMappings[:0]
			for _, mapping := range out.Policy.VIPMappings {
				if !containsVIPMapping(suppressed.VIPMappings, mapping) {
					keptVIPs = append(keptVIPs, mapping)
				}
			}
			out.Policy.VIPMappings = keptVIPs
			keptZones := out.Policy.K8sDNSZones[:0]
			for _, zone := range out.Policy.K8sDNSZones {
				if !containsDNSZone(suppressed.DNSZones, zone) {
					keptZones = append(keptZones, zone)
				}
			}
			out.Policy.K8sDNSZones = keptZones
		}
		ownedByPeer := map[string]map[string]struct{}{}
		for _, peer := range suppressed.WGPeers {
			prefixes := map[string]struct{}{}
			for _, prefix := range peer.AllowedIPs {
				prefixes[prefix] = struct{}{}
			}
			ownedByPeer[peer.PublicKey] = prefixes
		}
		for i := range out.Peers {
			prefixes := ownedByPeer[out.Peers[i].PublicKey]
			if len(prefixes) == 0 {
				continue
			}
			kept := out.Peers[i].AllowedIPs[:0]
			for _, prefix := range out.Peers[i].AllowedIPs {
				if _, remove := prefixes[prefix]; !remove {
					kept = append(kept, prefix)
				}
			}
			out.Peers[i].AllowedIPs = kept
		}
	}
	return out
}

func baseStateHash(base reconcile.DesiredState) (string, error) {
	return BaseStateHash(base)
}

func fenceReleasedForBase(fence PoolFence, base reconcile.DesiredState) bool {
	if fence.ReleasedAtBaseVersion == 0 || base.Version < fence.ReleasedAtBaseVersion {
		return false
	}
	if base.Version > fence.ReleasedAtBaseVersion {
		return true
	}
	hash, err := baseStateHash(base)
	return err == nil && hash == fence.ReleasedAtBaseHash
}

func containsVIPMapping(values []nodepolicy.VIPMapping, candidate nodepolicy.VIPMapping) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func containsDNSZone(values []nodepolicy.K8sDNSZone, candidate nodepolicy.K8sDNSZone) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func projectDesiredState(base reconcile.DesiredState, ownership EffectiveOwnership) (reconcile.DesiredState, error) {
	out := cloneDesiredState(base)
	if isZeroEffective(ownership) {
		return out, nil
	}
	if out.Policy == nil {
		return reconcile.DesiredState{}, ErrBasePolicyUnavailable
	}
	if err := projectWGPeers(&out, ownership.WGPeers); err != nil {
		return reconcile.DesiredState{}, err
	}
	if err := projectRoutes(out.Policy, ownership.Routes); err != nil {
		return reconcile.DesiredState{}, err
	}
	if err := projectVIPMappings(out.Policy, ownership.VIPMappings); err != nil {
		return reconcile.DesiredState{}, err
	}
	if err := projectDNSZones(out.Policy, ownership.DNSZones); err != nil {
		return reconcile.DesiredState{}, err
	}
	return out, nil
}

func projectWGPeers(state *reconcile.DesiredState, owned []WGPeerOwnership) error {
	indices := make(map[string]int, len(state.Peers))
	for i, peer := range state.Peers {
		if peer.PublicKey == "" {
			continue // keyless OpenVPN roster entries are not WireGuard ownership targets
		}
		if _, duplicate := indices[peer.PublicKey]; duplicate {
			return fmt.Errorf("%w: duplicate base peer %q", ErrOwnershipCollision, peer.PublicKey)
		}
		indices[peer.PublicKey] = i
	}
	var ownedPrefixes []netip.Prefix
	for _, peer := range owned {
		index, exists := indices[peer.PublicKey]
		if !exists {
			return fmt.Errorf("%w: %q", ErrOwnershipPeerMissing, peer.PublicKey)
		}
		for _, raw := range peer.AllowedIPs {
			prefix := netip.MustParsePrefix(raw)
			for _, prior := range ownedPrefixes {
				if prefixesOverlap(prefix, prior) {
					return fmt.Errorf("%w: owned WireGuard prefixes %s and %s overlap", ErrOwnershipCollision, prefix, prior)
				}
			}
			for _, basePeer := range state.Peers {
				for _, baseRaw := range basePeer.AllowedIPs {
					basePrefix, err := netip.ParsePrefix(baseRaw)
					if err == nil && prefixesOverlap(prefix, basePrefix) {
						return fmt.Errorf("%w: owned WireGuard prefix %s overlaps base peer %q prefix %s", ErrOwnershipCollision, prefix, basePeer.PublicKey, basePrefix)
					}
				}
			}
			ownedPrefixes = append(ownedPrefixes, prefix)
		}
		state.Peers[index].AllowedIPs = append(state.Peers[index].AllowedIPs, peer.AllowedIPs...)
	}
	return nil
}

func projectRoutes(policy *nodepolicy.Compiled, owned []string) error {
	var ownedPrefixes []netip.Prefix
	for _, raw := range owned {
		prefix := netip.MustParsePrefix(raw)
		for _, prior := range ownedPrefixes {
			if prefixesOverlap(prefix, prior) {
				return fmt.Errorf("%w: owned routes %s and %s overlap", ErrOwnershipCollision, prefix, prior)
			}
		}
		for _, route := range policy.Routes {
			basePrefix, err := netip.ParsePrefix(route.DstCIDR)
			if err == nil && prefixesOverlap(prefix, basePrefix) {
				return fmt.Errorf("%w: owned route %s overlaps base route %s", ErrOwnershipCollision, prefix, basePrefix)
			}
		}
		ownedPrefixes = append(ownedPrefixes, prefix)
		policy.Routes = append(policy.Routes, nodepolicy.Route{DstCIDR: raw})
	}
	return nil
}

func projectVIPMappings(policy *nodepolicy.Compiled, owned []nodepolicy.VIPMapping) error {
	all := append([]nodepolicy.VIPMapping(nil), policy.VIPMappings...)
	for _, candidate := range owned {
		for _, existing := range all {
			if vipMappingsCollide(existing, candidate) {
				return fmt.Errorf("%w: VIP mapping %q/%s conflicts with %q/%s", ErrOwnershipCollision,
					candidate.ServiceID, candidate.VIP, existing.ServiceID, existing.VIP)
			}
		}
		all = append(all, candidate)
	}
	policy.VIPMappings = all
	return nil
}

func vipMappingsCollide(a, b nodepolicy.VIPMapping) bool {
	if a.ServiceID != "" && a.ServiceID == b.ServiceID {
		return true
	}
	if a.VIP != "" && a.VIP == b.VIP {
		return true
	}
	if a.DNSName != "" && strings.EqualFold(strings.TrimSuffix(a.DNSName, "."), strings.TrimSuffix(b.DNSName, ".")) {
		return true
	}
	return a.Namespace == b.Namespace && a.Service == b.Service && a.Protocol == b.Protocol &&
		a.PortLow == b.PortLow && a.PortHigh == b.PortHigh
}

func projectDNSZones(policy *nodepolicy.Compiled, owned []nodepolicy.K8sDNSZone) error {
	all := append([]nodepolicy.K8sDNSZone(nil), policy.K8sDNSZones...)
	for _, candidate := range owned {
		candidateZone := strings.ToLower(strings.TrimSuffix(candidate.Zone, "."))
		for _, existing := range all {
			existingZone := strings.ToLower(strings.TrimSuffix(existing.Zone, "."))
			if candidate.ListenVIP == existing.ListenVIP || candidateZone == existingZone {
				return fmt.Errorf("%w: DNS ownership %s/%s conflicts with %s/%s", ErrOwnershipCollision,
					candidate.ListenVIP, candidate.Zone, existing.ListenVIP, existing.Zone)
			}
		}
		all = append(all, candidate)
	}
	policy.K8sDNSZones = all
	return nil
}

func prefixesOverlap(a, b netip.Prefix) bool {
	a, b = a.Masked(), b.Masked()
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

func cloneDesiredState(in reconcile.DesiredState) reconcile.DesiredState {
	out := in
	out.Peers = make([]reconcile.Peer, len(in.Peers))
	for i, peer := range in.Peers {
		out.Peers[i] = peer
		out.Peers[i].AllowedIPs = append([]string(nil), peer.AllowedIPs...)
	}
	out.OVPNClients = append([]reconcile.OVPNClient(nil), in.OVPNClients...)
	if in.OVPNServer != nil {
		server := *in.OVPNServer
		out.OVPNServer = &server
	}
	if in.DNSResolveRequest != nil {
		request := *in.DNSResolveRequest
		request.RecordTypes = append([]fqdnrpc.RecordType(nil), request.RecordTypes...)
		request.ResolverEndpoints = append([]fqdnrpc.ResolverEndpoint(nil), request.ResolverEndpoints...)
		out.DNSResolveRequest = &request
	}
	if in.KubernetesOwnershipBaseAuthority != nil {
		authority := *in.KubernetesOwnershipBaseAuthority
		authority.Classifications = make([]reconcile.KubernetesOwnershipPoolClassification, len(in.KubernetesOwnershipBaseAuthority.Classifications))
		for i, item := range in.KubernetesOwnershipBaseAuthority.Classifications {
			authority.Classifications[i] = item
			authority.Classifications[i].Fields.Routes = append([]string(nil), item.Fields.Routes...)
			authority.Classifications[i].Fields.WGPeers = make([]reconcile.KubernetesOwnershipWGPeer, len(item.Fields.WGPeers))
			for j, peer := range item.Fields.WGPeers {
				authority.Classifications[i].Fields.WGPeers[j] = peer
				authority.Classifications[i].Fields.WGPeers[j].AllowedIPs = append([]string(nil), peer.AllowedIPs...)
			}
			authority.Classifications[i].Fields.VIPMappings = append([]nodepolicy.VIPMapping(nil), item.Fields.VIPMappings...)
			authority.Classifications[i].Fields.DNSZones = append([]nodepolicy.K8sDNSZone(nil), item.Fields.DNSZones...)
		}
		authority.UnfencedPools = append([]reconcile.KubernetesOwnershipPoolScope(nil), in.KubernetesOwnershipBaseAuthority.UnfencedPools...)
		out.KubernetesOwnershipBaseAuthority = &authority
	}
	if in.Policy != nil {
		policy := *in.Policy
		policy.Allow = append([]nodepolicy.AllowEntry(nil), in.Policy.Allow...)
		policy.Subjects = make([]nodepolicy.SubjectAttribution, len(in.Policy.Subjects))
		for i, subject := range in.Policy.Subjects {
			policy.Subjects[i] = subject
			if subject.ConfigRevision != nil {
				revision := *subject.ConfigRevision
				policy.Subjects[i].ConfigRevision = &revision
			}
		}
		policy.Routes = append([]nodepolicy.Route(nil), in.Policy.Routes...)
		policy.LocalSubnets = append([]string(nil), in.Policy.LocalSubnets...)
		policy.DNSForwards = append([]nodepolicy.DNSForward(nil), in.Policy.DNSForwards...)
		policy.VIPMappings = append([]nodepolicy.VIPMapping(nil), in.Policy.VIPMappings...)
		policy.K8sDNSZones = append([]nodepolicy.K8sDNSZone(nil), in.Policy.K8sDNSZones...)
		policy.FQDNGenerations = make([]nodepolicy.FQDNGeneration, len(in.Policy.FQDNGenerations))
		for i, generation := range in.Policy.FQDNGenerations {
			policy.FQDNGenerations[i] = generation
			policy.FQDNGenerations[i].Answers = append([]string(nil), generation.Answers...)
		}
		out.Policy = &policy
	}
	return out
}
