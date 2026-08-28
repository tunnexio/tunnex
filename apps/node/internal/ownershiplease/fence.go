package ownershiplease

import (
	"fmt"
	"sort"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

const FenceVersion = 2

const legacyFenceVersion = 1

// PoolScope is the durable authority boundary. A pool is never inferred from
// dataplane prefixes: the control plane must name the same exact scope when it
// explicitly retires a fence.
type PoolScope struct {
	OrgID     string `json:"org_id"`
	SiteID    string `json:"site_id"`
	ClusterID string `json:"cluster_id"`
	PoolID    string `json:"pool_id"`
}

// PoolFence is a durable tombstone for generation-1 Kubernetes fields that
// may still be present in ordinary DesiredState. Once armed, the exact fields
// adopted by v3 stay suppressed after withdrawal and restart. Only an explicit
// authoritative base update may remove the fence.
type PoolFence struct {
	Version               int                 `json:"version"`
	Scope                 PoolScope           `json:"scope"`
	Suppressed            PoolOwnedBaseFields `json:"suppressed"`
	ArmedAtBaseVersion    uint64              `json:"armed_at_base_version,omitempty"`
	ArmedAtBaseHash       string              `json:"armed_at_base_hash,omitempty"`
	ReleasedAtBaseVersion uint64              `json:"released_at_base_version,omitempty"`
	ReleasedAtBaseHash    string              `json:"released_at_base_hash,omitempty"`
}

// PoolOwnedBaseFields is the scope-complete ordinary-base attribution held by
// a fence. It deliberately has no serving-lease identity: an arm_fence
// authority can create this tombstone on a standby that has never served.
type PoolOwnedBaseFields struct {
	Routes      []string                `json:"routes"`
	WGPeers     []WGPeerOwnership       `json:"wg_peers"`
	VIPMappings []nodepolicy.VIPMapping `json:"vip_mappings"`
	DNSZones    []nodepolicy.K8sDNSZone `json:"dns_zones"`
}

// BaseAuthority accompanies a full control-plane base snapshot. An empty value
// never changes fences. UnfencedPools is an explicit CP assertion, not an
// inference from fields disappearing from the base.
type BaseAuthority struct {
	// Present distinguishes an omitted mixed-version field from a present but
	// malformed all-zero object. It is transport metadata, not fingerprinted.
	Present           bool                 `json:"-"`
	WireVersion       int                  `json:"wire_version"`
	AuthorityRevision uint64               `json:"authority_revision"`
	NodeID            string               `json:"node_id"`
	OrgID             string               `json:"org_id"`
	SiteID            string               `json:"site_id"`
	BaseVersion       uint64               `json:"base_version"`
	BaseHash          string               `json:"base_hash"`
	Classifications   []PoolClassification `json:"classifications"`
	UnfencedPools     []PoolScope          `json:"unfenced_pools"`
}

type PoolClassificationDisposition string

const (
	PoolClassificationArmFence      PoolClassificationDisposition = "arm_fence"
	PoolClassificationMaintainFence PoolClassificationDisposition = "maintain_fence"
)

// PoolClassification is the CP's scope-complete attribution of every current
// base field belonging to one pool. It lets an armed fence suppress changed
// values, not just byte-identical historical values.
type PoolClassification struct {
	Scope       PoolScope                     `json:"scope"`
	Disposition PoolClassificationDisposition `json:"disposition"`
	Fields      PoolOwnedBaseFields           `json:"fields"`
	// Ownership is a source-compatible bridge for the pre-P3 internal tests and
	// callers. New wire authority always uses Fields and never fabricates these
	// lease-only identity fields.
	Ownership EffectiveOwnership `json:"-"`
}

func fenceFor(value EffectiveOwnership) (PoolFence, error) {
	canonical, err := canonicalEffective(value, true)
	if err != nil {
		return PoolFence{}, err
	}
	return PoolFence{
		Version:    FenceVersion,
		Scope:      PoolScope{OrgID: canonical.OrgID, SiteID: canonical.SiteID, ClusterID: canonical.ClusterID, PoolID: canonical.PoolID},
		Suppressed: PoolOwnedBaseFields{Routes: canonical.Routes, WGPeers: canonical.WGPeers, VIPMappings: canonical.VIPMappings, DNSZones: canonical.DNSZones},
	}, nil
}

func fenceForClassification(scope PoolScope, fields PoolOwnedBaseFields) (PoolFence, error) {
	canonical, err := canonicalPoolOwnedBaseFields(fields)
	if err != nil || !validScope(scope) {
		return PoolFence{}, fmt.Errorf("invalid scope-complete pool classification")
	}
	return PoolFence{Version: FenceVersion, Scope: scope, Suppressed: canonical}, nil
}

func canonicalFence(value PoolFence) (PoolFence, error) {
	if value.Version != FenceVersion {
		return PoolFence{}, fmt.Errorf("unsupported ownership fence version")
	}
	suppressed := value.Suppressed
	if !validScope(value.Scope) {
		return PoolFence{}, fmt.Errorf("invalid ownership fence scope")
	}
	var err error
	if suppressed, err = canonicalPoolOwnedBaseFields(suppressed); err != nil {
		return PoolFence{}, err
	}
	if (value.ReleasedAtBaseVersion == 0) != (value.ReleasedAtBaseHash == "") ||
		(value.ReleasedAtBaseHash != "" && !hex64RE.MatchString(value.ReleasedAtBaseHash)) {
		return PoolFence{}, fmt.Errorf("invalid ownership fence release binding")
	}
	if (value.ArmedAtBaseVersion == 0) != (value.ArmedAtBaseHash == "") ||
		(value.ArmedAtBaseHash != "" && !hex64RE.MatchString(value.ArmedAtBaseHash)) {
		return PoolFence{}, fmt.Errorf("invalid ownership fence base binding")
	}
	value.Suppressed = suppressed
	return value, nil
}

func canonicalPoolOwnedBaseFields(value PoolOwnedBaseFields) (PoolOwnedBaseFields, error) {
	var err error
	value.Routes, err = canonicalPrefixes(value.Routes)
	if err != nil || len(value.Routes) == 0 {
		return PoolOwnedBaseFields{}, fmt.Errorf("invalid fenced routes")
	}
	value.WGPeers, err = canonicalFenceWGPeers(value.WGPeers)
	if err != nil || len(value.WGPeers) == 0 {
		return PoolOwnedBaseFields{}, fmt.Errorf("invalid fenced WireGuard peers")
	}
	value.VIPMappings, err = canonicalFenceVIPMappings(value.VIPMappings)
	if err != nil {
		return PoolOwnedBaseFields{}, err
	}
	value.DNSZones, err = canonicalFenceDNSZones(value.DNSZones)
	if err != nil {
		return PoolOwnedBaseFields{}, err
	}
	return value, nil
}

func canonicalFenceWGPeers(values []WGPeerOwnership) ([]WGPeerOwnership, error) {
	out := make([]WGPeerOwnership, 0, len(values))
	seenKeys := map[string]struct{}{}
	for _, value := range values {
		canonical, err := canonicalWGPeers([]WGPeerOwnership{value})
		if err != nil || len(canonical) != 1 {
			return nil, fmt.Errorf("invalid fenced WireGuard peer")
		}
		if _, exists := seenKeys[value.PublicKey]; exists {
			return nil, fmt.Errorf("duplicate fenced WireGuard peer")
		}
		seenKeys[value.PublicKey] = struct{}{}
		out = append(out, canonical[0])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out, nil
}

func canonicalFenceVIPMappings(values []nodepolicy.VIPMapping) ([]nodepolicy.VIPMapping, error) {
	out := make([]nodepolicy.VIPMapping, 0, len(values))
	seen := map[nodepolicy.VIPMapping]struct{}{}
	for _, value := range values {
		canonical, err := canonicalVIPMappings([]nodepolicy.VIPMapping{value})
		if err != nil || len(canonical) != 1 {
			return nil, fmt.Errorf("invalid fenced VIP mapping")
		}
		if _, exists := seen[canonical[0]]; exists {
			return nil, fmt.Errorf("duplicate fenced VIP mapping")
		}
		seen[canonical[0]] = struct{}{}
		out = append(out, canonical[0])
	}
	sort.Slice(out, func(i, j int) bool { return fenceVIPKey(out[i]) < fenceVIPKey(out[j]) })
	return out, nil
}

func canonicalFenceDNSZones(values []nodepolicy.K8sDNSZone) ([]nodepolicy.K8sDNSZone, error) {
	out := make([]nodepolicy.K8sDNSZone, 0, len(values))
	seen := map[nodepolicy.K8sDNSZone]struct{}{}
	for _, value := range values {
		canonical, err := canonicalDNSZones([]nodepolicy.K8sDNSZone{value})
		if err != nil || len(canonical) != 1 {
			return nil, fmt.Errorf("invalid fenced DNS zone")
		}
		if _, exists := seen[canonical[0]]; exists {
			return nil, fmt.Errorf("duplicate fenced DNS zone")
		}
		seen[canonical[0]] = struct{}{}
		out = append(out, canonical[0])
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ListenVIP+"\x00"+out[i].Zone < out[j].ListenVIP+"\x00"+out[j].Zone
	})
	return out, nil
}

func fenceVIPKey(value nodepolicy.VIPMapping) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%s", value.ServiceID, value.VIP,
		value.Namespace, value.Service, value.ServiceCIDR, value.Protocol, value.PortLow, value.PortHigh, value.DNSName)
}

func canonicalFences(values []PoolFence) ([]PoolFence, error) {
	out := make([]PoolFence, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		canonical, err := canonicalFence(value)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[canonical.Scope.PoolID]; exists {
			return nil, fmt.Errorf("duplicate ownership fence pool")
		}
		seen[canonical.Scope.PoolID] = struct{}{}
		out = append(out, canonical)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope.PoolID < out[j].Scope.PoolID })
	return out, nil
}

func mergeFence(existing, next PoolFence) (PoolFence, error) {
	existing, err := canonicalFence(existing)
	if err != nil {
		return PoolFence{}, err
	}
	next, err = canonicalFence(next)
	if err != nil {
		return PoolFence{}, err
	}
	if existing.Scope != next.Scope {
		return PoolFence{}, fmt.Errorf("ownership fence scope changed for pool")
	}
	merged := next.Suppressed
	merged.Routes = unionStrings(existing.Suppressed.Routes, merged.Routes)
	merged.WGPeers = unionWGPeers(existing.Suppressed.WGPeers, merged.WGPeers)
	merged.VIPMappings = unionVIPMappings(existing.Suppressed.VIPMappings, merged.VIPMappings)
	merged.DNSZones = unionDNSZones(existing.Suppressed.DNSZones, merged.DNSZones)
	next.Suppressed = merged
	next.ReleasedAtBaseVersion = 0
	next.ReleasedAtBaseHash = ""
	next, err = canonicalFence(next)
	if err != nil {
		return PoolFence{}, err
	}
	return next, nil
}

func unionStrings(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, values := range [][]string{a, b} {
		for _, value := range values {
			if _, exists := seen[value]; !exists {
				seen[value] = struct{}{}
				out = append(out, value)
			}
		}
	}
	return out
}

func unionWGPeers(a, b []WGPeerOwnership) []WGPeerOwnership {
	byKey := map[string][]string{}
	for _, values := range [][]WGPeerOwnership{a, b} {
		for _, value := range values {
			byKey[value.PublicKey] = unionStrings(byKey[value.PublicKey], value.AllowedIPs)
		}
	}
	out := make([]WGPeerOwnership, 0, len(byKey))
	for key, prefixes := range byKey {
		out = append(out, WGPeerOwnership{PublicKey: key, AllowedIPs: prefixes})
	}
	return out
}

func unionVIPMappings(a, b []nodepolicy.VIPMapping) []nodepolicy.VIPMapping {
	out := append([]nodepolicy.VIPMapping(nil), a...)
	for _, candidate := range b {
		if !containsVIPMapping(out, candidate) {
			out = append(out, candidate)
		}
	}
	return out
}

func unionDNSZones(a, b []nodepolicy.K8sDNSZone) []nodepolicy.K8sDNSZone {
	out := append([]nodepolicy.K8sDNSZone(nil), a...)
	for _, candidate := range b {
		if !containsDNSZone(out, candidate) {
			out = append(out, candidate)
		}
	}
	return out
}

func validScope(scope PoolScope) bool {
	for _, value := range []string{scope.OrgID, scope.SiteID, scope.ClusterID, scope.PoolID} {
		if !uuidRE.MatchString(value) || value == "00000000-0000-0000-0000-000000000000" {
			return false
		}
	}
	return true
}
