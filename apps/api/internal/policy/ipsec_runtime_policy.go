package policy

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// CompileIPsecRuntimePolicy must run inside the runtime transaction after its
// organization serialization lock. Migration policy-writer mirrors preserve a
// coherent snapshot across these queries. Caller input never supplies authority.
func CompileIPsecRuntimePolicy(ctx context.Context, q *sqlc.Queries, input ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
	return compileIPsecRuntimePolicyWithEntitlement(ctx, q, input, false)
}

// IPsecRuntimePolicyCompiler uses the same named entitlement as ordinary policy.
// A missing entitlement callback remains fail closed for retained FQDN rules.
func IPsecRuntimePolicyCompiler(entitled func() bool) ipsec.RuntimePolicyCompiler {
	return func(ctx context.Context, q *sqlc.Queries, input ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
		return compileIPsecRuntimePolicyWithEntitlement(ctx, q, input, entitled != nil && entitled())
	}
}

func compileIPsecRuntimePolicyWithEntitlement(ctx context.Context, q *sqlc.Queries, input ipsec.RuntimePolicyInput, entitled bool) (ipsec.RuntimePolicy, error) {
	snapshot, err := BuildSnapshotWithQueries(ctx, q, input.OrgID)
	if err != nil {
		return ipsec.RuntimePolicy{}, ipsec.ErrConnectionUnavailable
	}
	if err := appendRuntimeFQDNGenerations(ctx, &snapshot, input, entitled); err != nil {
		return ipsec.RuntimePolicy{}, ipsec.ErrConnectionUnavailable
	}
	rows, err := q.ListIPsecDNSResolverProfiles(ctx, input.OrgID)
	if err != nil {
		return ipsec.RuntimePolicy{}, ipsec.ErrConnectionUnavailable
	}
	declared := []IPsecDNSProfile{}
	for _, row := range rows {
		if row.GatewayID != input.NodeID {
			continue
		}
		profile, err := DecodeIPsecDNSProfile(row)
		if err != nil {
			return ipsec.RuntimePolicy{}, ipsec.ErrConnectionUnavailable
		}
		declared = append(declared, profile)
	}
	result, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil {
		return result, err
	}
	// Proxy entitlement uses ordinary WG policy before the forwarded IPsec compiler filters local cloud prefixes.
	var proxyAllows []policyspec.AllowEntry
	if snapshot.Mode == ModeEnforcing {
		proxyAllows = Compile(snapshot)[input.NodeID].Allow
	}
	if err := attachRuntimeDNSProfiles(&result, declared, input, proxyAllows); err != nil {
		return ipsec.RuntimePolicy{}, err
	}
	return hashRuntimePolicy(result, input)
}
func compileIPsecRuntimePolicy(snapshot Snapshot, input ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
	if input.OrgID == uuid.Nil || input.NodeID == uuid.Nil || input.SiteID == uuid.Nil || input.ConnectionID == uuid.Nil {
		return ipsec.RuntimePolicy{}, ipsec.ErrConnectionInvalid
	}
	// This dedicated artifact belongs to one connection's exact gateway. Keep
	// the underlying shared compiler unchanged while making local-source Site
	// placement explicit instead of depending on co-Site gateway ordering.
	bound := false
	siteNodes := make([]SiteNode, 0, len(snapshot.SiteNodes))
	for _, n := range snapshot.SiteNodes {
		if n.SiteID == input.SiteID {
			if n.NodeID != input.NodeID {
				continue
			}
			bound = true
		}
		siteNodes = append(siteNodes, n)
	}
	if !bound {
		return ipsec.RuntimePolicy{}, ipsec.ErrConnectionIneligible
	}
	snapshot.SiteNodes = siteNodes
	fqdnSnapshot := snapshot
	result := ipsec.RuntimePolicy{Grants: []ipsec.RuntimeGrant{}}
	// Isolate the supported shared-rule classes before compilation. Membership,
	// FQDN generations, device owners and service discovery cannot widen this port.
	rules := make([]Rule, 0, len(snapshot.Rules))
	for _, r := range snapshot.Rules {
		if (r.SrcKind == "cidr" || (r.SrcKind == "site" && r.SrcSiteID == input.SiteID)) && (r.DstKind == "site" || r.DstKind == "resource") {
			rules = append(rules, r)
		}
	}
	snapshot.Rules = rules
	snapshot.IPsecNetworks = []IPsecNetwork{{ConnectionID: input.ConnectionID, AssignedGatewayID: input.NodeID, LocalSiteID: input.SiteID, RemotePrefixes: input.Config.RemotePrefixes}}
	if snapshot.Mode == ModeEnforcing {
		artifact := Compile(snapshot)[input.NodeID]
		for _, grant := range artifact.Allow {
			source, ok := runtimePolicyPrefix(grant.SrcIP)
			if !ok {
				continue
			}
			destination, ok := runtimePolicyPrefix(grant.DstCIDR)
			if !ok {
				continue
			}
			outbound := runtimePolicyWithin(source, input.Config.LocalPrefixes) && runtimePolicyWithin(destination, input.Config.RemotePrefixes)
			inbound := runtimePolicyWithin(source, input.Config.RemotePrefixes) && runtimePolicyWithin(destination, input.Config.LocalPrefixes)
			if grant.FQDNManaged || (!outbound && !inbound) || grant.PortLow < 0 || grant.PortHigh < 0 || grant.PortLow > 65535 || grant.PortHigh > 65535 {
				continue
			}
			result.Grants = append(result.Grants, ipsec.RuntimeGrant{Source: source.String(), Destination: destination.String(), Protocol: string(grant.Protocol), PortLow: uint16(grant.PortLow), PortHigh: uint16(grant.PortHigh), RuleID: grant.RuleID})
		}
	}
	result.FQDNGrants = compileIPsecFQDNGrants(fqdnSnapshot, input)
	if len(result.FQDNGrants) != 0 {
		result.FQDNPolicyVersion = input.FQDNPolicyVersion
		if input.FQDNPolicyVersion == 1 {
			result.FQDNLeaseDeadline = runtimeFQDNLeaseDeadline(fqdnSnapshot, result.FQDNGrants)
			if !result.FQDNLeaseDeadline.After(input.CompiledAt) {
				return ipsec.RuntimePolicy{}, ipsec.ErrConnectionIneligible
			}
		}
	}
	if len(result.Grants)+len(result.FQDNGrants) > 128 {
		return ipsec.RuntimePolicy{}, ipsec.ErrConnectionIneligible
	}
	sort.Slice(result.Grants, func(a, b int) bool {
		x, _ := json.Marshal(result.Grants[a])
		y, _ := json.Marshal(result.Grants[b])
		return string(x) < string(y)
	})
	return hashRuntimePolicy(result, input)
}
func hashRuntimePolicy(result ipsec.RuntimePolicy, input ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
	return ipsec.HashRuntimePolicy(result, input)
}
func runtimePolicyPrefix(raw string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		a, e := netip.ParseAddr(raw)
		if e != nil || !a.Is4() {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, 32)
	}
	return p, p.Addr().Is4() && p == p.Masked()
}
func runtimePolicyWithin(prefix netip.Prefix, ranges []string) bool {
	for _, raw := range ranges {
		outer, err := netip.ParsePrefix(raw)
		if err == nil && outer.Addr().Is4() && outer == outer.Masked() && outer.Bits() <= prefix.Bits() && outer.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
