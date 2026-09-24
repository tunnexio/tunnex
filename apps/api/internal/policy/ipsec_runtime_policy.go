package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

// CompileIPsecRuntimePolicy must run inside the runtime transaction after its
// organization serialization lock. Migration policy-writer mirrors preserve a
// coherent snapshot across these queries. Caller input never supplies authority.
func CompileIPsecRuntimePolicy(ctx context.Context, q *sqlc.Queries, input ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
	snapshot, err := BuildSnapshotWithQueries(ctx, q, input.OrgID)
	if err != nil {
		return ipsec.RuntimePolicy{}, ipsec.ErrConnectionUnavailable
	}
	return compileIPsecRuntimePolicy(snapshot, input)
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
	if len(result.Grants) > 128 {
		return ipsec.RuntimePolicy{}, ipsec.ErrConnectionIneligible
	}
	sort.Slice(result.Grants, func(a, b int) bool {
		x, _ := json.Marshal(result.Grants[a])
		y, _ := json.Marshal(result.Grants[b])
		return string(x) < string(y)
	})
	// Bind the hash to this exact connection even when its effective policy is
	// empty. Hash only canonical nonsecret forwarding authority, never PSKs.
	raw, err := json.Marshal(struct {
		Org, Node, Site, Connection uuid.UUID
		Grants                      []ipsec.RuntimeGrant
	}{input.OrgID, input.NodeID, input.SiteID, input.ConnectionID, result.Grants})
	if err != nil {
		return ipsec.RuntimePolicy{}, ipsec.ErrConnectionUnavailable
	}
	hash := sha256.Sum256(raw)
	result.Hash = hex.EncodeToString(hash[:])
	return result, nil
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
