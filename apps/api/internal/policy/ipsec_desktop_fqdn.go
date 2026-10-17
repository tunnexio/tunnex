package policy

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"sort"
)

// A static CNAME supplies DNS provenance; this independent connection binding supplies application routing.
func compileIPsecDesktopFQDNGrants(s Snapshot, in ipsec.RuntimePolicyInput) []ipsec.RuntimeFQDNGrant {
	if s.Mode != ModeEnforcing || !s.FQDNResourcesLicensed || !s.FQDNResourcesEnabled || in.DesktopTransitVersion != 1 || in.DesktopFQDNVersion != 1 || in.FQDNPolicyVersion != 2 || in.ConfigurationRevision != 1 || in.Config.ProfileID != "aws-bgp-ipv4-v1" || in.Config.BGP == nil || in.CompiledAt.IsZero() {
		return nil
	}
	devices := ipsecDesktopDevices(s, in)
	filtered := s
	filtered.Rules = nil
	filtered.FQDNResources = nil
	rules := map[string]Rule{}
	resources := map[uuid.UUID]FQDNResource{}
	refs := map[string]uuid.UUID{}
	for _, r := range s.FQDNResources {
		g := r.Active
		if g == nil || g.ApplicationIPsecPath == nil || !g.StaticCNAME || g.IPsecConnectionID != uuid.Nil || g.IPsecSourceAddress != "" || g.SelectedSiteID != in.SiteID || g.SelectedGatewayID != in.NodeID || g.ApplicationIPsecPath.ConnectionID != in.ConnectionID.String() || g.ApplicationIPsecPath.ConfigurationRevision != in.ConfigurationRevision || g.ResolverMatchSuffix == "" || g.ResolvedAt.IsZero() || g.ResolvedAt.After(in.CompiledAt) || !g.FreshUntil.After(in.CompiledAt) {
			continue
		}
		if _, duplicate := resources[r.ID]; duplicate {
			return nil
		}
		if _, _, _, ok := activeFQDNGeneration(r); ok {
			resources[r.ID] = r
			filtered.FQDNResources = append(filtered.FQDNResources, r)
		}
	}
	for _, ref := range s.FQDNRuleReferences {
		if _, duplicate := refs[ref.PolicyRuleID.String()]; duplicate {
			return nil
		}
		refs[ref.PolicyRuleID.String()] = ref.FQDNResourceID
	}
	for _, r := range s.Rules {
		if r.ID == uuid.Nil || r.Disabled || r.DstKind != "fqdn_resource" || (r.SrcKind != "user" && r.SrcKind != "group" && r.SrcKind != "") || (r.ExpiresAt != nil && !r.ExpiresAt.After(in.CompiledAt)) {
			continue
		}
		if _, ok := resources[refs[r.ID.String()]]; !ok {
			continue
		}
		filtered.Rules = append(filtered.Rules, r)
		rules[r.ID.String()] = r
	}
	var out []ipsec.RuntimeFQDNGrant
	for _, g := range Compile(filtered)[in.NodeID].Allow {
		d, ok := devices[g.SrcDeviceID]
		r, rok := resources[refs[g.RuleID]]
		rule, ruleOK := rules[g.RuleID]
		dst, valid := runtimePolicyPrefix(g.DstCIDR)
		if !ok || !rok || !ruleOK || !g.FQDNManaged || g.SrcIP != d.AssignedIP || !valid || dst.Bits() != 32 || !runtimePolicyWithin(dst, in.Config.RemotePrefixes) || g.PortLow < 1 || g.PortLow > g.PortHigh || g.PortHigh > 65535 || (g.Protocol != "tcp" && g.Protocol != "udp") {
			continue
		}
		generation, _, _, valid := activeFQDNGeneration(r)
		if !valid {
			continue
		}
		expiry := r.Active.FreshUntil
		if rule.ExpiresAt != nil && rule.ExpiresAt.Before(expiry) {
			expiry = *rule.ExpiresAt
		}
		out = append(out, ipsec.RuntimeFQDNGrant{RuntimeGrant: ipsec.RuntimeGrant{Source: d.AssignedIP + "/32", Destination: dst.String(), Protocol: string(g.Protocol), PortLow: uint16(g.PortLow), PortHigh: uint16(g.PortHigh), RuleID: g.RuleID}, ExpiresAt: expiry, FQDNManaged: true, ResourceID: r.ID.String(), Name: r.FQDN, Generation: generation.Generation, ResolverConfigID: r.Active.ResolverConfigID.String(), ResolverConfigVersion: r.Active.ResolverConfigVersion, SelectedSiteID: in.SiteID.String(), SelectedGatewayID: in.NodeID.String(), ResolverProfileID: r.Active.ResolverProfileID.String(), ResolverMatchSuffix: r.Active.ResolverMatchSuffix, ConnectionID: in.ConnectionID.String(), ConfigurationRevision: in.ConfigurationRevision, DeviceID: d.ID.String(), PublicKey: d.PublicKey, ResolverKind: "static_cname"})
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := json.Marshal(out[i])
		b, _ := json.Marshal(out[j])
		return string(a) < string(b)
	})
	return out
}
