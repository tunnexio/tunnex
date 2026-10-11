package policy

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

type runtimeFQDNGenerationReader struct {
	query fqdnresolver.ActiveGenerationQuery
}

func (r runtimeFQDNGenerationReader) ActiveGenerations(ctx context.Context, org uuid.UUID) ([]fqdnresolver.ActiveGeneration, error) {
	return fqdnresolver.ActiveGenerationsWithQuery(ctx, r.query, org)
}
func appendRuntimeFQDNGenerations(ctx context.Context, snapshot *Snapshot, input ipsec.RuntimePolicyInput, entitled bool) error {
	if snapshot == nil || !entitled || (input.FQDNPolicyVersion != 1 && input.FQDNPolicyVersion != 2) || input.Transaction == nil {
		return nil
	}
	snapshot.FQDNResourcesLicensed = true
	return appendActiveFQDNGenerations(ctx, snapshot, runtimeFQDNGenerationReader{input.Transaction}, input.OrgID)
}

// This is an answer-only adapter over the shared compiler. Resolver carriage
// from an FQDN rule is deliberately not copied into ordinary IPsec Grants.
func compileIPsecFQDNGrants(snapshot Snapshot, input ipsec.RuntimePolicyInput) []ipsec.RuntimeFQDNGrant {
	if (input.FQDNPolicyVersion != 1 && input.FQDNPolicyVersion != 2) || input.ConfigurationRevision != 1 || snapshot.Mode != ModeEnforcing || !snapshot.FQDNResourcesLicensed || !snapshot.FQDNResourcesEnabled {
		return nil
	}
	rules := make([]Rule, 0, len(snapshot.Rules))
	for _, rule := range snapshot.Rules {
		if !rule.Disabled && rule.DstKind == "fqdn_resource" && (rule.SrcKind == "cidr" || rule.SrcKind == "site" && rule.SrcSiteID == input.SiteID) {
			rules = append(rules, rule)
		}
	}
	snapshot.Rules = rules
	// Restrict the active resolver context to the exact current provider and its
	// immutable config. The decoder already excludes retired/pending generations.
	resources := make(map[uuid.UUID]FQDNResource)
	for _, r := range snapshot.FQDNResources {
		g := r.Active
		if g == nil || input.CompiledAt.IsZero() || g.ResolvedAt.IsZero() || g.ResolvedAt.After(input.CompiledAt) || !g.FreshUntil.After(g.ResolvedAt) || !g.FreshUntil.After(input.CompiledAt) || g.SelectedSiteID != input.SiteID || g.SelectedGatewayID != input.NodeID || g.IPsecConnectionID != input.ConnectionID || g.IPsecConfigurationRevision != input.ConfigurationRevision {
			continue
		}
		source, err := netip.ParseAddr(g.IPsecSourceAddress)
		if err != nil || !source.Is4() || source.String() != g.IPsecSourceAddress || !source.IsPrivate() || !runtimePolicyWithin(netip.PrefixFrom(source, 32), input.Config.LocalPrefixes) {
			continue
		}
		if _, duplicate := resources[r.ID]; duplicate {
			return nil
		}
		if _, _, _, valid := activeFQDNGeneration(r); valid {
			resources[r.ID] = r
		}
	}
	snapshot.FQDNResources = nil
	for _, r := range resources {
		snapshot.FQDNResources = append(snapshot.FQDNResources, r)
	}
	references := map[uuid.UUID]uuid.UUID{}
	ambiguous := map[uuid.UUID]bool{}
	for _, ref := range snapshot.FQDNRuleReferences {
		if _, exists := references[ref.PolicyRuleID]; exists {
			ambiguous[ref.PolicyRuleID] = true
		}
		references[ref.PolicyRuleID] = ref.FQDNResourceID
	}
	ruleExpiry := map[uuid.UUID]*time.Time{}
	for _, rule := range snapshot.Rules {
		ruleExpiry[rule.ID] = rule.ExpiresAt
	}
	now := time.Now()
	var out []ipsec.RuntimeFQDNGrant
	for _, grant := range Compile(snapshot)[input.NodeID].Allow {
		if !grant.FQDNManaged {
			continue
		}
		rule, err := uuid.Parse(grant.RuleID)
		if err != nil || ambiguous[rule] {
			continue
		}
		resource, exists := resources[references[rule]]
		if !exists {
			continue
		}
		generation, _, _, valid := activeFQDNGeneration(resource)
		source, sourceOK := runtimePolicyPrefix(grant.SrcIP)
		destination, destOK := runtimePolicyPrefix(grant.DstCIDR)
		if !valid || !sourceOK || !destOK || destination.Bits() != 32 || !runtimePolicyWithin(source, input.Config.LocalPrefixes) || !runtimePolicyWithin(destination, input.Config.RemotePrefixes) || grant.PortLow < 0 || grant.PortHigh < 0 || grant.PortLow > 65535 || grant.PortHigh > 65535 {
			continue
		}
		g := resource.Active
		var expires time.Time
		resolverSource := ""
		if input.FQDNPolicyVersion == 2 {
			expires = g.FreshUntil
			if !expires.After(now) || expires.After(now.Add(time.Hour)) {
				continue
			}
			if x := ruleExpiry[rule]; x != nil && x.Before(expires) {
				expires = *x
			}
			if !expires.After(now) || expires.After(now.Add(time.Hour)) {
				continue
			}
			expires = expires.UTC()
			resolverSource = g.IPsecSourceAddress
		}
		out = append(out, ipsec.RuntimeFQDNGrant{ExpiresAt: expires, ResolverSourceAddress: resolverSource, RuntimeGrant: ipsec.RuntimeGrant{Source: source.String(), Destination: destination.String(), Protocol: string(grant.Protocol), PortLow: uint16(grant.PortLow), PortHigh: uint16(grant.PortHigh), RuleID: grant.RuleID}, FQDNManaged: true, ResourceID: resource.ID.String(), Name: generation.Name, Generation: generation.Generation, ResolverConfigID: g.ResolverConfigID.String(), ResolverConfigVersion: g.ResolverConfigVersion, SelectedSiteID: g.SelectedSiteID.String(), SelectedGatewayID: g.SelectedGatewayID.String(), ResolverProfileID: g.ResolverProfileID.String(), ResolverMatchSuffix: g.ResolverMatchSuffix, ConnectionID: g.IPsecConnectionID.String(), ConfigurationRevision: g.IPsecConfigurationRevision})
	}
	sort.Slice(out, func(a, b int) bool {
		x, _ := json.Marshal(out[a])
		y, _ := json.Marshal(out[b])
		return string(x) < string(y)
	})
	return out
}
