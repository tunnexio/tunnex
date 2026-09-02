package policy

import (
	"context"
	"net/netip"
	"sort"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// DeviceFQDNForwards projects only the FQDN resolver dependencies authorized
// for one active device. The caller owns device authentication; the routed-
// ranges HTTP handler validates active ownership through nodes.DeviceDial before
// invoking this method.
//
// The projection is derived from the same canonical snapshot as enforcement.
// It never enumerates organization-wide resolver profiles and never persists a
// synthetic resource or policy rule. A parent rule disappearing from the next
// snapshot removes its resolver forward automatically.
func (s *Service) DeviceFQDNForwards(ctx context.Context, orgID, deviceID uuid.UUID, routedRanges []string) ([]policyspec.DNSForward, error) {
	snapshot, err := s.BuildSnapshot(ctx, orgID)
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, 0, len(routedRanges))
	for _, raw := range routedRanges {
		if prefix, parseErr := netip.ParsePrefix(raw); parseErr == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return deviceFQDNForwardsFromSnapshot(snapshot, deviceID, prefixes), nil
}

// deviceFQDNForwardsFromSnapshot is the pure per-device projection. Source
// matching mirrors Compile: user/group/agent/agent-group parents authorize only
// their matching active device. Site/CIDR sources never become desktop resolver
// state. Exact-suffix authority conflicts are withheld instead of depending on
// rule or database order.
func deviceFQDNForwardsFromSnapshot(snapshot Snapshot, deviceID uuid.UUID, routedPrefixes []netip.Prefix) []policyspec.DNSForward {
	if snapshot.Mode == ModeOff || !snapshot.FQDNResourcesLicensed || !snapshot.FQDNResourcesEnabled || deviceID == uuid.Nil {
		return []policyspec.DNSForward{}
	}

	var device Device
	foundDevice := false
	for _, candidate := range snapshot.Devices {
		if candidate.ID != deviceID || candidate.AssignedIP == "" {
			continue
		}
		if foundDevice { // ambiguous compiler input is never last-write-wins
			return []policyspec.DNSForward{}
		}
		device, foundDevice = candidate, true
	}
	if !foundDevice {
		return []policyspec.DNSForward{}
	}

	ownerGroups := make(map[uuid.UUID]bool)
	for _, membership := range snapshot.Memberships {
		if membership.UserID == device.UserID {
			ownerGroups[membership.GroupID] = true
		}
	}
	agentGroups := make(map[uuid.UUID]bool)
	for _, membership := range snapshot.AgentGroupMemberships {
		if membership.DeviceID == device.ID {
			agentGroups[membership.GroupID] = true
		}
	}

	resources := make(map[uuid.UUID]FQDNResource, len(snapshot.FQDNResources))
	ambiguousResources := make(map[uuid.UUID]bool)
	for _, resource := range snapshot.FQDNResources {
		if _, exists := resources[resource.ID]; exists {
			ambiguousResources[resource.ID] = true
			continue
		}
		resources[resource.ID] = resource
	}
	references := make(map[uuid.UUID]uuid.UUID)
	ambiguousReferences := make(map[uuid.UUID]bool)
	for _, reference := range snapshot.FQDNRuleReferences {
		if reference.PolicyRuleID == uuid.Nil || reference.FQDNResourceID == uuid.Nil {
			ambiguousReferences[reference.PolicyRuleID] = true
			continue
		}
		if _, exists := references[reference.PolicyRuleID]; exists {
			ambiguousReferences[reference.PolicyRuleID] = true
			continue
		}
		references[reference.PolicyRuleID] = reference.FQDNResourceID
	}
	selectedGateways := make(map[[2]uuid.UUID]bool)
	for _, siteNode := range snapshot.SiteNodes {
		if siteNode.SiteID != uuid.Nil && siteNode.NodeID != uuid.Nil {
			selectedGateways[[2]uuid.UUID{siteNode.SiteID, siteNode.NodeID}] = true
		}
	}

	bySuffix := make(map[string]string)
	conflicted := make(map[string]bool)
	for _, rule := range snapshot.Rules {
		if rule.Disabled || rule.DstKind != "fqdn_resource" || !ruleMatchesDevice(rule, device, ownerGroups, agentGroups) {
			continue
		}
		resourceID, referenced := references[rule.ID]
		resource, exists := resources[resourceID]
		if !referenced || ambiguousReferences[rule.ID] || !exists || ambiguousResources[resourceID] || resource.Active == nil {
			continue
		}
		if !selectedGateways[[2]uuid.UUID{resource.Active.SelectedSiteID, resource.Active.SelectedGatewayID}] {
			continue
		}
		_, _, resolvers, active := activeFQDNGeneration(resource)
		if !active {
			continue
		}
		suffix, validSuffix := normalizeResolverMatchSuffix(resource.Active.ResolverMatchSuffix)
		if !validSuffix || suffix == "" {
			continue // a legacy/default resolver has no honest scoped suffix to install
		}
		selected, reachable := selectFirstReachableResolverAddress(resolvers, routedPrefixes)
		if !reachable {
			continue
		}
		resolver := netip.MustParsePrefix(selected).Addr().String()
		if previous, exists := bySuffix[suffix]; exists && previous != resolver {
			conflicted[suffix] = true
			continue
		}
		bySuffix[suffix] = resolver
	}

	suffixes := make([]string, 0, len(bySuffix))
	for suffix := range bySuffix {
		if !conflicted[suffix] {
			suffixes = append(suffixes, suffix)
		}
	}
	sort.Strings(suffixes)
	out := make([]policyspec.DNSForward, 0, len(suffixes))
	for _, suffix := range suffixes {
		out = append(out, policyspec.DNSForward{Domain: suffix, ResolverIP: bySuffix[suffix]})
	}
	return out
}

func ruleMatchesDevice(rule Rule, device Device, ownerGroups, agentGroups map[uuid.UUID]bool) bool {
	switch rule.SrcKind {
	case "agent_group":
		return agentGroups[rule.SrcAgentGroupID]
	case "agent":
		return rule.SrcDeviceID == device.ID
	case "user":
		return rule.SrcUserID == device.UserID
	default:
		return ownerGroups[rule.SrcGroupID]
	}
}

// selectFirstReachableResolverAddress returns the first resolver candidate
// covered by the device's routed prefixes. Candidate order is resolver-profile
// endpoint order and is therefore authoritative: callers must not sort it.
//
// The returned value is a canonical host prefix because the same selection is
// consumed by the policy compiler. Invalid, unusable, or unrouted candidates
// are skipped; no reachable candidate is a fail-closed empty result.
func selectFirstReachableResolverAddress(candidates []string, routedPrefixes []netip.Prefix) (string, bool) {
	for _, raw := range candidates {
		var addr netip.Addr
		if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Bits() == prefix.Addr().BitLen() {
			addr = prefix.Addr()
		} else if parsed, err := netip.ParseAddr(raw); err == nil {
			addr = parsed
		}
		if !usableResolverAddress(addr) {
			continue
		}
		for _, prefix := range routedPrefixes {
			if prefix.IsValid() && prefix.Contains(addr) {
				return netip.PrefixFrom(addr, addr.BitLen()).String(), true
			}
		}
	}
	return "", false
}
