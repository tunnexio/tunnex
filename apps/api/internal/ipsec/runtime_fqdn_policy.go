package ipsec

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdn"
	"net/netip"
	"strings"
	"time"
)

func validRuntimeFQDNPolicy(policy RuntimePolicy, input RuntimePolicyInput) bool {
	if len(policy.FQDNGrants) == 0 {
		return policy.FQDNPolicyVersion == 0
	}
	if (input.FQDNPolicyVersion != 1 && input.FQDNPolicyVersion != 2) || policy.FQDNPolicyVersion != input.FQDNPolicyVersion || input.ConfigurationRevision != 1 {
		return false
	}
	seen := make(map[RuntimeFQDNGrant]bool)
	for _, g := range policy.FQDNGrants {
		if !g.FQDNManaged || seen[g] || g.ConnectionID != input.ConnectionID.String() || g.ConfigurationRevision != input.ConfigurationRevision || g.SelectedSiteID != input.SiteID.String() || g.SelectedGatewayID != input.NodeID.String() || !runtimeDigest(g.Generation) || g.ResolverConfigVersion < 1 {
			return false
		}
		for _, raw := range []string{g.RuleID, g.ResourceID, g.ResolverConfigID, g.ResolverProfileID} {
			id, err := uuid.Parse(raw)
			if err != nil || id == uuid.Nil || id.String() != raw {
				return false
			}
		}
		name, err := fqdn.Normalize(g.Name)
		if err != nil || name != g.Name {
			return false
		}
		if g.ResolverMatchSuffix != "" {
			suffix, err := fqdn.Normalize("resolver-root." + g.ResolverMatchSuffix)
			if err != nil || suffix != "resolver-root."+g.ResolverMatchSuffix || (name != g.ResolverMatchSuffix && !strings.HasSuffix(name, "."+g.ResolverMatchSuffix)) {
				return false
			}
		}
		source, err := netip.ParsePrefix(g.Source)
		if err != nil || !source.Addr().Is4() || source != source.Masked() || source.String() != g.Source || !runtimeFQDNWithin(source, input.Config.LocalPrefixes) {
			return false
		}
		destination, err := netip.ParsePrefix(g.Destination)
		if err != nil || !destination.Addr().Is4() || destination.Bits() != 32 || destination.String() != g.Destination || !runtimeFQDNWithin(destination, input.Config.RemotePrefixes) || !runtimeFQDNAddressSafe(destination.Addr()) {
			return false
		}
		if g.Protocol != "any" && g.Protocol != "tcp" && g.Protocol != "udp" || g.PortLow > g.PortHigh || (g.Protocol == "any" && (g.PortLow != 0 || g.PortHigh != 0)) || (g.Protocol != "any" && g.PortLow == 0 && g.PortHigh != 0) {
			return false
		}
		if policy.FQDNPolicyVersion == 1 {
			if !g.ExpiresAt.IsZero() || g.ResolverSourceAddress != "" {
				return false
			}
		} else {
			now := time.Now()
			source, err := netip.ParseAddr(g.ResolverSourceAddress)
			if !g.ExpiresAt.After(now) || g.ExpiresAt.After(now.Add(time.Hour)) || err != nil || source.String() != g.ResolverSourceAddress || !source.Is4() || !source.IsPrivate() || !runtimeFQDNWithin(netip.PrefixFrom(source, 32), input.Config.LocalPrefixes) {
				return false
			}
		}
		seen[g] = true
	}
	return true
}
func runtimeFQDNWithin(prefix netip.Prefix, ranges []string) bool {
	for _, raw := range ranges {
		outer, err := netip.ParsePrefix(raw)
		if err == nil && outer.Addr().Is4() && outer == outer.Masked() && outer.Bits() <= prefix.Bits() && outer.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
func runtimeFQDNAddressSafe(address netip.Addr) bool {
	if !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() {
		return false
	}
	for _, raw := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "169.254.169.254/32"} {
		if netip.MustParsePrefix(raw).Contains(address) {
			return false
		}
	}
	return true
}
