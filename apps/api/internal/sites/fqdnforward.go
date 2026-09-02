package sites

import (
	"context"
	"net/netip"
	"sort"

	"github.com/google/uuid"
)

// fqdnProfileResolverEndpoint is one client-usable endpoint candidate from an
// active FQDN resolver profile. The database query deliberately returns only
// UDP/53 endpoints: macOS scoped resolvers and Windows NRPT accept a DNS server
// address, but cannot preserve an arbitrary transport or port from the FQDN
// gateway-RPC contract.
type fqdnProfileResolverEndpoint struct {
	ProfileID  uuid.UUID
	Domain     string
	ResolverIP string
}

// listFQDNProfileForwards projects active FQDN resolver-profile suffixes onto
// the existing desktop split-DNS channel. This closes the S21 handoff without
// creating a second client inventory/API path: the routed-ranges poll remains
// the single volatile routes + resolvers channel.
func (s *Service) listFQDNProfileForwards(ctx context.Context, orgID uuid.UUID, prefixes []netip.Prefix) ([]DNSForward, error) {
	rows, err := s.q.ListActiveFQDNProfileForwardCandidates(ctx, orgID)
	if err != nil {
		return nil, err
	}
	candidates := make([]fqdnProfileResolverEndpoint, 0, len(rows))
	for _, row := range rows {
		candidates = append(candidates, fqdnProfileResolverEndpoint{
			ProfileID:  row.ProfileID,
			Domain:     row.Domain,
			ResolverIP: row.ResolverIp,
		})
	}
	return selectFQDNProfileForwards(candidates, prefixes), nil
}

// selectFQDNProfileForwards chooses one reachable resolver address per profile
// suffix. Multiple endpoints inside one profile are ordered deterministically by
// the query; the first reachable UDP/53 address is the OS resolver target. If
// two active Site/Gateway contexts claim the exact same suffix with different
// addresses, that suffix is omitted fail-closed instead of depending on row
// order. Parent/child suffixes remain valid because the OS performs longest-
// suffix matching, like the FQDN profile selector.
func selectFQDNProfileForwards(candidates []fqdnProfileResolverEndpoint, prefixes []netip.Prefix) []DNSForward {
	type profileDomain struct {
		profile uuid.UUID
		domain  string
	}
	perProfile := make(map[profileDomain]string)
	ordered := make([]profileDomain, 0)
	for _, candidate := range candidates {
		domain, ok := NormalizeDomain(candidate.Domain)
		if !ok {
			continue
		}
		ip, err := netip.ParseAddr(candidate.ResolverIP)
		if err != nil || !ip.IsValid() {
			continue
		}
		reachable := false
		for _, prefix := range prefixes {
			if prefix.Contains(ip) {
				reachable = true
				break
			}
		}
		if !reachable {
			continue
		}
		key := profileDomain{profile: candidate.ProfileID, domain: domain}
		if _, exists := perProfile[key]; exists {
			continue
		}
		perProfile[key] = ip.String()
		ordered = append(ordered, key)
	}

	byDomain := make(map[string]string)
	conflicted := make(map[string]bool)
	for _, key := range ordered {
		ip := perProfile[key]
		if previous, exists := byDomain[key.domain]; exists && previous != ip {
			conflicted[key.domain] = true
			continue
		}
		byDomain[key.domain] = ip
	}
	domains := make([]string, 0, len(byDomain))
	for domain := range byDomain {
		if !conflicted[domain] {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	out := make([]DNSForward, 0, len(domains))
	for _, domain := range domains {
		out = append(out, DNSForward{Domain: domain, ResolverIP: byDomain[domain]})
	}
	return out
}

// mergeResolverForwardsFailClosed combines the legacy Site/Kubernetes forwards
// with FQDN-profile forwards. Equal domain/address pairs de-duplicate. An exact
// domain mapped to different resolver addresses is withheld entirely: the
// desktop cannot truthfully choose between two DNS authorities.
func mergeResolverForwardsFailClosed(groups ...[]DNSForward) []DNSForward {
	byDomain := make(map[string]string)
	conflicted := make(map[string]bool)
	for _, group := range groups {
		for _, forward := range group {
			domain, ok := NormalizeDomain(forward.Domain)
			if !ok {
				continue
			}
			ip, err := netip.ParseAddr(forward.ResolverIP)
			if err != nil || !ip.IsValid() {
				continue
			}
			resolver := ip.String()
			if previous, exists := byDomain[domain]; exists && previous != resolver {
				conflicted[domain] = true
				continue
			}
			byDomain[domain] = resolver
		}
	}
	domains := make([]string, 0, len(byDomain))
	for domain := range byDomain {
		if !conflicted[domain] {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	out := make([]DNSForward, 0, len(domains))
	for _, domain := range domains {
		out = append(out, DNSForward{Domain: domain, ResolverIP: byDomain[domain]})
	}
	return out
}
