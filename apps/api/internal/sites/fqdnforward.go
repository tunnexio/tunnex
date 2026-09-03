package sites

import (
	"net/netip"
	"sort"
)

// MergeResolverForwardsFailClosed combines independently authorized resolver
// sources for the desktop handoff. Equal domain/address pairs de-duplicate. An
// exact domain mapped to different resolver addresses is withheld entirely: the
// desktop cannot truthfully choose between two DNS authorities. Parent/child
// domains remain independent and rely on the OS's longest-suffix selection.
func MergeResolverForwardsFailClosed(groups ...[]DNSForward) []DNSForward {
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
