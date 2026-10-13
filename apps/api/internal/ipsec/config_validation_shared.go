package ipsec

import "net/netip"

// validateRoutedIPv4Pair is shared admission for local and remote site ranges.
// It validates explicit allowlists, not IPsec traffic selectors or BGP routes.
func validateRoutedIPv4Pair(localRaw, remoteRaw []string) ([]netip.Prefix, error) {
	local, err := routedPrefixes(localRaw, "local_prefixes")
	if err != nil {
		return nil, err
	}
	remote, err := routedPrefixes(remoteRaw, "remote_prefixes")
	if err != nil {
		return nil, err
	}
	for _, l := range local {
		for _, r := range remote {
			if l.Overlaps(r) {
				return nil, configError("prefix_overlap", "remote_prefixes", 0)
			}
		}
	}
	return append(local, remote...), nil
}
