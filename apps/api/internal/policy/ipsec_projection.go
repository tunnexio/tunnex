package policy

import (
	"net/netip"

	"github.com/google/uuid"
)

// IPsecNetwork is qualified runtime input, never a disabled configuration's
// implicit grant. The authoritative runtime service is not wired in this slice.
type IPsecNetwork struct {
	ConnectionID      uuid.UUID
	AssignedGatewayID uuid.UUID
	LocalSiteID       uuid.UUID
	RemotePrefixes    []string
}

// Refuse all IPsec placement on inconsistent projection input. Existing
// WireGuard inputs/placement are deliberately not rewritten or invalidated.
func validatedIPsecNetworks(s Snapshot) []IPsecNetwork {
	seen := map[uuid.UUID]bool{}
	var remote []netip.Prefix
	for _, n := range s.IPsecNetworks {
		if n.ConnectionID == uuid.Nil || n.AssignedGatewayID == uuid.Nil || n.LocalSiteID == uuid.Nil || seen[n.ConnectionID] || len(n.RemotePrefixes) == 0 || len(n.RemotePrefixes) > 64 {
			return nil
		}
		seen[n.ConnectionID] = true
		bound := false
		for _, sn := range s.SiteNodes {
			if sn.SiteID == n.LocalSiteID && sn.NodeID == n.AssignedGatewayID {
				bound = true
				break
			}
		}
		if !bound {
			return nil
		}
		for _, raw := range n.RemotePrefixes {
			p, ok := canonicalIPsecPrefix(raw)
			if !ok {
				return nil
			}
			for _, other := range remote {
				if p.Overlaps(other) {
					return nil
				}
			}
			for _, local := range s.SiteSubnets {
				if l, err := netip.ParsePrefix(local.CIDR); err == nil && p.Overlaps(l) {
					return nil
				}
			}
			remote = append(remote, p)
		}
	}
	return s.IPsecNetworks
}
func canonicalIPsecPrefix(raw string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(raw)
	return p, err == nil && p.Addr().Is4() && p.Bits() > 0 && p == p.Masked() && p.String() == raw
}
func ipsecSourceNetwork(raw string, networks []IPsecNetwork) (IPsecNetwork, bool) {
	p, ok := canonicalIPsecPrefix(raw)
	if !ok {
		return IPsecNetwork{}, false
	}
	for _, n := range networks {
		for _, rawRemote := range n.RemotePrefixes {
			r, _ := netip.ParsePrefix(rawRemote)
			if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
				return n, true
			}
		}
	}
	return IPsecNetwork{}, false
}
func ipsecLocalResource(raw string, site uuid.UUID, siteCIDRs map[uuid.UUID][]string) bool {
	p, ok := canonicalIPsecPrefix(raw)
	if !ok {
		return false
	}
	for _, rawLocal := range siteCIDRs[site] {
		l, err := netip.ParsePrefix(rawLocal)
		if err == nil && l.Addr().Is4() && l == l.Masked() && l.Bits() <= p.Bits() && l.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
