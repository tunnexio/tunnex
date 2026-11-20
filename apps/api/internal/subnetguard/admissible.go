package subnetguard

import "net/netip"

// Refusal names why a candidate may not be routed through a site at all. The values are the API error
// codes, so the caller renders them without a second mapping.
type Refusal string

const (
	RefusalNotIPv4    Refusal = "range_not_ipv4"
	RefusalNotPrivate Refusal = "range_not_private"
	RefusalTooWide    Refusal = "range_too_wide"
)

// routableBlocks are the only address blocks a site range may sit inside (SSI-0 D2): the RFC 1918 private
// blocks and the RFC 6598 shared address space. Everything else is someone else's address space: routing
// it through a site would pull that traffic off every other gateway and device in the organization.
var routableBlocks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

// RoutableBlocks returns the admissible blocks for display in a refusal message.
func RoutableBlocks() []netip.Prefix {
	return append([]netip.Prefix(nil), routableBlocks...)
}

// Admissible reports whether candidate may be advertised as a site range (SSI-1, finding F1). It is a
// STATIC rule with no organization input, and it is asked BEFORE Check: disjointness says a range does not
// collide with anything the organization already owns, which is true of almost any public range.
//
// A candidate is admissible only when it lies wholly inside one routable block. One that contains or
// straddles a block is too wide; one that touches no block is not private.
func Admissible(candidate netip.Prefix) (Refusal, bool) {
	if !candidate.IsValid() || !candidate.Addr().Is4() {
		return RefusalNotIPv4, false
	}
	c := candidate.Masked()
	overlapsABlock := false
	for _, b := range routableBlocks {
		if c.Bits() >= b.Bits() && b.Contains(c.Addr()) {
			return "", true
		}
		if c.Overlaps(b) {
			overlapsABlock = true
		}
	}
	if overlapsABlock {
		return RefusalTooWide, false
	}
	return RefusalNotPrivate, false
}
