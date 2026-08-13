// Package subnetguard is the ONE disjointness validator (S8.1 D5/D7). A candidate prefix — a site
// subnet being advertised, a resized device pool, OR a Kubernetes cluster VIP range (S10.3) — must be
// DISJOINT from every allocatable class in the org: the other site subnets, the device pool, the
// clusters' VIP ranges, and reserved ranges. It is called from EVERY seam that can violate the
// invariant so the check can't diverge, with the class carried so each caller renders its own typed error.
//
// The full input set is assembled by Collect (the ONLY constructor of OrgRanges) so a new caller cannot
// silently omit a class — the validator-input-filtering law: every range class joins EVERY seam. A
// hand-built OrgRanges{} is unusable (unexported fields + a `collected` marker) and Check fails CLOSED on
// one; the census test (no OrgRanges{...} literal outside this file) is the compile-adjacent backstop.
//
// The CIDR math is netip.Prefix.Overlaps — stdlib — so ADJACENCY (touching-but-disjoint, e.g.
// 10.0.0.0/24 and 10.0.1.0/24) is NOT an overlap, an EXACT-BOUNDARY subset (10.0.0.0/24 vs 10.0.0.0/25)
// IS, and there is no hand-rolled off-by-one (where these validators actually break).
package subnetguard

import (
	"context"
	"net/netip"

	"github.com/google/uuid"
)

// OverlapClass names which input a candidate collided with (for the caller's typed error).
type OverlapClass string

const (
	ClassSiteSubnet OverlapClass = "site_subnet"
	ClassPool       OverlapClass = "pool"
	ClassVIPRange   OverlapClass = "vip_range" // S10.3: a K8s cluster's synthetic VIP range
	ClassReserved   OverlapClass = "reserved"
)

// Overlap is the first collision found: the existing prefix and its class.
type Overlap struct {
	With  netip.Prefix
	Class OverlapClass
}

// OrgRanges is the complete set of a candidate's forbidden neighbors for an org. Its fields are
// UNEXPORTED and it carries a `collected` marker so the only way to obtain a usable value is Collect —
// a caller cannot hand-assemble a partial set that silently omits a class (e.g. VIP ranges). A
// zero-value OrgRanges{} makes Check fail CLOSED (see Check). Do NOT construct this with a literal
// outside this package; the census test enforces it.
type OrgRanges struct {
	site      []netip.Prefix
	pool      netip.Prefix
	vipRanges []netip.Prefix
	reserved  []netip.Prefix
	collected bool
}

// RangeSource yields the raw CIDR text for each allocatable class of an org. Collect ALWAYS queries
// every class, so a new caller that wires a RangeSource gets VIP ranges (and every future class) for
// free — the seventh caller costs nothing and cannot leak the law.
type RangeSource interface {
	SiteSubnetCIDRs(ctx context.Context, orgID uuid.UUID) ([]string, error)
	PoolCIDR(ctx context.Context, orgID uuid.UUID) (string, error)
	VIPRangeCIDRs(ctx context.Context, orgID uuid.UUID) ([]string, error)
}

// Collect assembles the org's full disjointness input set from the source. It is the ONLY constructor
// of a usable OrgRanges. Reserved ranges (static, non-DB — e.g. link-local) are added via WithReserved.
func Collect(ctx context.Context, src RangeSource, orgID uuid.UUID) (OrgRanges, error) {
	var r OrgRanges
	siteC, err := src.SiteSubnetCIDRs(ctx, orgID)
	if err != nil {
		return OrgRanges{}, err
	}
	r.site = parsePrefixes(siteC)

	poolC, err := src.PoolCIDR(ctx, orgID)
	if err != nil {
		return OrgRanges{}, err
	}
	if p, e := netip.ParsePrefix(poolC); e == nil {
		r.pool = p
	}

	vipC, err := src.VIPRangeCIDRs(ctx, orgID)
	if err != nil {
		return OrgRanges{}, err
	}
	r.vipRanges = parsePrefixes(vipC)

	r.collected = true
	return r, nil
}

// WithReserved returns a copy with the static reserved set added.
func (r OrgRanges) WithReserved(reserved []netip.Prefix) OrgRanges {
	r.reserved = reserved
	return r
}

// WithoutPool returns a copy that excludes the device pool — for the pool-resize caller, which checks a
// NEW pool and must not collide with the OLD one it is replacing. VIP ranges + site subnets stay in, so
// the law does not leak.
func (r OrgRanges) WithoutPool() OrgRanges {
	r.pool = netip.Prefix{}
	return r
}

// Check reports whether candidate is DISJOINT from every class (ok=true), or the FIRST overlap it hit
// (ok=false). Order: site subnets → pool → VIP ranges → reserved, so the class of the first collision is
// stable. A non-Collect'd OrgRanges fails CLOSED (ok=false) — a hand-built value can never wave a
// candidate through.
func Check(candidate netip.Prefix, r OrgRanges) (Overlap, bool) {
	if !r.collected {
		return Overlap{}, false
	}
	c := candidate.Masked()
	for _, s := range r.site {
		if c.Overlaps(s.Masked()) {
			return Overlap{With: s, Class: ClassSiteSubnet}, false
		}
	}
	if r.pool.IsValid() && c.Overlaps(r.pool.Masked()) {
		return Overlap{With: r.pool, Class: ClassPool}, false
	}
	for _, v := range r.vipRanges {
		if c.Overlaps(v.Masked()) {
			return Overlap{With: v, Class: ClassVIPRange}, false
		}
	}
	for _, res := range r.reserved {
		if c.Overlaps(res.Masked()) {
			return Overlap{With: res, Class: ClassReserved}, false
		}
	}
	return Overlap{}, true
}

func parsePrefixes(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if p, e := netip.ParsePrefix(c); e == nil {
			out = append(out, p)
		}
	}
	return out
}
