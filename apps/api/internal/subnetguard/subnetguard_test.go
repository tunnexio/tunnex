package subnetguard

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// mk builds a collected OrgRanges directly (same-package access to the unexported fields). Test-only —
// production code MUST go through Collect (enforced by TestCensusNoHandBuiltOrgRanges).
func mk(site []netip.Prefix, pool netip.Prefix, vip, reserved []netip.Prefix) OrgRanges {
	return OrgRanges{site: site, pool: pool, vipRanges: vip, reserved: reserved, collected: true}
}

// TestCheck pins the disjointness validator's CIDR math — especially the ADJACENCY vs EXACT-BOUNDARY
// edges, where off-by-one bugs hide. Table-driven; one validator, four classes.
func TestCheck(t *testing.T) {
	ranges := mk(
		[]netip.Prefix{p("10.20.0.0/24"), p("10.21.0.0/24")},
		p("10.99.0.0/24"),
		[]netip.Prefix{p("100.64.0.0/16")}, // a cluster VIP range
		[]netip.Prefix{p("192.168.255.0/24")},
	)
	cases := []struct {
		name      string
		candidate string
		wantOK    bool
		wantClass OverlapClass
	}{
		{"fully disjoint", "10.30.0.0/24", true, ""},
		{"adjacent-above a site subnet → disjoint", "10.20.1.0/24", true, ""},
		{"adjacent to the pool → disjoint", "10.99.1.0/24", true, ""},
		{"identical to a site subnet → overlap", "10.20.0.0/24", false, ClassSiteSubnet},
		{"subset of a site subnet (boundary) → overlap", "10.20.0.0/25", false, ClassSiteSubnet},
		{"superset containing a site subnet → overlap", "10.20.0.0/16", false, ClassSiteSubnet},
		{"overlaps the pool → pool class", "10.99.0.128/25", false, ClassPool},
		{"overlaps a VIP range → vip_range class", "100.64.5.0/24", false, ClassVIPRange},
		{"contains a VIP range → vip_range class", "100.64.0.0/12", false, ClassVIPRange},
		{"overlaps a reserved range → reserved class", "192.168.255.64/26", false, ClassReserved},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ov, ok := Check(p(c.candidate), ranges)
			if ok != c.wantOK {
				t.Fatalf("Check ok=%v, want %v (overlap=%+v)", ok, c.wantOK, ov)
			}
			if !ok && ov.Class != c.wantClass {
				t.Fatalf("overlap class=%q, want %q", ov.Class, c.wantClass)
			}
		})
	}
}

// TestCheckClassOrder: site → pool → vip → reserved. A candidate overlapping several reports site first.
func TestCheckClassOrder(t *testing.T) {
	ranges := mk([]netip.Prefix{p("10.20.0.0/24")}, p("10.99.0.0/24"), []netip.Prefix{p("10.5.0.0/24")}, nil)
	ov, ok := Check(p("10.0.0.0/8"), ranges)
	if ok || ov.Class != ClassSiteSubnet {
		t.Fatalf("first overlap must be the site-subnet class, got ok=%v class=%q", ok, ov.Class)
	}
}

// TestZeroValueFailsClosed: a hand-built (non-Collect'd) OrgRanges must never wave a candidate through —
// Check fails CLOSED on the missing `collected` marker. This is the runtime backstop to the census red.
func TestZeroValueFailsClosed(t *testing.T) {
	if _, ok := Check(p("10.30.0.0/24"), OrgRanges{}); ok {
		t.Fatal("a zero-value OrgRanges must FAIL CLOSED (ok=false) — never pass a candidate")
	}
}

// TestWithoutPoolExcludesPoolNotVIP: the pool-resize caller drops the OLD pool but VIP ranges + site
// subnets stay in — the law does not leak through WithoutPool.
func TestWithoutPoolExcludesPoolNotVIP(t *testing.T) {
	ranges := mk([]netip.Prefix{p("10.20.0.0/24")}, p("10.99.0.0/24"), []netip.Prefix{p("100.64.0.0/16")}, nil)
	// A candidate overlapping the OLD pool passes once the pool is excluded.
	if _, ok := Check(p("10.99.0.128/25"), ranges.WithoutPool()); !ok {
		t.Fatal("WithoutPool must exclude the pool (a resize's new pool may overlap the old one)")
	}
	// ...but a VIP-range overlap STILL refuses.
	if ov, ok := Check(p("100.64.5.0/24"), ranges.WithoutPool()); ok || ov.Class != ClassVIPRange {
		t.Fatalf("WithoutPool must keep VIP ranges in, got ok=%v class=%q", ok, ov.Class)
	}
}

type fakeSource struct {
	site, vip []string
	pool      string
}

func (f fakeSource) SiteSubnetCIDRs(context.Context, uuid.UUID) ([]string, error) { return f.site, nil }
func (f fakeSource) PoolCIDR(context.Context, uuid.UUID) (string, error)          { return f.pool, nil }
func (f fakeSource) VIPRangeCIDRs(context.Context, uuid.UUID) ([]string, error)   { return f.vip, nil }

// TestCollectIncludesEveryClass: Collect ALWAYS pulls site subnets, pool, AND VIP ranges — so a caller
// that wires a RangeSource cannot omit VIP ranges (F2).
func TestCollectIncludesEveryClass(t *testing.T) {
	src := fakeSource{site: []string{"10.20.0.0/24"}, pool: "10.99.0.0/24", vip: []string{"100.64.0.0/16"}}
	r, err := Collect(context.Background(), src, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	// The VIP range is present: a candidate inside it refuses with the vip class.
	if ov, ok := Check(p("100.64.1.0/24"), r); ok || ov.Class != ClassVIPRange {
		t.Fatalf("Collect must include VIP ranges, got ok=%v class=%q", ok, ov.Class)
	}
	// And the pool + site are present too.
	if ov, _ := Check(p("10.99.0.0/24"), r); ov.Class != ClassPool {
		t.Fatalf("Collect must include the pool, got class=%q", ov.Class)
	}
}

// TestCensusNoHandBuiltOrgRanges is the F2 census red: OrgRanges may be constructed ONLY inside this
// package (by Collect / the test helper). A literal anywhere else re-opens the law leak — a partial or
// empty set waved through Check. Grep the api tree; the only allowed hits are this package's own files.
func TestCensusNoHandBuiltOrgRanges(t *testing.T) {
	// cwd = this package dir; ../.. = apps/api. grep exits 1 with no matches (fine), >1 on error.
	// No --include (BusyBox grep in the test container lacks it) — filter to .go paths in Go instead.
	out, err := exec.Command("grep", "-rn", "OrgRanges{", "../..").CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return // no matches at all — trivially clean
		}
		t.Fatalf("census grep failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		path, _, _ := strings.Cut(line, ":")
		if !strings.HasSuffix(path, ".go") {
			continue // only Go source is in scope for the law
		}
		if strings.Contains(line, "internal/subnetguard/") {
			continue // this package IS the constructor's home
		}
		t.Fatalf("OrgRanges{ literal outside subnetguard (the law leaks here — go through Collect):\n%s", line)
	}
}
