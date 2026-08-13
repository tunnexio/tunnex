package ipalloc

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAllocateLowestFreeDeterministic(t *testing.T) {
	// Empty pool -> .2 (skips .0 network, .1 gateway).
	ip, err := Allocate("10.99.0.0/24", nil)
	if err != nil || ip != "10.99.0.2" {
		t.Fatalf("want 10.99.0.2, got %q err=%v", ip, err)
	}
	// .2 taken -> .3; deterministic: same inputs, same output.
	for i := 0; i < 3; i++ {
		ip, err = Allocate("10.99.0.0/24", []string{"10.99.0.2"})
		if err != nil || ip != "10.99.0.3" {
			t.Fatalf("want 10.99.0.3 deterministically, got %q err=%v", ip, err)
		}
	}
	// Lowest-free reuses a gap (release/reuse): .2 free, .3 taken -> .2.
	ip, _ = Allocate("10.99.0.0/24", []string{"10.99.0.3", "10.99.0.4"})
	if ip != "10.99.0.2" {
		t.Fatalf("want lowest-free 10.99.0.2 (gap reuse), got %q", ip)
	}
}

func TestReservedAddressesNeverAllocated(t *testing.T) {
	// A /29 = 8 addrs: .0 network, .1 gateway, .2-.6 hosts (5), .7 broadcast.
	cidr := "10.0.0.0/29"
	used := []string{}
	got := map[string]bool{}
	for i := 0; i < 5; i++ {
		ip, err := Allocate(cidr, used)
		if err != nil {
			t.Fatalf("allocation %d failed early: %v", i, err)
		}
		got[ip] = true
		used = append(used, ip)
	}
	// Exhaustion arrives at EXACTLY capacity (5 hosts), cleanly.
	if _, err := Allocate(cidr, used); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("want ErrPoolExhausted at capacity, got %v", err)
	}
	// The reserved addresses were never handed out.
	for _, r := range []string{"10.0.0.0", "10.0.0.1", "10.0.0.7"} {
		if got[r] {
			t.Fatalf("reserved address %s was allocated", r)
		}
	}
	// And exactly .2-.6 were allocated.
	for _, h := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"} {
		if !got[h] {
			t.Fatalf("expected host %s to be allocatable", h)
		}
	}
}

func TestAllocateIgnoresOutOfPoolUsed(t *testing.T) {
	// A stale used-entry from a different pool must not perturb allocation.
	ip, err := Allocate("10.99.0.0/24", []string{"192.168.1.5", "garbage"})
	if err != nil || ip != "10.99.0.2" {
		t.Fatalf("out-of-pool/garbage used should be ignored, got %q err=%v", ip, err)
	}
}

func TestPoolTooSmall(t *testing.T) {
	// /31 and /32 have no allocatable host after reservations.
	if _, err := Allocate("10.0.0.0/31", nil); !errors.Is(err, ErrPoolTooSmall) {
		t.Fatalf("want ErrPoolTooSmall for /31, got %v", err)
	}
}

func TestGatewayCIDR(t *testing.T) {
	gw, err := GatewayCIDR("10.99.0.0/24")
	if err != nil || gw != "10.99.0.1/24" {
		t.Fatalf("want 10.99.0.1/24, got %q err=%v", gw, err)
	}
	// Works from an unmasked input too.
	gw, _ = GatewayCIDR("10.5.0.0/16")
	if gw != "10.5.0.1/16" {
		t.Fatalf("want 10.5.0.1/16, got %q", gw)
	}
}

func TestOrphansShrinkAndGrow(t *testing.T) {
	alloc := []string{"10.99.0.2", "10.99.0.130", "10.99.0.200"}
	// Shrinking 10.99.0.0/24 -> /25 (0-127) strands .130 and .200 (out of range).
	off, err := Orphans("10.99.0.0/25", alloc)
	if err != nil {
		t.Fatal(err)
	}
	if len(off) != 2 || off[0].Addr != "10.99.0.130" || off[1].Addr != "10.99.0.200" {
		t.Fatalf("want [.130 .200] as orphans, got %v", addrs(off))
	}
	// Growing (superset) strands nothing (.2/.130/.200 all inside /23, none on a
	// new reserved addr).
	off, _ = Orphans("10.99.0.0/23", alloc)
	if len(off) != 0 {
		t.Fatalf("grow should strand nothing, got %v", addrs(off))
	}
}

func TestBadCIDR(t *testing.T) {
	if _, err := Allocate("not-a-cidr", nil); !errors.Is(err, ErrBadCIDR) {
		t.Fatalf("want ErrBadCIDR, got %v", err)
	}
	if _, err := Allocate("2001:db8::/64", nil); !errors.Is(err, ErrBadCIDR) {
		t.Fatalf("want ErrBadCIDR for IPv6 (IPv4-only), got %v", err)
	}
}

func addrs(os []Orphan) []string {
	out := make([]string, len(os))
	for i, o := range os {
		out[i] = o.Addr
	}
	return out
}

func eqStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestOrphansOrderingAndOutOfRange covers the shrink orphan set: out-of-range
// addresses AND new-reserved collisions, deterministically ordered by numeric
// address (== assigned_ip order) for a stable, byte-exact 409, each tagged with
// its reason.
func TestOrphansOrderingAndOutOfRange(t *testing.T) {
	// Shrink 10.0.0.0/24 -> /28 (range .0-.15; network .0, gateway .1, broadcast .15).
	got, err := Orphans("10.0.0.0/28", []string{
		"10.0.0.200", // out of range
		"10.0.0.5",   // inside, not reserved -> NOT an orphan
		"10.0.0.15",  // NEW broadcast (numerically inside) -> reserved_collision
		"10.0.0.1",   // NEW gateway -> reserved_collision
		"10.0.0.0",   // NEW network -> reserved_collision
		"10.0.0.20",  // out of range
	})
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	want := []string{"10.0.0.0", "10.0.0.1", "10.0.0.15", "10.0.0.20", "10.0.0.200"}
	if !eqStrs(addrs(got), want) {
		t.Fatalf("orphans = %v, want %v (numeric-asc; .5 excluded)", addrs(got), want)
	}
	wantReasons := []string{ReasonReservedCollision, ReasonReservedCollision, ReasonReservedCollision, ReasonOutOfRange, ReasonOutOfRange}
	for i, o := range got {
		if o.Reason != wantReasons[i] {
			t.Fatalf("orphan %s reason = %q, want %q", o.Addr, o.Reason, wantReasons[i])
		}
	}
}

// TestOrphansCatchesNewReservedCollision is the watch-item (b) edge in isolation:
// a device numerically INSIDE the new range but sitting on what BECOMES the new
// broadcast is orphaned as reserved_collision — a plain range-containment check
// would pass it (which is exactly why Orphans exists, not a bare contains-check).
func TestOrphansCatchesNewReservedCollision(t *testing.T) {
	const dev = "10.0.0.15" // becomes the /28 broadcast
	// Contrast: the device IS numerically inside the new /28 — a naive
	// containment check would NOT flag it...
	if !netip.MustParsePrefix("10.0.0.0/28").Contains(netip.MustParseAddr(dev)) {
		t.Fatalf("precondition: %s must be inside /28 for this contrast to be meaningful", dev)
	}
	// ...but Orphans catches it as a reserved-address collision.
	orphans, err := Orphans("10.0.0.0/28", []string{dev})
	if err != nil || len(orphans) != 1 || orphans[0].Addr != dev || orphans[0].Reason != ReasonReservedCollision {
		t.Fatalf("Orphans must flag %s as reserved_collision; got %+v err=%v", dev, orphans, err)
	}
}

// TestOrphansUnparseableSortLast: a malformed stored address is treated as an
// out_of_range orphan and ordered after valid ones.
func TestOrphansUnparseableSortLast(t *testing.T) {
	got, err := Orphans("10.0.0.0/28", []string{"garbage", "10.0.0.20"})
	if err != nil || !eqStrs(addrs(got), []string{"10.0.0.20", "garbage"}) {
		t.Fatalf("orphans = %v err=%v, want [10.0.0.20 garbage]", addrs(got), err)
	}
}
