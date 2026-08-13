// Package ipalloc is the org tunnel-address allocator: deterministic, collision-
// free assignment from an org's flat pool CIDR. It is pure (CIDR + used-set in,
// address out) so every acceptance property — reserved addresses, exhaustion at
// exactly capacity, release/reuse, CIDR-resize safety, determinism — is unit
// testable. The DB's UNIQUE(org_id, assigned_ip) is the concurrency backstop;
// this package decides WHICH address, the index guarantees no two ever collide.
package ipalloc

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

var (
	// ErrPoolExhausted means every allocatable host in the pool is taken.
	ErrPoolExhausted = errors.New("ip pool exhausted")
	// ErrBadCIDR means the pool CIDR is not a valid IPv4 prefix.
	ErrBadCIDR = errors.New("invalid pool CIDR")
	// ErrPoolTooSmall means the CIDR has no allocatable host after reservations.
	ErrPoolTooSmall = errors.New("pool CIDR too small")
)

// Two addresses are reserved at the low end (network, gateway) and one at the top
// (broadcast), structurally — derived from the CIDR, never from loop bounds.
const reservedLow = 2 // .0 network, .1 gateway (the node interface)

// Allocate returns the lowest free host in the pool, deterministically (same
// pool + same used-set → same address), skipping the reserved network/gateway/
// broadcast addresses. used addresses outside the pool are ignored.
func Allocate(cidr string, used []string) (string, error) {
	p, err := prefix(cidr)
	if err != nil {
		return "", err
	}
	network := toU32(p.Addr())
	hostBits := 32 - p.Bits()
	if hostBits < 2 { // need network + gateway + >=1 host + broadcast
		return "", ErrPoolTooSmall
	}
	broadcast := network + (uint32(1) << hostBits) - 1
	first := network + reservedLow // skip .0 network and .1 gateway
	last := broadcast - 1          // skip broadcast

	taken := make(map[uint32]bool, len(used))
	for _, s := range used {
		if a, err := netip.ParseAddr(s); err == nil && p.Contains(a) {
			taken[toU32(a)] = true
		}
	}
	for u := first; u <= last; u++ {
		if !taken[u] {
			return fromU32(u).String(), nil
		}
	}
	return "", ErrPoolExhausted
}

// GatewayCIDR returns the gateway (node interface) address with the pool's prefix
// length, e.g. "10.99.0.1/24" — the first usable host in the pool.
func GatewayCIDR(cidr string) (string, error) {
	p, err := prefix(cidr)
	if err != nil {
		return "", err
	}
	if 32-p.Bits() < 1 {
		return "", ErrPoolTooSmall
	}
	gw := fromU32(toU32(p.Addr()) + 1)
	return fmt.Sprintf("%s/%d", gw, p.Bits()), nil
}

// Orphan-reason values (kept in sync with the OpenAPI Orphan.reason enum).
const (
	// ReasonOutOfRange: the address falls outside the new range entirely.
	ReasonOutOfRange = "out_of_range"
	// ReasonReservedCollision: the address is numerically INSIDE the new range but
	// lands on its network/gateway/broadcast — looks fine to the eye, still stranded.
	ReasonReservedCollision = "reserved_collision"
)

// Orphan is a stranded allocation plus WHY it's stranded. The reason matters to
// an admin: an out_of_range address is visibly outside the new range, but a
// reserved_collision address is numerically INSIDE it and looks fine ("why is
// this device blocking the shrink?") — so the 409 must say which.
type Orphan struct {
	Addr   string
	Reason string
}

// Orphans returns the allocations a resize to newCIDR would strand: those OUTSIDE
// the new range, OR those colliding with the new range's RESERVED addresses
// (network, gateway, broadcast). The reserved case is the subtle one — a device
// numerically INSIDE the new range but sitting on .0/.1/broadcast is still
// orphaned, because the allocator will never hand those out and they can't remain
// assigned (a plain range-containment check alone misses it). Deterministically ordered by numeric
// address ascending (== assigned_ip order for valid IPv4), so the resize 409 is
// stable and byte-exact-testable; unparseable inputs are treated as out_of_range
// orphans and sorted last by their raw string.
func Orphans(newCIDR string, allocated []string) ([]Orphan, error) {
	p, err := prefix(newCIDR)
	if err != nil {
		return nil, err
	}
	network := toU32(p.Addr())
	hostBits := 32 - p.Bits()
	// For a /31 or /32 there is no distinct broadcast; the resize validation
	// refuses such a pool (too small) before this runs, but stay well-defined:
	// treat every reserved slot as the network address in that degenerate case.
	broadcast := network
	if hostBits >= 1 {
		broadcast = network + (uint32(1) << hostBits) - 1
	}
	reserved := map[uint32]bool{network: true, network + 1: true, broadcast: true}

	type offender struct {
		u      uint32
		ok     bool
		addr   string
		reason string
	}
	var offenders []offender
	for _, s := range allocated {
		a, perr := netip.ParseAddr(s)
		if perr != nil || !a.Is4() {
			offenders = append(offenders, offender{addr: s, ok: false, reason: ReasonOutOfRange})
			continue
		}
		u := toU32(a)
		switch {
		case !p.Contains(a):
			offenders = append(offenders, offender{u: u, ok: true, addr: s, reason: ReasonOutOfRange})
		case reserved[u]:
			offenders = append(offenders, offender{u: u, ok: true, addr: s, reason: ReasonReservedCollision})
		}
	}
	// Deterministic order: valid addresses by numeric value asc, then unparseable
	// ones by raw string.
	sort.Slice(offenders, func(i, j int) bool {
		if offenders[i].ok != offenders[j].ok {
			return offenders[i].ok // valid (ok) before invalid
		}
		if offenders[i].ok {
			return offenders[i].u < offenders[j].u
		}
		return offenders[i].addr < offenders[j].addr
	})
	out := make([]Orphan, len(offenders))
	for i, o := range offenders {
		out[i] = Orphan{Addr: o.addr, Reason: o.reason}
	}
	return out, nil
}

// prefix parses cidr into a canonical (masked) IPv4 prefix.
func prefix(cidr string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, ErrBadCIDR
	}
	return p.Masked(), nil
}

func toU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromU32(u uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}

// InPool reports whether ip is inside cidr. Used by the cascade restore before reclaiming a remembered address
// (S13.1 review fold #14): 0059 stopped clearing assigned_ip so a revoked row remembers what it held, but the
// pool can be SHRUNK while those rows are invisible to the shrink guard — which only inspects live allocations.
// Reclaiming then hands a device an address outside its own org's pool: no gateway routes it, and every surface
// reads clean. Taken-ness and validity are different questions, and only one of them was being asked.
func InPool(cidr, ip string) bool {
	p, err := prefix(cidr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return p.Contains(a)
}
