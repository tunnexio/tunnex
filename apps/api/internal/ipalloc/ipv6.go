package ipalloc

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/uuid"
)

// IPv6OrgPrefix deterministically selects an organization /64 inside a
// deployment /48. The deployment pool is operator-configured; the org id is
// mixed into the remaining 16 bits so two organizations do not share a prefix
// unless the caller explicitly accepts a hash collision.
func IPv6OrgPrefix(poolCIDR string, orgID uuid.UUID) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(poolCIDR)
	if err != nil || !p.Addr().Is6() || p.Bits() > 48 {
		return netip.Prefix{}, fmt.Errorf("ipv6 pool must be an IPv6 /48 or larger: %q", poolCIDR)
	}
	p = p.Masked()
	h := sha256.Sum256(orgID[:])
	base := p.Addr().As16()
	// A /48 has exactly one 16-bit organization slot before the host portion.
	binary.BigEndian.PutUint16(base[6:8], binary.BigEndian.Uint16(h[:2]))
	return netip.PrefixFrom(netip.AddrFrom16(base), 64), nil
}

// IPv6DeviceAddr maps the already-allocated IPv4 host identity into the org's
// /64. It is stable across reconcile and does not create a second allocator
// race; the IPv4 org-wide uniqueness constraint remains the source identity.
func IPv6DeviceAddr(poolCIDR string, orgID uuid.UUID, ipv4 string) (netip.Addr, error) {
	_ = orgID // retained for API compatibility; poolCIDR is already org-scoped.
	p, err := netip.ParsePrefix(poolCIDR)
	if err != nil || !p.Addr().Is6() || p.Bits() != 64 {
		return netip.Addr{}, fmt.Errorf("device IPv6 pool must be an IPv6 /64: %q", poolCIDR)
	}
	p = p.Masked()
	v4, err := netip.ParseAddr(ipv4)
	if err != nil || !v4.Is4() {
		return netip.Addr{}, fmt.Errorf("invalid IPv4 device address %q", ipv4)
	}
	b := p.Addr().As16()
	v4b := v4.As4()
	binary.BigEndian.PutUint32(b[12:], binary.BigEndian.Uint32(v4b[:]))
	return netip.AddrFrom16(b), nil
}

func IPv6OrgPoolCIDR(poolCIDR string, orgID uuid.UUID) (string, error) {
	p, err := IPv6OrgPrefix(poolCIDR, orgID)
	if err != nil {
		return "", err
	}
	return p.String(), nil
}

func IPv6GatewayCIDR(poolCIDR string, orgID uuid.UUID) (string, error) {
	_ = orgID // retained for API compatibility; poolCIDR is already org-scoped.
	p, err := netip.ParsePrefix(poolCIDR)
	if err != nil || !p.Addr().Is6() || p.Bits() != 64 {
		return "", fmt.Errorf("gateway IPv6 pool must be an IPv6 /64: %q", poolCIDR)
	}
	p = p.Masked()
	b := p.Addr().As16()
	b[15] = 1
	return netip.PrefixFrom(netip.AddrFrom16(b), 64).String(), nil
}
