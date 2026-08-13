package reconcile

import (
	"net"
	"net/netip"
)

// siteRouteSrc + hostIPv4Addrs are CROSS-PLATFORM (pure netip + net.InterfaceAddrs) so BOTH the linux
// wgctrl backend (D2 route src-hint) AND the backend-agnostic reconcile loop (D3 unreachable-subnet health
// signal) read the SAME derivation — one truth, not two.

// hostIPv4Addrs returns the host's global-unicast IPv4 addresses (all interfaces). The D2 src-hint picks
// the one inside an approved local site subnet; the D3 detection uses the same set.
func hostIPv4Addrs() []netip.Addr {
	var out []netip.Addr
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range ifaddrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if v4 := ipnet.IP.To4(); v4 != nil {
				if addr, ok := netip.AddrFromSlice(v4); ok && addr.IsValid() && !addr.IsLoopback() {
					out = append(out, addr)
				}
			}
		}
	}
	return out
}

// siteRouteSrc picks the gateway's SOURCE for its site routes (D2): the host address inside one of the
// gateway's OWN approved site subnets (localSubnets — the CP's authoritative answer). Returns (addr,true)
// on a match. Returns (_, false) when localSubnets is empty (no site source to hint — the route still
// programs identically to today) OR when localSubnets is non-empty but NO host address is inside any of
// them — the D3 refuse-loudly case (a gateway advertising a subnet it isn't on, e.g. bridge-trapped wg0).
// PURE. `hadSubnets` distinguishes the two false cases (empty vs no-match): (had && !ok) IS the D3 signal.
func siteRouteSrc(localSubnets []string, hostAddrs []netip.Addr) (src netip.Addr, ok bool, hadSubnets bool) {
	if len(localSubnets) == 0 {
		return netip.Addr{}, false, false
	}
	for _, s := range localSubnets {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		for _, a := range hostAddrs {
			if p.Contains(a) {
				return a, true, true
			}
		}
	}
	return netip.Addr{}, false, true
}
