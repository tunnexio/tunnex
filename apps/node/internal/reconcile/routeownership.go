package reconcile

import "net/netip"

// siteRouteMetric tags every S8.2 kernel route owned by the agent.
const siteRouteMetric = 8021

// returnRulePriority is reserved by Tunnex for device-pool return routing.
const returnRulePriority = 100

// canonicalRoutePrefix normalizes route destinations exactly as the Linux
// route reader does. `ip route show` prints host routes without /32 or /128.
func canonicalRoutePrefix(token string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(token); err == nil {
		return prefix.Masked(), true
	}
	if addr, err := netip.ParseAddr(token); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}
