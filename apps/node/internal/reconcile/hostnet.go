package reconcile

import (
	"net/netip"
	"sort"
	"strings"
)

// SSI-7 — the gateway checks site routes against the networks its own host is attached to.
//
// Two defects shared one cause: the agent programmed and judged site routes without looking at the host.
//
//   - A REMOTE range that overlaps a network the host is directly attached to was installed as a wg0 route
//     regardless. The control plane cannot catch this: it knows the organization's ranges, not the bridges
//     and container networks on a gateway host.
//   - A LOCAL range was called reachable only when a host address sat inside it. A range the gateway reaches
//     through its LAN without being in it (a peered network, another subnet of the same VPC) raised
//     site_subnet_unreachable for a path that worked.

// HostNetwork is one IPv4 network the gateway host is directly attached to.
type HostNetwork struct {
	Prefix netip.Prefix // the connected network
	Addr   netip.Addr   // the host's own address in it
	Iface  string
	// Tunnel marks an overlay interface (the agent's WireGuard device, an OpenVPN tun, an IPsec interface).
	// Site routes belong there, so a tunnel network never counts as a collision or as LAN reachability.
	Tunnel bool
}

// HostNetworkProbe reads the host. Both functions are injected so the plan below stays pure.
type HostNetworkProbe struct {
	// Networks lists the connected IPv4 networks.
	Networks func() []HostNetwork
	// RouteDev reports the interface the kernel would use to reach addr, ignoring the agent's own site
	// routes. ok=false means the kernel has no route.
	RouteDev func(addr netip.Addr) (dev string, ok bool)
}

// RouteConflict is a remote site range the agent refused to route because the host is attached to an
// overlapping network.
type RouteConflict struct {
	CIDR    string // the remote range
	Network string // the connected network it overlaps
	Iface   string
}

// siteRoutePlan is what one reconcile should do about site routes, derived from one host snapshot.
type siteRoutePlan struct {
	Routes           []string        // remote ranges that are safe to program
	Conflicts        []RouteConflict // remote ranges refused
	Src              netip.Addr      // route source hint, when a LAN address sits inside a local range
	SrcOK            bool
	LocalUnreachable []string // local ranges the host cannot deliver
}

// degraded reports whether the gateway cannot do what the control plane asked of it.
func (p siteRoutePlan) degraded() bool {
	return len(p.Conflicts) > 0 || len(p.LocalUnreachable) > 0
}

// signature is a stable string for onset-only logging.
func (p siteRoutePlan) signature() string {
	parts := make([]string, 0, len(p.Conflicts)+len(p.LocalUnreachable))
	for _, c := range p.Conflicts {
		parts = append(parts, "conflict:"+c.CIDR+"@"+c.Iface)
	}
	for _, l := range p.LocalUnreachable {
		parts = append(parts, "unreachable:"+l)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// planSiteRoutes decides, from one snapshot of the host's networks, which remote ranges to program and
// whether each local range can actually be delivered. PURE.
//
// Remote range: refused when it overlaps a connected non-tunnel network. Installing it would either be
// shadowed by the connected route (the site is silently unreachable) or, when more specific, pull the
// host's own LAN or container traffic into the tunnel.
//
// Local range: deliverable when a LAN address of the host sits inside it, or when the kernel routes it out
// of a non-tunnel interface. The second clause is what admits a peered network. A range the kernel would
// send into a tunnel, or cannot route at all, is not deliverable.
func planSiteRoutes(routes, localSubnets []string, nets []HostNetwork, routeDev func(netip.Addr) (string, bool)) siteRoutePlan {
	var plan siteRoutePlan
	tunnel := map[string]bool{}
	for _, n := range nets {
		if n.Tunnel {
			tunnel[n.Iface] = true
		}
	}
	for _, raw := range routes {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			plan.Routes = append(plan.Routes, raw) // the backend already drops malformed input
			continue
		}
		p = p.Masked()
		conflicted := false
		for _, n := range nets {
			if n.Tunnel || !n.Prefix.IsValid() || n.Prefix.Addr().Is4() != p.Addr().Is4() {
				continue
			}
			if p.Overlaps(n.Prefix.Masked()) {
				plan.Conflicts = append(plan.Conflicts, RouteConflict{CIDR: p.String(), Network: n.Prefix.Masked().String(), Iface: n.Iface})
				conflicted = true
				break
			}
		}
		if !conflicted {
			plan.Routes = append(plan.Routes, raw)
		}
	}
	for _, raw := range localSubnets {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		p = p.Masked()
		reachable := false
		for _, n := range nets {
			if n.Tunnel || !n.Addr.IsValid() {
				continue
			}
			if p.Contains(n.Addr) {
				reachable = true
				if !plan.SrcOK {
					plan.Src, plan.SrcOK = n.Addr, true
				}
				break
			}
		}
		if !reachable && routeDev != nil {
			if dev, ok := routeDev(p.Addr()); ok && dev != "" && !tunnel[dev] {
				reachable = true
			}
		}
		if !reachable {
			plan.LocalUnreachable = append(plan.LocalUnreachable, p.String())
		}
	}
	return plan
}
