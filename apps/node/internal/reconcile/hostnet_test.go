package reconcile

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func hn(prefix, addr, iface string, tunnel bool) HostNetwork {
	return HostNetwork{Prefix: netip.MustParsePrefix(prefix), Addr: netip.MustParseAddr(addr), Iface: iface, Tunnel: tunnel}
}

// The AWS control-plane host on 2026-11-20: a VPC interface, the WireGuard device, and three container
// bridges, one of them the Compose network that collided with a routed range.
var cpHost = []HostNetwork{
	hn("172.31.32.0/20", "172.31.47.225", "ens5", false),
	hn("10.99.0.0/24", "10.99.0.1", "wg0", true),
	hn("172.17.0.0/16", "172.17.0.1", "docker0", false),
	hn("172.18.0.0/16", "172.18.0.1", "br-ai", false),
	hn("172.19.0.0/16", "172.19.0.1", "br-2183a35198ad", false),
}

func viaLAN(netip.Addr) (string, bool)    { return "ens5", true }
func viaTunnel(netip.Addr) (string, bool) { return "wg0", true }
func noRoute(netip.Addr) (string, bool)   { return "", false }

// TestPlanRefusesRemoteRangeOnAConnectedNetwork (SSI-7, finding F8) — a remote range that overlaps a
// network the host is attached to is not programmed, and the refusal names the interface.
func TestPlanRefusesRemoteRangeOnAConnectedNetwork(t *testing.T) {
	plan := planSiteRoutes(
		[]string{"172.19.0.0/16", "172.19.1.0/24", "10.70.0.0/24", "172.16.0.0/12"},
		nil, cpHost, viaLAN)

	if len(plan.Routes) != 1 || plan.Routes[0] != "10.70.0.0/24" {
		t.Fatalf("only the disjoint remote range may be programmed, got %v", plan.Routes)
	}
	if len(plan.Conflicts) != 3 {
		t.Fatalf("three remote ranges collide with host networks, got %+v", plan.Conflicts)
	}
	byCIDR := map[string]RouteConflict{}
	for _, c := range plan.Conflicts {
		byCIDR[c.CIDR] = c
	}
	// An exact match and a more-specific range both name the Compose bridge.
	for _, cidr := range []string{"172.19.0.0/16", "172.19.1.0/24"} {
		if c := byCIDR[cidr]; c.Iface != "br-2183a35198ad" || c.Network != "172.19.0.0/16" {
			t.Fatalf("%s must be refused against the Compose bridge, got %+v", cidr, c)
		}
	}
	// A wider range that swallows a host network is refused too.
	if _, ok := byCIDR["172.16.0.0/12"]; !ok {
		t.Fatal("a remote range wider than a host network must be refused")
	}
	if !plan.degraded() {
		t.Fatal("a refused route must degrade the gateway, never report green")
	}
}

// TestPlanIgnoresTunnelNetworks — the agent's own overlay is where site routes live. A remote range inside
// the device pool's interface network is the control plane's business (it refuses that overlap), not a host
// collision.
func TestPlanIgnoresTunnelNetworks(t *testing.T) {
	plan := planSiteRoutes([]string{"10.99.0.7/32"}, nil, cpHost, viaLAN)
	if len(plan.Conflicts) != 0 || len(plan.Routes) != 1 {
		t.Fatalf("a route on the tunnel network is not a host collision, got %+v", plan)
	}
}

// TestPlanLocalRangeReachableThroughTheLAN (SSI-7, finding F10) — a range the gateway is not in but routes
// out of its LAN interface is deliverable. Before SSI-7 this raised site_subnet_unreachable for a peered
// network that worked.
func TestPlanLocalRangeReachableThroughTheLAN(t *testing.T) {
	plan := planSiteRoutes(nil, []string{"172.31.37.55/32", "10.50.1.0/24"}, cpHost, viaLAN)
	if plan.degraded() {
		t.Fatalf("a host elsewhere in the VPC and a peered network are both deliverable, got %+v", plan)
	}
	// Neither range contains a host address, so there is no source hint to give, and none is guessed.
	if plan.SrcOK {
		t.Fatalf("no host address is inside either range: no source hint, got %s", plan.Src)
	}
}

// TestPlanLocalRangeSourceHint — a LAN address inside a local range is still the route source hint.
func TestPlanLocalRangeSourceHint(t *testing.T) {
	plan := planSiteRoutes(nil, []string{"172.31.0.0/16"}, cpHost, viaLAN)
	if !plan.SrcOK || plan.Src.String() != "172.31.47.225" || plan.degraded() {
		t.Fatalf("want source 172.31.47.225 and a healthy plan, got %+v", plan)
	}
	// The tunnel's own address is never offered as a LAN source.
	tunnelOnly := planSiteRoutes(nil, []string{"10.99.0.0/24"}, cpHost, viaTunnel)
	if tunnelOnly.SrcOK {
		t.Fatalf("a tunnel address must not become the LAN source hint, got %s", tunnelOnly.Src)
	}
}

// TestPlanLocalRangeUndeliverable — the reassuring-green trap is still caught: a local range the kernel
// would send into a tunnel, or cannot route at all, is reported.
func TestPlanLocalRangeUndeliverable(t *testing.T) {
	for name, routeDev := range map[string]func(netip.Addr) (string, bool){"into the tunnel": viaTunnel, "no route": noRoute} {
		plan := planSiteRoutes(nil, []string{"10.50.1.0/24"}, cpHost, routeDev)
		if len(plan.LocalUnreachable) != 1 || plan.LocalUnreachable[0] != "10.50.1.0/24" || !plan.degraded() {
			t.Fatalf("%s: the local range must be reported undeliverable, got %+v", name, plan)
		}
	}
	// Per range, not all-or-nothing: one deliverable range no longer hides an undeliverable one.
	mixed := planSiteRoutes(nil, []string{"172.31.0.0/16", "10.50.1.0/24"}, cpHost, noRoute)
	if len(mixed.LocalUnreachable) != 1 || mixed.LocalUnreachable[0] != "10.50.1.0/24" {
		t.Fatalf("each local range is judged on its own, got %+v", mixed)
	}
}

func TestParseRouteGetDev(t *testing.T) {
	cases := map[string]string{
		"10.50.1.10 via 172.31.32.1 dev ens5 src 172.31.47.225 uid 0 \\    cache ": "ens5",
		"172.19.1.10 dev br-2183a35198ad src 172.19.0.1 uid 1000 \\    cache ":     "br-2183a35198ad",
		"10.2.0.9 dev wg0 src 10.99.0.1 uid 0":                                     "wg0",
	}
	for out, want := range cases {
		if got, ok := parseRouteGetDev(out); !ok || got != want {
			t.Fatalf("parseRouteGetDev(%q) = (%q, %v), want %q", out, got, ok, want)
		}
	}
	for _, out := range []string{"", "RTNETLINK answers: Network is unreachable", "unreachable 10.9.9.9 "} {
		if dev, ok := parseRouteGetDev(out); ok {
			t.Fatalf("no interface is named in %q, got %q", out, dev)
		}
	}
}

// TestRunOncePlansRoutesAgainstTheHost — the reconciler threads ONE host snapshot through: the refused
// remote range never reaches the backend, the source hint is the LAN address, and the health sink follows
// the plan and clears when the collision goes away.
func TestRunOncePlansRoutesAgainstTheHost(t *testing.T) {
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	var sink atomic.Bool
	r.SetSiteSubnetUnreachableSink(&sink)
	nets := cpHost
	r.SetHostNetworkProbe(&HostNetworkProbe{Networks: func() []HostNetwork { return nets }, RouteDev: viaLAN})
	ctx := context.Background()
	c := &fakeClient{watch: make(chan struct{})}
	c.set(DesiredState{Policy: &nodepolicy.Compiled{
		Version: 5, Mode: nodepolicy.ModeEnforcing,
		Routes:       []nodepolicy.Route{{DstCIDR: "172.19.0.0/16"}, {DstCIDR: "10.70.0.0/24"}},
		LocalSubnets: []string{"172.31.0.0/16", "10.50.1.0/24"},
	}})
	if _, err := r.runOnce(ctx, c); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if got := appliedRoutesOf(b); len(got) != 1 || got[0] != "10.70.0.0/24" {
		t.Fatalf("the colliding remote range must never reach the backend, got %v", got)
	}
	if got := b.appliedSrcHint(); got != "172.31.47.225" {
		t.Fatalf("source hint must be the LAN address inside a local range, got %q", got)
	}
	if !sink.Load() {
		t.Fatal("a refused route must raise the health signal")
	}
	// The Compose bridge is gone (the stack moved to another range): the route is programmed, green again.
	nets = cpHost[:4]
	if _, err := r.runOnce(ctx, c); err != nil {
		t.Fatalf("runOnce 2: %v", err)
	}
	if got := appliedRoutesOf(b); len(got) != 2 {
		t.Fatalf("with no collision both remote ranges are programmed, got %v", got)
	}
	if sink.Load() {
		t.Fatal("the health signal must clear when the collision goes away")
	}
}

func appliedRoutesOf(f *fakeBackend) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.routes...)
}
