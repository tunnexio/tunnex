package reconcile

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// MemBackend is an in-memory WGBackend used by the S3.1 agent (the real wgctrl
// adapter arrives with the WireGuard device lifecycle in S3.2). It lets the full
// enroll->reconcile loop run end-to-end without NET_ADMIN or a WG device.
type MemBackend struct {
	mu                sync.Mutex
	peers             []Peer
	routes            []string
	interfacePrefixes []netip.Prefix
}

// NewMemBackend returns an empty in-memory backend.
func NewMemBackend() *MemBackend { return &MemBackend{} }

// Configure records the configured interface prefixes so the in-memory
// return-rule readback mirrors the Linux ownership predicate.
func (m *MemBackend) Configure(_ context.Context, cfg InterfaceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interfacePrefixes = m.interfacePrefixes[:0]
	for _, raw := range strings.Split(cfg.Address, ",") {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil {
			m.interfacePrefixes = append(m.interfacePrefixes, prefix.Masked())
		}
	}
	return nil
}

func (m *MemBackend) Peers(context.Context) ([]Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// R2 fixture-fidelity: the real kernel read path cannot express SiteLink → strip it on read.
	out := make([]Peer, len(m.peers))
	for i, p := range m.peers {
		p.SiteLink = false
		p.AllowedIPs = append([]string(nil), p.AllowedIPs...)
		out[i] = p
	}
	return out, nil
}

func (m *MemBackend) ApplyPeers(_ context.Context, peers []Peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers = make([]Peer, len(peers))
	for i, peer := range peers {
		peer.AllowedIPs = append([]string(nil), peer.AllowedIPs...)
		m.peers[i] = peer
	}
	return nil
}

// ApplyRoutes records the desired route set (the in-memory backend has no kernel FIB).
func (m *MemBackend) ApplyRoutes(_ context.Context, cidrs []string, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = m.routes[:0]
	seen := make(map[netip.Prefix]bool, len(cidrs))
	for _, raw := range cidrs {
		if prefix, ok := canonicalRoutePrefix(raw); ok {
			seen[prefix] = true
		}
	}
	for prefix := range seen {
		m.routes = append(m.routes, prefix.String())
	}
	sort.Strings(m.routes)
	return nil
}

// Readback returns deep-cloned effective state. Return rules are derived using
// the same rule as Linux: only a configured interface prefix that is also an
// explicit agent-owned route receives the priority-100 lookup-main rule.
func (m *MemBackend) Readback(context.Context) (WGBackendReadback, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	peers := make([]Peer, len(m.peers))
	for i, peer := range m.peers {
		peer.SiteLink = false
		peer.AllowedIPs = append([]string(nil), peer.AllowedIPs...)
		peers[i] = peer
	}
	routes := append([]string(nil), m.routes...)
	desired := make(map[netip.Prefix]bool, len(routes))
	for _, raw := range routes {
		if prefix, ok := canonicalRoutePrefix(raw); ok {
			desired[prefix] = true
		}
	}
	var rules []ReturnRule
	for _, prefix := range m.interfacePrefixes {
		if desired[prefix] {
			rules = append(rules, ReturnRule{Priority: returnRulePriority, Destination: prefix.String(), Lookup: "main"})
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Destination < rules[j].Destination })
	details := make([]OwnedRoute, len(routes))
	for i, raw := range routes {
		prefix, _ := canonicalRoutePrefix(raw)
		family := "ipv6"
		if prefix.Addr().Is4() {
			family = "ipv4"
		}
		details[i] = OwnedRoute{Family: family, Destination: raw, Device: "memory", Protocol: "static", Metric: siteRouteMetric}
	}
	return WGBackendReadback{Peers: peers, Routes: routes, RouteDetails: details, ReturnRules: rules}, nil
}

// Stats returns no telemetry (the in-memory backend has no real device).
func (m *MemBackend) Stats(context.Context) ([]PeerStat, error) { return nil, nil }

// Close is a no-op for the in-memory backend — no real interface to tear down (WF-C Layer 1).
func (m *MemBackend) Close(context.Context) error { return nil }
