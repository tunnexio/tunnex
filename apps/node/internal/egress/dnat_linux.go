//go:build linux

package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// S10.3 WF-K5 — the K8s VIP DNAT (highest-privilege surface), REBUILT after the box-walk proved the original
// VIP->ClusterIP DNAT can not complete (netfilter applies one dst-NAT per prerouting pass, so kube-proxy's
// ClusterIP->pod DNAT is a silent no-op — see docs/S10.3-decisions.md "WF-K5"). A client reaches an exposed
// Service at its synthetic VIP; this gateway now DNATs VIP -> a READY pod ENDPOINT directly (single DNAT,
// VIP->pod), so traffic stays FORWARDED and the ip-tunnex grant chain + S8.7 conntrack-flush both keep
// working unchanged. Ready endpoints come from a read-only EndpointSlice+Service watch (endpointSource,
// k8swatch_linux.go), NOT CoreDNS. FAIL-CLOSED at every branch: the ONLY input that programs a DNAT is a
// Service with >=1 READY endpoint and a valid VIP; resolution is decoupled from the apply path (the render
// reads the last-resolved map, does no I/O); the render is pure.

// resolvedVIP is a VIP the agent WILL DNAT — produced ONLY by classify's single success branch. targets are
// the ready podIP:port destinations (port 0 = address-only DNAT, preserving the client's destination port).
type resolvedVIP struct {
	vip     string
	proto   string // tcp | udp (allowlisted; never interpolated raw)
	svcPort int    // the exposed service port the client dials at the VIP (0 = any → address-only)
	targets []k8sTarget
}

// refusedVIP is a mapping that did NOT program a DNAT, with the reason (surfaced for the operator).
type refusedVIP struct {
	vip, namespace, service, reason string
}

// classify is THE decision — one function, one success. ok=true is reachable at EXACTLY ONE return: a valid
// IPv4 VIP, a single specific exposed port, and >=1 READY non-local endpoint. Every other outcome fails
// closed (ok=false, no DNAT). Structured so a future edit cannot reorder a guard into a fail-open — the
// success is the last line, gated by everything above it. isLocal reports whether an address is one of THIS
// gateway's own addresses (M6): a hostNetwork endpoint equal to the gateway IP would DNAT->local->INPUT,
// bypassing the forward grant chain (the option-5 hazard) — such a target is dropped.
func classify(m nodepolicy.VIPMapping, targets []k8sTarget, sourceOK bool, isLocal func(netip.Addr) bool) (out []k8sTarget, ok bool, reason string) {
	// Defense-in-depth (WF-K5): the VIP is a raw string from the CP; NEVER interpolate an unvalidated value
	// into the nft ruleset. H4 — the render is IPv4-only (`ip daddr`/`dnat to`); a v6 or malformed VIP fails
	// CLOSED here, mirroring the DNS-VIP path's Is4() guard, so it can never reach `nft -f` and reject the
	// WHOLE atomic `table ip tunnex` (grant chain + kill-switch + conntrack).
	if a, e := netip.ParseAddr(m.VIP); e != nil || !a.Is4() {
		return nil, false, "invalid_vip"
	}
	// M8/M9: the exposure must be a SINGLE specific port. All-ports (PortLow==0) can't remap svcPort->
	// targetPort (address-only DNAT would silently hit the wrong pod port); a range (PortHigh>PortLow) DNATs
	// only PortLow and blackholes the rest. Both are silently-wrong, worse than unsupported — refuse with a
	// typed reason. The CP also rejects them at expose time (the teaching error); this is the enforcement-
	// point backstop. M5: bound the port so an out-of-range value can't render invalid nft.
	if m.PortLow == 0 {
		return nil, false, "all_ports_unsupported"
	}
	if m.PortHigh != 0 && m.PortHigh != m.PortLow {
		return nil, false, "port_range_unsupported"
	}
	if m.PortLow < 1 || m.PortLow > 65535 {
		return nil, false, "invalid_port"
	}
	if !sourceOK {
		// The watcher has no live view — API unreachable, a watch fault that cleared the cache, or not yet
		// listed. NEVER a stale/guessed pod IP.
		return nil, false, "endpoints_unavailable"
	}
	// Validate + dedup the endpoint targets (from the K8s API — validated anyway, the never-interpolate rule).
	seen := map[string]struct{}{}
	for _, t := range targets {
		a, e := netip.ParseAddr(t.ip)
		if e != nil || !a.Is4() {
			continue // H4: a malformed / non-IPv4 endpoint is dropped, never rendered into the v4 ruleset
		}
		if t.port < 1 || t.port > 65535 {
			continue // M5: an out-of-range target port would render invalid nft — drop it
		}
		if isLocal != nil && isLocal(a) {
			continue // M6: a gateway-local endpoint would DNAT to a local addr → INPUT → grant-chain bypass
		}
		key := a.String() + ":" + strconv.Itoa(t.port)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, k8sTarget{ip: a.String(), port: t.port})
	}
	if len(out) == 0 {
		return nil, false, "no_ready_endpoints" // Service exists but no ready, valid, non-local pod backs it
	}
	// THE ONLY SUCCESS: a valid v4 VIP, a single specific port, >=1 ready non-local endpoint. Program it.
	return out, true, ""
}

// normProto restricts the CP-supplied protocol to an nft-safe allowlist (never interpolate raw). Empty/any
// defaults to tcp — Services default to TCP and a port-DNAT needs an L4 context.
func normProto(p string) string {
	if strings.EqualFold(p, "udp") {
		return "udp"
	}
	return "tcp"
}

// ResolveK8sVIPs reads the ready endpoints for every VIP mapping in the current policy (from the watch cache
// — PURE, no network I/O here) and stores the resolved map + refusals + the endpoints-unavailable flag.
// DECOUPLED from the nft apply; the render (preroutingDNAT) reads whatever this last stored. It runs on the
// egress reconcile, which the watcher KICKS on every endpoint change (watch-driven, not a slow poll).
func (m *Manager) ResolveK8sVIPs(ctx context.Context) {
	p := m.policy.Load()
	nVIP, nDNS := 0, 0
	if p != nil {
		nVIP, nDNS = len(p.VIPMappings), len(p.K8sDNSZones)
	}
	// WF-K-OBS-1: log what the agent received + resolved. A silent refusal (no DNAT, no log) is un-debuggable.
	if m.log != nil {
		m.log.Info("k8s_resolve_begin", "vip_mappings", nVIP, "dns_zones", nDNS)
	}
	if p == nil || len(p.VIPMappings) == 0 {
		m.resolvedVIPs.Store(&[]resolvedVIP{})
		m.refusedK8sVIPs.Store(&[]refusedVIP{})
		m.k8sUnavailable.Store(false)
		return
	}
	src := m.source
	// M6: snapshot THIS gateway's own addresses once per reconcile so classify can refuse an endpoint equal
	// to a gateway-local IP (a hostNetwork pod on this node) — such a DNAT target would divert to INPUT and
	// bypass the forward grant chain.
	var local map[netip.Addr]struct{}
	if m.localIPs != nil {
		local = m.localIPs()
	}
	isLocal := func(a netip.Addr) bool { _, ok := local[a.Unmap()]; return ok }
	var resolved []resolvedVIP
	var refused []refusedVIP
	haveView, noView := 0, 0
	for _, vm := range p.VIPMappings {
		var targets []k8sTarget
		var sourceOK bool
		if src != nil {
			targets, sourceOK = src.Targets(vm.Namespace, vm.Service, vm.PortLow)
		}
		if sourceOK {
			haveView++
		} else {
			noView++
		}
		out, ok, reason := classify(vm, targets, sourceOK, isLocal)
		if ok {
			resolved = append(resolved, resolvedVIP{vip: vm.VIP, proto: normProto(vm.Protocol), svcPort: vm.PortLow, targets: out})
			if m.log != nil {
				m.log.Info("k8s_vip_resolved", "vip", vm.VIP, "service", vm.Namespace+"/"+vm.Service, "ready_endpoints", len(out))
			}
		} else {
			refused = append(refused, refusedVIP{vip: vm.VIP, namespace: vm.Namespace, service: vm.Service, reason: reason})
			if m.log != nil {
				m.log.Warn("k8s_vip_refused", "vip", vm.VIP, "service", vm.Namespace+"/"+vm.Service, "reason", reason)
			}
		}
	}
	// Byte-stable order → a steady-state reconcile is a no-op (no thrash). Targets are sorted in the render.
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].vip < resolved[j].vip })
	// Health: the endpoint source is UNAVAILABLE only if EVERY exposed Service has no successful view (the
	// API is unreachable / the watch has not synced). A single reachable Service means the API is up (a
	// per-Service zero-ready is a different, quieter refusal, not an API-down signal). Fail-closed + surfaced
	// loud (k8s_endpoints_unavailable), never a silent no-map.
	m.k8sUnavailable.Store(noView > 0 && haveView == 0)
	m.resolvedVIPs.Store(&resolved)
	m.refusedK8sVIPs.Store(&refused)
}

// runIP is the real `ip` runner (a single command, discarded output — errors carry the exit status).
func runIP(ctx context.Context, args ...string) error {
	return exec.CommandContext(ctx, "ip", args...).Run()
}

// defaultLocalIPs is the real gateway-local address set (M6): every IP assigned to a host interface. A DNAT
// target in this set is a hostNetwork endpoint on THIS node — DNAT-ing to it would divert the flow to INPUT
// and bypass the forward grant chain, so classify drops it. Injectable via Manager.localIPs for tests.
func defaultLocalIPs() map[netip.Addr]struct{} {
	out := map[netip.Addr]struct{}{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ad, ok := netip.AddrFromSlice(ipn.IP); ok {
				out[ad.Unmap()] = struct{}{}
			}
		}
	}
	return out
}

// ReconcileDNSVIPs drives the wg interface's assigned DNS VIPs to match the policy's K8sDNSZones (S10.3 A1).
// Each cluster's reserved DNS VIP must be OWNED locally as a /32 so (a) a client's DNS query to it is
// delivered locally (not forwarded) and (b) the dnsforward bind-reconcile binds :53 on it (it enumerates
// the wg interface's addresses). Idempotent: `ip addr replace` adds/refreshes; a VIP that left the policy is
// `ip addr del`'d. FAIL-CLOSED by construction — if an assign fails (no CAP_NET_ADMIN / netlink fault) the
// address never becomes local, the forwarder never binds :53 on it, and the gateway answers NOTHING there
// (a departed-half-bind is impossible). Decoupled from the nft apply (its own step in the egress loop).
// UNCHANGED by WF-K5: this is the DNS-answer half (ruling A DNS clause intact).
func (m *Manager) ReconcileDNSVIPs(ctx context.Context) error {
	if !ifaceRE.MatchString(m.wgIface) {
		return fmt.Errorf("invalid wg interface name %q", m.wgIface) // never interpolate an unvalidated name into a privileged command
	}
	p := m.policy.Load()
	want := map[string]struct{}{}
	if p != nil {
		for _, z := range p.K8sDNSZones {
			// Validate the CP-supplied VIP before it reaches `ip` — the same never-interpolate-an-unvalidated-
			// CP-string discipline the DNAT classifier applies.
			if a, err := netip.ParseAddr(z.ListenVIP); err == nil && a.Is4() {
				want[a.String()] = struct{}{}
			}
		}
	}
	var prev []string
	if pv := m.dnsVIPs.Load(); pv != nil {
		prev = *pv
	}
	var errs []error
	// Remove VIPs no longer wanted (a deregistered/emptied cluster) — no stale local address, no stale :53 bind.
	for _, v := range prev {
		if _, ok := want[v]; !ok {
			if err := m.runIP(ctx, "addr", "del", v+"/32", "dev", m.wgIface); err != nil {
				errs = append(errs, fmt.Errorf("unassign %s: %w", v, err))
			}
		}
	}
	// Add/refresh wanted VIPs (idempotent replace). FAIL-CLOSED: a VIP whose assign fails is NOT recorded as
	// applied, so a later reconcile retries; the address stays non-local, the forwarder never binds :53 on it,
	// and the gateway answers nothing there — never a half-owned VIP.
	applied := make([]string, 0, len(want))
	for v := range want {
		if err := m.runIP(ctx, "addr", "replace", v+"/32", "dev", m.wgIface); err != nil {
			errs = append(errs, fmt.Errorf("assign %s: %w", v, err))
			continue
		}
		applied = append(applied, v)
	}
	sort.Strings(applied)
	m.dnsVIPs.Store(&applied)
	return errors.Join(errs...)
}

// preroutingDNAT renders the VIP->endpoint DNAT chain from the LAST-RESOLVED map (PURE — no I/O). Priority
// -101; harmless now that we DNAT straight to a pod IP (kube-proxy's ClusterIP rules never match a pod IP,
// so there is no chained-DNAT interaction — the WF-K5 defect is structurally gone). It lives in OUR
// `table ip tunnex` (atomic add;flush;table replace) — a removed Service's rule is swept for free. Empty (no
// chain at all) for a non-cluster gateway — the zero-config golden.
func (m *Manager) preroutingDNAT() string {
	rs := m.resolvedVIPs.Load()
	if rs == nil || len(*rs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type nat hook prerouting priority -101; policy accept;\n")
	for _, r := range *rs {
		b.WriteString("    " + dnatRule(r) + "\n")
	}
	b.WriteString("  }\n")
	return b.String()
}

// dnatRule renders ONE VIP's DNAT. Single ready endpoint → a plain `dnat to ip[:port]`. N ready endpoints →
// nft-native per-flow load balancing (`jhash ip saddr . ip daddr mod N map {...}`) — sticky per src/dst
// pair, no userspace round-robin, no state (WF-K5 condition 4). Port remap: the client dials VIP:svcPort;
// we DNAT to podIP:targetPort (targetPort from the EndpointSlice — kube-proxy's servicePort→targetPort remap
// is gone once we bypass the ClusterIP). svcPort==0 (an "any" exposure) → address-only DNAT (dport preserved).
func dnatRule(r resolvedVIP) string {
	// Byte-stable target order → a steady-state reconcile is a no-op (no nft thrash).
	ts := append([]k8sTarget(nil), r.targets...)
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].ip != ts[j].ip {
			return ts[i].ip < ts[j].ip
		}
		return ts[i].port < ts[j].port
	})
	// classify guarantees a single specific svcPort (1..65535) and every target port in range, so the DNAT
	// ALWAYS remaps VIP:svcPort -> podIP:targetPort (all-ports / range exposures are refused upstream).
	match := fmt.Sprintf("ip daddr %s %s dport %d", r.vip, r.proto, r.svcPort)
	if len(ts) == 1 {
		return fmt.Sprintf("%s dnat to %s:%d comment \"tunnex_k8s_vip\"", match, ts[0].ip, ts[0].port)
	}
	// N ready endpoints → nft-native per-flow load balancing: jhash over the src/dst pair (sticky per flow,
	// no userspace round-robin, no state). Map values are the addr+port concatenation `ip . port`.
	var parts []string
	for i, t := range ts {
		parts = append(parts, fmt.Sprintf("%d : %s . %d", i, t.ip, t.port))
	}
	return fmt.Sprintf("%s dnat to jhash ip saddr . ip daddr mod %d map { %s } comment \"tunnex_k8s_vip\"",
		match, len(ts), strings.Join(parts, ", "))
}

// EndpointsUnavailable reports the k8s_endpoints_unavailable health kind (this gateway fronts exposed
// Services but has NO successful endpoint view from the K8s API, so no VIP can be DNAT-programmed —
// fail-closed). Reported to the CP so an operator sees WHY no Service is reachable. (Renamed from the CoreDNS-
// era DNSUnreachable — WF-K5 moved target resolution from CoreDNS to the API watch.)
func (m *Manager) EndpointsUnavailable() bool { return m.k8sUnavailable.Load() }
