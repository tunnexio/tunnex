//go:build linux

package egress

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// noLocal is the M6 predicate for tests where no endpoint is gateway-local.
func noLocal(netip.Addr) bool { return false }

// fakeSource is an injectable endpointSource (WF-K5): it stands in for the in-cluster EndpointSlice+Service
// watch so every fail-closed branch of classify + the render is unit-tested without a live cluster.
type fakeSource struct{ m map[string]fakeEntry }

type fakeEntry struct {
	targets []k8sTarget
	ok      bool
}

func (f *fakeSource) Targets(ns, svc string, _ int) ([]k8sTarget, bool) {
	e, found := f.m[ns+"/"+svc]
	if !found {
		return nil, false
	}
	return e.targets, e.ok
}

func mgrWithVIPs(t *testing.T, mappings []nodepolicy.VIPMapping, src endpointSource) *Manager {
	t.Helper()
	m := New("wg0")
	m.localIPs = func() map[netip.Addr]struct{} { return nil } // deterministic: no endpoint is gateway-local (M6 tested separately)
	if src != nil {
		m.SetEndpointSource(src)
	}
	m.SetPolicy(&nodepolicy.Compiled{Version: 7, Mode: "enforcing", VIPMappings: mappings})
	m.ResolveK8sVIPs(context.Background())
	return m
}

// classify (WF-K5) is FAIL-CLOSED at every branch: the ONLY input that programs a DNAT is a valid VIP for a
// Service with >=1 READY endpoint. Every other outcome refuses — a malformed VIP, no successful endpoint
// view (API unreachable / not yet synced), or zero ready endpoints (the datapath-tier reassignment guard:
// never a stale pod IP).
func TestClassifyFailsClosedExceptReadyEndpoint(t *testing.T) {
	vm := nodepolicy.VIPMapping{VIP: "100.64.0.5", Namespace: "prod", Service: "api", PortLow: 80, Protocol: "tcp"}
	ready := []k8sTarget{{ip: "10.42.0.14", port: 8080}}
	cases := []struct {
		name       string
		targets    []k8sTarget
		sourceOK   bool
		wantOK     bool
		wantReason string
	}{
		{"no successful view (API unreachable / unsynced)", nil, false, false, "endpoints_unavailable"},
		{"view but zero ready endpoints", nil, true, false, "no_ready_endpoints"},
		{"one ready endpoint", ready, true, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, ok, reason := classify(vm, c.targets, c.sourceOK, noLocal)
			if ok != c.wantOK || reason != c.wantReason {
				t.Fatalf("classify=%v/%q, want %v/%q", ok, reason, c.wantOK, c.wantReason)
			}
			if ok && (len(out) != 1 || out[0].ip != "10.42.0.14" || out[0].port != 8080) {
				t.Fatalf("success must return the ready endpoint, got %+v", out)
			}
		})
	}
	// A malformed VIP from the CP fails closed — never interpolated into nft — even with a ready endpoint.
	badVIP := nodepolicy.VIPMapping{VIP: "100.64.0.5; drop", Namespace: "p", Service: "s", PortLow: 80}
	if _, ok, r := classify(badVIP, ready, true, noLocal); ok || r != "invalid_vip" {
		t.Fatalf("a malformed VIP must fail closed, got ok=%v reason=%q", ok, r)
	}
	// H4: an IPv6 VIP fails closed (the render is IPv4-only; a v6 addr would reject the whole nft table).
	v6VIP := nodepolicy.VIPMapping{VIP: "fd00::5", Namespace: "p", Service: "s", PortLow: 80}
	if _, ok, r := classify(v6VIP, ready, true, noLocal); ok || r != "invalid_vip" {
		t.Fatalf("an IPv6 VIP must fail closed, got ok=%v reason=%q", ok, r)
	}
	// M8/M9: all-ports (PortLow==0) and port-range exposures are refused with typed reasons (silently wrong
	// otherwise — wrong pod port / blackholed range).
	if _, ok, r := classify(nodepolicy.VIPMapping{VIP: "100.64.0.5"}, ready, true, noLocal); ok || r != "all_ports_unsupported" {
		t.Fatalf("an all-ports exposure must be refused, got ok=%v reason=%q", ok, r)
	}
	rng := nodepolicy.VIPMapping{VIP: "100.64.0.5", PortLow: 80, PortHigh: 90}
	if _, ok, r := classify(rng, ready, true, noLocal); ok || r != "port_range_unsupported" {
		t.Fatalf("a port-range exposure must be refused, got ok=%v reason=%q", ok, r)
	}
	// H4/M5: a malformed or non-IPv4 endpoint, or an out-of-range target port, is dropped; if it was the ONLY
	// endpoint the Service fails closed (no_ready_endpoints) rather than emitting a garbage DNAT target.
	if _, ok, r := classify(vm, []k8sTarget{{ip: "10.42.0.14; drop", port: 80}}, true, noLocal); ok || r != "no_ready_endpoints" {
		t.Fatalf("a malformed endpoint must be dropped → no_ready_endpoints, got ok=%v reason=%q", ok, r)
	}
	if _, ok, r := classify(vm, []k8sTarget{{ip: "fd00::14", port: 80}}, true, noLocal); ok || r != "no_ready_endpoints" {
		t.Fatalf("a v6 endpoint must be dropped → no_ready_endpoints, got ok=%v reason=%q", ok, r)
	}
	if _, ok, r := classify(vm, []k8sTarget{{ip: "10.42.0.14", port: 99999}}, true, noLocal); ok || r != "no_ready_endpoints" {
		t.Fatalf("an out-of-range target port must be dropped → no_ready_endpoints, got ok=%v reason=%q", ok, r)
	}
	// M6: a gateway-LOCAL endpoint (a hostNetwork pod on this node) is dropped — DNAT-ing to it would divert
	// to INPUT and bypass the forward grant chain. Only-local → fail closed.
	isLocal := func(a netip.Addr) bool { return a == netip.MustParseAddr("10.42.0.14") }
	if _, ok, r := classify(vm, ready, true, isLocal); ok || r != "no_ready_endpoints" {
		t.Fatalf("a gateway-local endpoint must be dropped → no_ready_endpoints, got ok=%v reason=%q", ok, r)
	}
}

// The VIP->ENDPOINT DNAT renders in OUR prerouting chain at priority -101; it DNATs the exposed svcPort to
// the pod's targetPort (port remap — kube-proxy's remap is gone once we bypass the ClusterIP); a removed
// Service's rule is GONE after one re-resolve with NO delete logic (the atomic table replace); and our
// ruleset never references kube-proxy's chains (resync-inert). This is the ARTIFACT-WORKS shape: a concrete
// VIP:port → podIP:port rule, not merely "a chain exists".
func TestVIPDNATRenderPortRemapAndAtomicSweep(t *testing.T) {
	vm := nodepolicy.VIPMapping{VIP: "100.64.0.5", Namespace: "prod", Service: "api", PortLow: 80, Protocol: "tcp"}
	src := &fakeSource{m: map[string]fakeEntry{"prod/api": {targets: []k8sTarget{{ip: "10.42.0.14", port: 8080}}, ok: true}}}
	m := mgrWithVIPs(t, []nodepolicy.VIPMapping{vm}, src)

	rs := m.ruleset("10.99.0.1/24")
	if !strings.Contains(rs, "chain prerouting") || !strings.Contains(rs, "priority -101") {
		t.Fatalf("prerouting DNAT chain missing / wrong priority:\n%s", rs)
	}
	if !strings.Contains(rs, "ip daddr 100.64.0.5 tcp dport 80 dnat to 10.42.0.14:8080") {
		t.Fatalf("VIP:svcPort -> podIP:targetPort DNAT rule missing (port remap):\n%s", rs)
	}
	if strings.Contains(rs, "KUBE-") {
		t.Fatal("our ruleset must never reference kube-proxy chains (resync-inert)")
	}

	// Remove the Service -> re-resolve -> the DNAT is GONE, with NO explicit delete logic (atomic replace).
	m.SetPolicy(&nodepolicy.Compiled{Version: 7, Mode: "enforcing"})
	m.ResolveK8sVIPs(context.Background())
	if rs2 := m.ruleset("10.99.0.1/24"); strings.Contains(rs2, "chain prerouting") || strings.Contains(rs2, "tunnex_k8s_vip") {
		t.Fatalf("a removed Service's DNAT must be swept by the atomic replace (no delete logic):\n%s", rs2)
	}
}

// Steady-state re-resolve is idempotent (byte-stable); a pod-IP change (the reassignment churn) re-programs
// within one tick.
func TestVIPDNATIdempotentAndReprogramsOnEndpointChange(t *testing.T) {
	vm := nodepolicy.VIPMapping{VIP: "100.64.0.5", Namespace: "prod", Service: "api", PortLow: 80, Protocol: "tcp"}
	src := &fakeSource{m: map[string]fakeEntry{"prod/api": {targets: []k8sTarget{{ip: "10.42.0.14", port: 8080}}, ok: true}}}
	m := mgrWithVIPs(t, []nodepolicy.VIPMapping{vm}, src)

	first := m.ruleset("10.99.0.1/24")
	m.ResolveK8sVIPs(context.Background())
	if m.ruleset("10.99.0.1/24") != first {
		t.Fatal("a steady-state re-resolve must be idempotent (byte-stable ruleset)")
	}
	// A pod restarts onto a new IP -> re-resolve -> DNAT re-programmed to the new endpoint (never the stale one).
	src.m["prod/api"] = fakeEntry{targets: []k8sTarget{{ip: "10.42.0.99", port: 8080}}, ok: true}
	m.ResolveK8sVIPs(context.Background())
	rs := m.ruleset("10.99.0.1/24")
	if strings.Contains(rs, "10.42.0.14") || !strings.Contains(rs, "dnat to 10.42.0.99:8080") {
		t.Fatalf("a pod-IP change must re-program the DNAT within one tick (no stale pod IP):\n%s", rs)
	}
}

// N ready endpoints -> nft-native per-flow load balancing (jhash over src/dst), no userspace round-robin.
func TestVIPDNATLoadBalancesMultipleEndpoints(t *testing.T) {
	vm := nodepolicy.VIPMapping{VIP: "100.64.0.5", Namespace: "prod", Service: "api", PortLow: 80, Protocol: "tcp"}
	src := &fakeSource{m: map[string]fakeEntry{"prod/api": {targets: []k8sTarget{
		{ip: "10.42.0.14", port: 8080}, {ip: "10.42.0.15", port: 8080},
	}, ok: true}}}
	rs := mgrWithVIPs(t, []nodepolicy.VIPMapping{vm}, src).ruleset("10.99.0.1/24")
	if !strings.Contains(rs, "jhash ip saddr . ip daddr mod 2 map {") {
		t.Fatalf("multiple ready endpoints must render an nft jhash LB map:\n%s", rs)
	}
	if !strings.Contains(rs, "10.42.0.14 . 8080") || !strings.Contains(rs, "10.42.0.15 . 8080") {
		t.Fatalf("the LB map must carry both ready endpoints (ip . port):\n%s", rs)
	}
}

// An "any-port" (PortLow==0) or port-range exposure is REFUSED end-to-end — no DNAT chain rendered (M8/M9):
// address-only DNAT would silently hit the wrong pod port, and a range would blackhole past PortLow.
func TestVIPDNATRefusesAllPortsAndRange(t *testing.T) {
	src := &fakeSource{m: map[string]fakeEntry{"prod/api": {targets: []k8sTarget{{ip: "10.42.0.14", port: 8080}}, ok: true}}}
	allPorts := nodepolicy.VIPMapping{VIP: "100.64.0.5", Namespace: "prod", Service: "api"} // PortLow 0
	if strings.Contains(mgrWithVIPs(t, []nodepolicy.VIPMapping{allPorts}, src).ruleset("10.99.0.1/24"), "chain prerouting") {
		t.Fatal("an all-ports exposure must render NO DNAT chain (refused)")
	}
	rng := nodepolicy.VIPMapping{VIP: "100.64.0.5", Namespace: "prod", Service: "api", PortLow: 80, PortHigh: 90}
	if strings.Contains(mgrWithVIPs(t, []nodepolicy.VIPMapping{rng}, src).ruleset("10.99.0.1/24"), "chain prerouting") {
		t.Fatal("a port-range exposure must render NO DNAT chain (refused)")
	}
}

// A non-cluster gateway (no VIP mappings, nil source) renders NO prerouting chain (the zero-config golden);
// and a K8s gateway with a mapping but NO endpoint source (watcher failed to build) also programs NO DNAT.
func TestNoDNATWithoutReadyView(t *testing.T) {
	if strings.Contains(mgrWithVIPs(t, nil, nil).ruleset("10.99.0.1/24"), "chain prerouting") {
		t.Fatal("a non-cluster gateway must render NO prerouting chain")
	}
	vm := nodepolicy.VIPMapping{VIP: "100.64.0.5", Namespace: "prod", Service: "api", PortLow: 80}
	m := mgrWithVIPs(t, []nodepolicy.VIPMapping{vm}, nil) // in-cluster mapping but no source (fail-closed)
	if strings.Contains(m.ruleset("10.99.0.1/24"), "chain prerouting") {
		t.Fatal("a mapping with no endpoint source must program NO DNAT (fail-closed)")
	}
	if !m.EndpointsUnavailable() {
		t.Fatal("no source for an exposed Service must set the k8s_endpoints_unavailable health kind")
	}
}

// The health kind (WF-K5): EndpointsUnavailable fires only when EVERY exposed Service has no successful view
// (the API is down). A view that returns zero ready endpoints is a per-Service refusal, NOT an API-down
// signal — the API is up.
func TestEndpointsUnavailableOnlyWhenNoViewAtAll(t *testing.T) {
	vm := nodepolicy.VIPMapping{VIP: "100.64.0.5", Namespace: "prod", Service: "api", PortLow: 80}

	down := &fakeSource{m: map[string]fakeEntry{"prod/api": {ok: false}}}
	m := mgrWithVIPs(t, []nodepolicy.VIPMapping{vm}, down)
	if !m.EndpointsUnavailable() {
		t.Fatal("no successful view for the only exposed Service must set k8s_endpoints_unavailable")
	}
	if strings.Contains(m.ruleset("10.99.0.1/24"), "chain prerouting") {
		t.Fatal("no view must program NO DNAT (fail-closed)")
	}

	zeroReady := &fakeSource{m: map[string]fakeEntry{"prod/api": {ok: true, targets: nil}}}
	m2 := mgrWithVIPs(t, []nodepolicy.VIPMapping{vm}, zeroReady)
	if m2.EndpointsUnavailable() {
		t.Fatal("a reachable API returning zero ready endpoints is NOT k8s_endpoints_unavailable (API is up)")
	}
	if strings.Contains(m2.ruleset("10.99.0.1/24"), "chain prerouting") {
		t.Fatal("zero ready endpoints must still program NO DNAT for that VIP (fail-closed)")
	}
}

// C1 (WF-K5) — the enforcement grant and the DNAT must key on the SAME VIP. A k8s_service grant compiles to
// DstCIDR=VIP/32; the forward chain renders it as `ct original ip daddr <VIP>` so it matches the PRE-DNAT dst
// (the VIP the client dialed), while the prerouting DNAT rewrites VIP→podIP. Both keyed on the VIP = the
// one-truth (enforcement + the S8.7 flush adjudicate the same tuple). A grant to the POD CIDR renders against
// the pod CIDR, NOT the VIP — so it can NOT admit a VIP flow (whose ct-original dst is the VIP, ∉ pod CIDR):
// the render-level half of the mandatory bypass red. The WIRE halves (granted VIP flow completes; pod-CIDR-
// granted client is denied at the forward chain with counter evidence) are the enforcing re-walk leg.
func TestVIPGrantAndDNATKeyedOnSameVIP(t *testing.T) {
	src := &fakeSource{m: map[string]fakeEntry{"prod/api": {ok: true, targets: []k8sTarget{{ip: "10.42.0.14", port: 8080}}}}}
	m := New("wg0")
	m.localIPs = func() map[netip.Addr]struct{} { return nil }
	m.SetEndpointSource(src)
	m.SetPolicy(&nodepolicy.Compiled{
		Version: 7, Mode: nodepolicy.ModeEnforcing,
		Allow:       []nodepolicy.AllowEntry{{SrcIP: "10.99.0.7", DstCIDR: "100.64.0.5/32", Protocol: "tcp", PortLow: 80, PortHigh: 80}},
		VIPMappings: []nodepolicy.VIPMapping{{VIP: "100.64.0.5", Namespace: "prod", Service: "api", Protocol: "tcp", PortLow: 80, PortHigh: 80}},
	})
	m.ResolveK8sVIPs(context.Background())
	rs := m.ruleset("10.99.0.1/24")
	// The DNAT (prerouting) rewrites the VIP to the pod.
	if !strings.Contains(rs, "ip daddr 100.64.0.5 tcp dport 80 dnat to 10.42.0.14:8080") {
		t.Fatalf("VIP DNAT missing:\n%s", rs)
	}
	// The grant (forward) matches the PRE-DNAT VIP via ct-original — so the client dialing the VIP is admitted
	// even though its packet's dst is the pod IP by the time the forward chain runs.
	if !strings.Contains(rs, "ip saddr 10.99.0.7 ct original ip daddr 100.64.0.5/32 tcp dport 80 counter accept") {
		t.Fatalf("VIP grant must render `ct original ip daddr <VIP>` (keyed on the VIP the client dialed):\n%s", rs)
	}
	// A grant to the POD CIDR renders against the pod CIDR, never the VIP → cannot admit a VIP flow.
	m.SetPolicy(&nodepolicy.Compiled{
		Version: 7, Mode: nodepolicy.ModeEnforcing,
		Allow:       []nodepolicy.AllowEntry{{SrcIP: "10.99.0.7", DstCIDR: "10.42.0.0/16", Protocol: "any"}},
		VIPMappings: []nodepolicy.VIPMapping{{VIP: "100.64.0.5", Namespace: "prod", Service: "api", Protocol: "tcp", PortLow: 80, PortHigh: 80}},
	})
	m.ResolveK8sVIPs(context.Background())
	rs = m.ruleset("10.99.0.1/24")
	if strings.Contains(rs, "ct original ip daddr 100.64.0.5") {
		t.Fatalf("a pod-CIDR grant must NOT render a VIP-matching accept (no bypass):\n%s", rs)
	}
	if !strings.Contains(rs, "ct original ip daddr 10.42.0.0/16") {
		t.Fatalf("the pod-CIDR grant should render against the pod CIDR:\n%s", rs)
	}
}

// TestReconcileDNSVIPsAssignsAndSweeps — S10.3 A1 (UNCHANGED by WF-K5): each cluster's reserved DNS VIP is
// assigned as a /32 on wg0 (so the client's query is delivered locally and the forwarder binds :53 on it),
// and a VIP that leaves the policy is removed. Fail-closed: an assign that errors is NOT recorded (retried
// next tick), and an invalid CP-supplied VIP never reaches `ip`.
func TestReconcileDNSVIPsAssignsAndSweeps(t *testing.T) {
	m := New("wg0")
	var cmds []string
	fail := map[string]bool{}
	m.runIP = func(_ context.Context, args ...string) error {
		key := strings.Join(args, " ")
		cmds = append(cmds, key)
		if fail[key] {
			return errors.New("RTNETLINK: operation not permitted")
		}
		return nil
	}

	// Two clusters, one with a bogus VIP that must never reach `ip`.
	m.SetPolicy(&nodepolicy.Compiled{Version: 7, K8sDNSZones: []nodepolicy.K8sDNSZone{
		{ListenVIP: "100.64.0.2", Zone: "prod.k8s.acme.com"},
		{ListenVIP: "not-an-ip", Zone: "bad.k8s.acme.com"},
	}})
	if err := m.ReconcileDNSVIPs(context.Background()); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "addr replace 100.64.0.2/32 dev wg0") {
		t.Fatalf("the valid DNS VIP must be assigned, got:\n%s", joined)
	}
	if strings.Contains(joined, "not-an-ip") {
		t.Fatalf("an invalid CP-supplied VIP must NEVER reach ip, got:\n%s", joined)
	}

	// The cluster leaves the policy → its DNS VIP is removed (no stale local address / :53 bind).
	cmds = nil
	m.SetPolicy(&nodepolicy.Compiled{Version: 7})
	if err := m.ReconcileDNSVIPs(context.Background()); err != nil {
		t.Fatalf("sweep reconcile: %v", err)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "addr del 100.64.0.2/32 dev wg0") {
		t.Fatalf("a departed DNS VIP must be unassigned, got:\n%s", strings.Join(cmds, "\n"))
	}

	// Fail-closed: an assign that errors is not recorded as applied → the NEXT reconcile retries it.
	cmds = nil
	fail["addr replace 100.64.0.2/32 dev wg0"] = true
	m.SetPolicy(&nodepolicy.Compiled{Version: 7, K8sDNSZones: []nodepolicy.K8sDNSZone{{ListenVIP: "100.64.0.2", Zone: "prod.k8s.acme.com"}}})
	if err := m.ReconcileDNSVIPs(context.Background()); err == nil {
		t.Fatal("an assign failure must surface an error")
	}
	cmds = nil
	fail["addr replace 100.64.0.2/32 dev wg0"] = false
	_ = m.ReconcileDNSVIPs(context.Background())
	if !strings.Contains(strings.Join(cmds, "\n"), "addr replace 100.64.0.2/32 dev wg0") {
		t.Fatalf("a previously-FAILED assign must be retried (never recorded as applied), got:\n%s", strings.Join(cmds, "\n"))
	}
}
