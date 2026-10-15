package ipsec

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func desktopGrantFixture() RuntimeDesktopGrant {
	return RuntimeDesktopGrant{RuntimeGrant: RuntimeGrant{Source: "10.99.0.7/32", Destination: "10.20.0.8/32", Protocol: "tcp", PortLow: 443, PortHigh: 443, RuleID: uuid.NewString()}, DeviceID: uuid.NewString(), PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
}
func TestDesktopMaterialSeparatesEnrolledSourceFromLAN(t *testing.T) {
	m := runtimeMaterialFixture()
	m.Manifest.ProfileID = "aws-bgp-ipv4-v1"
	v := 1
	m.Manifest.BGPVersion = &v
	m.Manifest.BGP = &BGPConfig{LocalASN: 65000, RemoteASN: 7224, RouterID: "10.10.0.1", MaximumPrefixes: 64}
	m.Manifest.Tunnels[0].Selected = false
	runtimeReseal(&m)
	m.Policy.DesktopGrants = []RuntimeDesktopGrant{desktopGrantFixture()}
	_, grants, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil || len(grants) != 1 || grants[0].DesktopDeviceID == uuid.Nil {
		t.Fatalf("desktop rejected: %v", err)
	}
	for name, mutate := range map[string]func(*RuntimeMaterial){"broad source": func(m *RuntimeMaterial) { m.Policy.DesktopGrants[0].Source = "10.99.0.0/24" }, "no key": func(m *RuntimeMaterial) { m.Policy.DesktopGrants[0].PublicKey = "" }, "foreign destination": func(m *RuntimeMaterial) { m.Policy.DesktopGrants[0].Destination = "8.8.8.8/32" }, "expired": func(m *RuntimeMaterial) {
		end := time.Now().Add(-time.Second)
		m.Policy.DesktopGrants[0].ExpiresAt = &end
	}, "static": func(m *RuntimeMaterial) { m.Manifest.ProfileID = "aws-static-ipv4-v1"; runtimeReseal(m) }} {
		t.Run(name, func(t *testing.T) {
			bad := m
			bad.Policy.DesktopGrants = append([]RuntimeDesktopGrant(nil), m.Policy.DesktopGrants...)
			mutate(&bad)
			if _, _, err := runtimeMaterialEntry(bad, bad.Manifest.OrgID, bad.Manifest.NodeID, "net:[4026531992]"); err == nil {
				t.Fatal("invalid desktop material accepted")
			}
		})
	}
}
func TestDesktopGuardBindsWGIngressAndKeepsNATRefusal(t *testing.T) {
	in := guardFixture()
	c := &in.Connections[0]
	c.ReplyIngressIndices = []int{10}
	d := desktopGrantFixture()
	g := GuardGrant{Source: netip.MustParsePrefix(d.Source), Destination: netip.MustParsePrefix(d.Destination), Protocol: GuardTCP, PortLow: 443, PortHigh: 443, DesktopDeviceID: uuid.MustParse(d.DeviceID), DesktopPublicKey: d.PublicKey, DesktopIngressIndex: 7}
	c.Grants = []GuardGrant{g}
	rendered, err := RenderGuard(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.NFT, "meta iif 7 meta oif 10") || !strings.Contains(rendered.NFT, "meta iif 10 meta oif 7") || strings.Contains(rendered.NFT, "meta iif 2 meta oif 10") || !strings.Contains(rendered.NFT, "ct status snat counter drop") {
		t.Fatal("source interface or NAT guard widened", rendered.NFT)
	}
	for _, bad := range []int{0, 10} {
		c.Grants[0].DesktopIngressIndex = bad
		if _, err = RenderGuard(in); err == nil {
			t.Fatal("unobserved or IPsec ingress accepted")
		}
	}
}
func TestDesktopPeerProofRejectsSpoofedOrAmbiguousIP(t *testing.T) {
	d := desktopGrantFixture()
	p := netip.MustParsePrefix(d.Source)
	valid := "wg0\t" + d.PublicKey + "\t" + d.Source + "\n"
	if iface, ok := desktopPeerInterface(valid, d.PublicKey, p); !ok || iface != "wg0" {
		t.Fatal("exact peer refused")
	}
	for _, raw := range []string{strings.Replace(valid, d.Source, "10.99.0.0/24", 1), valid + valid, strings.Replace(valid, d.PublicKey, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))), 1)} {
		if _, ok := desktopPeerInterface(raw, d.PublicKey, p); ok {
			t.Fatal("spoofed peer accepted")
		}
	}
	if !desktopReturnRoute([]byte(`[{"dst":"10.99.0.7","dev":"wg0"}]`), "wg0", p) || desktopReturnRoute([]byte(`[{"dst":"10.99.0.7","dev":"eth0"}]`), "wg0", p) || desktopReturnRoute([]byte(`[{"dst":"10.99.0.7","dev":"wg0","gateway":"192.168.1.1"}]`), "wg0", p) {
		t.Fatal("return route ownership invalid")
	}
}
func TestDesktopNoSNATRequiresExactPriorReturn(t *testing.T) {
	source, destination := netip.MustParsePrefix("10.99.0.7/32"), netip.MustParsePrefix("10.20.0.8/32")
	rule := map[string]any{"family": "ip", "table": "tunnex", "chain": "postrouting", "comment": "tunnex_ipsec_desktop_no_snat", "expr": []any{guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(source)), guardMatch("==", guardPayload("ip", "daddr"), guardPrefixJSON(destination)), guardCounter(), map[string]any{"return": nil}}}
	marshal := func(rows ...any) []byte {
		header := map[string]any{"chain": map[string]any{"family": "ip", "table": "tunnex", "name": "postrouting", "type": "nat", "hook": "postrouting", "prio": 99}}
		b, _ := json.Marshal(map[string]any{"nftables": append([]any{header}, rows...)})
		return b
	}
	raw := marshal(map[string]any{"rule": rule})
	if !desktopNATExempt(raw, source, destination) {
		t.Fatal("exact exemption rejected")
	}
	if desktopNATExempt(raw, netip.MustParsePrefix("10.99.0.8/32"), destination) || desktopNATExempt(raw, source, netip.MustParsePrefix("10.20.0.0/24")) {
		t.Fatal("exemption broadened")
	}
	prior := map[string]any{"rule": map[string]any{"family": "ip", "table": "tunnex", "chain": "postrouting", "expr": []any{map[string]any{"masquerade": nil}}}}
	if desktopNATExempt(marshal(prior, map[string]any{"rule": rule}), source, destination) {
		t.Fatal("return after masquerade accepted")
	}
}

func TestDesktopExportsWithdrawWithLeaseOwner(t *testing.T) {
	e := bgpEntryFixture(t)
	p := &bgpSessionFixture{}
	c := &RuntimeController{bgpProcesses: map[uuid.UUID]runtimeBGPSession{e.DeliveryID: p}, bgpDesktopExports: map[uuid.UUID][]netip.Prefix{e.DeliveryID: {netip.MustParsePrefix("10.99.0.7/32")}}}
	if err := c.stopUnleasedDesktopExports([]RuntimeJournalEntry{e}, map[uuid.UUID]runtimeActive{e.Allocation.ConnectionID: {Entry: e}}); err != nil || p.closed {
		t.Fatal("current leased export withdrawn")
	}
	if err := c.stopUnleasedDesktopExports([]RuntimeJournalEntry{e}, nil); err != nil || !p.closed || c.bgpProcesses[e.DeliveryID] != nil {
		t.Fatal("unleased desktop export survived")
	}
}
func TestDesktopProofMustPreserveObservedInterface(t *testing.T) {
	g := GuardGrant{Source: netip.MustParsePrefix("10.99.0.7/32"), DesktopDeviceID: uuid.New(), DesktopIngressIndex: 7}
	c := &RuntimeController{desktopObserve: func(_ context.Context, in []GuardGrant) ([]GuardGrant, error) {
		out := append([]GuardGrant(nil), in...)
		out[0].DesktopIngressIndex = 8
		return out, nil
	}}
	if c.proveDesktopGrants(context.Background(), []GuardGrant{g}) == nil {
		t.Fatal("interface substitution accepted")
	}
	c.desktopObserve = func(_ context.Context, in []GuardGrant) ([]GuardGrant, error) { return in, ErrRuntimeController }
	if c.proveDesktopGrants(context.Background(), []GuardGrant{g}) == nil {
		t.Fatal("lost identity read accepted")
	}
}

// Exercise material refresh, retained priority renewal, and identity withdrawal
// through the real shared guard/lease machinery. Native observations are mocked.
func TestDesktopMaintenancePreservesAndRechecksWGIdentity(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	var id, delivery uuid.UUID
	for i := range r.materials {
		m := &r.materials[i]
		if m.Manifest.ProfileID != "aws-bgp-ipv4-v1" {
			continue
		}
		id, delivery = m.Manifest.ConnectionID, m.ID
		d := desktopGrantFixture()
		d.Destination = netip.PrefixFrom(netip.MustParsePrefix(m.Manifest.RemotePrefixes[0]).Addr().Next(), 32).String()
		m.Policy.DesktopGrants = []RuntimeDesktopGrant{d}
		a := r.c.active[id]
		_, grants, err := runtimeMaterialEntry(*m, r.c.config.OrgID, r.c.config.GatewayID, a.Environment.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		for j := range grants {
			if grants[j].DesktopDeviceID != uuid.Nil {
				grants[j].DesktopIngressIndex = 7777
			}
		}
		a.Grants = grants
		r.c.active[id] = a
		break
	}
	if id == uuid.Nil {
		t.Fatal("missing AWS BGP fixture")
	}
	kernel := newRecoveryKernelFixture()
	kernel.p = r.c.active[id].Entry.Allocation
	kernel.owned = r.c.active[id].Entry.Observed
	for i := range kernel.routes {
		kernel.routes[i] = map[string]bool{}
	}
	for _, route := range r.c.active[id].Entry.BGPRoutes.Owned {
		kernel.routes[int(route.Slot)-1][route.Prefix.String()] = true
	}
	r.c.kernel = kernel.applier()
	observed := 0
	r.c.desktopObserve = func(_ context.Context, in []GuardGrant) ([]GuardGrant, error) {
		observed++
		out := append([]GuardGrant(nil), in...)
		for i := range out {
			if out[i].DesktopDeviceID != uuid.Nil {
				out[i].DesktopIngressIndex = 7777
			}
		}
		return out, nil
	}
	interfaces := r.c.guard.reader.interfaces
	r.c.guard.reader.interfaces = func() ([]GuardInterface, error) {
		out, err := interfaces()
		return append(out, GuardInterface{Name: "wg0", Index: 7777}), err
	}
	r.c.bgpDesktopExports = map[uuid.UUID][]netip.Prefix{delivery: {netip.MustParsePrefix("10.99.0.7/32")}}
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("initial desktop guard", err)
	}
	r.phase = "maintenance"
	results, err := r.c.maintainIPsecRuntime(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true })
	if err != nil || len(results) != len(r.materials) {
		t.Fatal("desktop material lost continuity", err, len(results))
	}
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
		t.Fatal("desktop priority renewal", err)
	}
	found := false
	for _, g := range r.c.active[id].Grants {
		if g.DesktopDeviceID != uuid.Nil && g.DesktopIngressIndex == 7777 {
			found = true
		}
	}
	if observed < 3 || !found {
		t.Fatal("desktop proof omitted")
	}
	r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, ErrRuntimeController }
	if _, err := r.c.maintainIPsecRuntime(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }); err == nil {
		t.Fatal("lost WG identity retained authority")
	}
	if len(r.c.active) != 0 || r.c.bgpProcesses[delivery] != nil || !r.applicationDenied[id] {
		t.Fatal("identity withdrawal retained forwarding or return exports")
	}
}
