package ipsec

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func dnsMaterialFixture() RuntimeMaterial {
	m := runtimeMaterialFixture()
	m.Policy.DNSResolverGrants = []RuntimeDNSResolverGrant{{ContextConfigID: uuid.New(), ContextConfigVersion: 4, ProfileID: uuid.New(), ConnectionID: m.Manifest.ConnectionID, ConfigurationRevision: m.Manifest.ConfigurationRevision, SourceAddress: "10.10.0.1", ResolverAddress: "10.20.0.53"}}
	return m
}
func TestRuntimeDNSMaterialExactHostTransportOnly(t *testing.T) {
	m := dnsMaterialFixture()
	_, grants, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil || len(grants) != 2 {
		t.Fatal(err, grants)
	}
	for _, g := range grants {
		if !g.HostOrigin || g.FQDNManaged || g.Source.String() != "10.10.0.1/32" || g.Destination.String() != "10.20.0.53/32" || g.PortLow != 53 || g.PortHigh != 53 || !g.DNSResolver.valid() {
			t.Fatal("widened DNS authority", g)
		}
	}
	i := guardFixture()
	i.Connections[0].Grants = grants
	i.Connections[0].Grants[0].DNSResolver.ConnectionID = i.Connections[0].ID
	i.Connections[0].Grants[1].DNSResolver.ConnectionID = i.Connections[0].ID
	g, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"ip saddr 10.10.0.1/32 ip daddr 10.20.0.53/32", "udp dport 53", "tcp dport 53", "udp sport 53", "tcp sport 53"} {
		if !strings.Contains(g.NFT, required) {
			t.Fatal("missing", required, g.NFT)
		}
	}
	for _, line := range strings.Split(g.NFT, "\n") {
		if strings.Contains(line, "counter accept") && strings.Contains(line, "meta iif 2") {
			t.Fatal("DNS host transport widenedforwarded traffic")
		}
	}
	i.Connections[0].PermitFor = 0
	i.Connections[0].PermittedInterfaceIndices = nil
	denied, err := RenderGuard(i)
	if err != nil || strings.Contains(denied.NFT, "counter accept") {
		t.Fatal("expiry permits DNS", err)
	}
	raw, _ := json.Marshal(journalFixture())
	if strings.Contains(string(raw), "DNSResolver") {
		t.Fatal("DNS runtime authority persisted")
	}
}

func TestRuntimeDNSMaterialRejectsUnboundOrWidenedResolverAuthority(t *testing.T) {
	cases := map[string]func(*RuntimeMaterial){
		"foreignconnection": func(m *RuntimeMaterial) { m.Policy.DNSResolverGrants[0].ConnectionID = uuid.New() },
		"stalerevision":     func(m *RuntimeMaterial) { m.Policy.DNSResolverGrants[0].ConfigurationRevision++ },
		"missingconfig":     func(m *RuntimeMaterial) { m.Policy.DNSResolverGrants[0].ContextConfigID = uuid.Nil },
		"missingprofile":    func(m *RuntimeMaterial) { m.Policy.DNSResolverGrants[0].ProfileID = uuid.Nil },
		"missingversion":    func(m *RuntimeMaterial) { m.Policy.DNSResolverGrants[0].ContextConfigVersion = 0 },
		"foreignsource":     func(m *RuntimeMaterial) { m.Policy.DNSResolverGrants[0].SourceAddress = "10.11.0.1" },
		"foreignresolver":   func(m *RuntimeMaterial) { m.Policy.DNSResolverGrants[0].ResolverAddress = "8.8.8.8" },
		"CIDRsource":        func(m *RuntimeMaterial) { m.Policy.DNSResolverGrants[0].SourceAddress = "10.10.0.0/24" },
		"IPv6":              func(m *RuntimeMaterial) { m.Policy.DNSResolverGrants[0].ResolverAddress = "fd00::1" },
		"duplicate": func(m *RuntimeMaterial) {
			m.Policy.DNSResolverGrants = append(m.Policy.DNSResolverGrants, m.Policy.DNSResolverGrants[0])
		},
		"aggregatebound": func(m *RuntimeMaterial) {
			for n := 0; n < 127; n++ {
				m.Policy.Grants = append(m.Policy.Grants, RuntimeGrant{Source: "10.10.0.0/24", Destination: "10.20.0.0/24", Protocol: "tcp", PortLow: 443, PortHigh: 443})
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := dnsMaterialFixture()
			mutate(&m)
			if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
				t.Fatal("invalidDNSauthority accepted")
			}
		})
	}
}

func TestDNSGuardProvenanceCannotBecomeGeneralHostGrant(t *testing.T) {
	m := dnsMaterialFixture()
	_, grants, _ := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	cases := map[string]func(*GuardGrant){"any": func(g *GuardGrant) { g.Protocol = GuardAny; g.PortLow = 0; g.PortHigh = 0 }, "broaderPort": func(g *GuardGrant) { g.PortHigh = 65535 }, "broaderSource": func(g *GuardGrant) { g.Source = netip.MustParsePrefix("10.10.0.0/24") }, "broaderResolver": func(g *GuardGrant) { g.Destination = netip.MustParsePrefix("10.20.0.0/24") }, "forwarded": func(g *GuardGrant) { g.HostOrigin = false }, "FQDNManaged": func(g *GuardGrant) { g.FQDNManaged = true }, "foreignConnection": func(g *GuardGrant) { g.DNSResolver.ConnectionID = uuid.New() }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			i := guardFixture()
			g := grants[0]
			g.DNSResolver.ConnectionID = i.Connections[0].ID
			mutate(&g)
			i.Connections[0].Grants = []GuardGrant{g}
			if _, err := RenderGuard(i); err == nil {
				t.Fatal("DNSprovenance acceptedbroad authority")
			}
		})
	}
}

func TestDNSResolverRouteRejectsWANAndSourceFallback(t *testing.T) {
	source, resolver := netip.MustParseAddr("10.10.0.1"), netip.MustParseAddr("10.20.0.53")
	good := `[{"dst":"10.20.0.53","from":"10.10.0.1","dev":"tnxi-owned","flags":[],"cache":[]}]`
	if !dnsResolverRouteMatches([]byte(good), "tnxi-owned", source, resolver) {
		t.Fatal("validexactroute refused")
	}
	for _, bad := range []string{strings.ReplaceAll(good, "tnxi-owned", "eth0"), strings.ReplaceAll(good, "10.10.0.1", "10.10.0.2"), strings.ReplaceAll(good, "10.20.0.53", "10.20.0.54"), `[{"dst":"10.20.0.53","dev":"tnxi-owned"}]`, `[{"dst":"10.20.0.53","from":"10.10.0.1","dev":"tnxi-owned","gateway":"10.10.0.254"}]`} {
		if dnsResolverRouteMatches([]byte(bad), "tnxi-owned", source, resolver) {
			t.Fatal("foreignnative route accepted", bad)
		}
	}
}

func TestDNSResolverSlotUsesCurrentPerPrefixBGPSelection(t *testing.T) {
	m := runtimeMaterialFixture()
	v := 1
	m.Manifest.BGPVersion = &v
	m.Manifest.BGP = &BGPConfig{LocalASN: 65000, RemoteASN: 64512, RouterID: "10.10.0.1", MaximumPrefixes: 64}
	m.Manifest.ProfileID = "aws-bgp-ipv4-v1"
	m.Manifest.Tunnels[0].Selected = false
	runtimeReseal(&m)
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	e.Observed[1].InterfaceIndex = 11
	r := RuntimeBGPRouteTuple{Prefix: netip.MustParsePrefix("10.20.0.0/24"), Slot: 2, InterfaceIndex: 11, Table: 254, Protocol: 242, Metric: 50002}
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 3, Stage: "completed", Owned: []RuntimeBGPRouteTuple{r}, Target: []RuntimeBGPRouteTuple{r}}
	if dnsResolverSlot(e, netip.MustParseAddr("10.20.0.53")) != 2 {
		t.Fatal("DNSignoredactualBGPprefixselection")
	}
	e.BGPRoutes.Withdrawal = true
	e.BGPRoutes.Owned = []RuntimeBGPRouteTuple{}
	e.BGPRoutes.Target = []RuntimeBGPRouteTuple{}
	if dnsResolverSlot(e, netip.MustParseAddr("10.20.0.53")) != 0 {
		t.Fatal("withdrawnBGProutekeptDNSpath")
	}
}
