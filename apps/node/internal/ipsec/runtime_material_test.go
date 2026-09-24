package ipsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"net/netip"
	"strings"
	"testing"
)

func runtimeMaterialFixture() RuntimeMaterial {
	e := journalFixture()
	m := RuntimeMaterial{RuntimeDelivery: RuntimeDelivery{ID: e.DeliveryID, DesiredRevision: e.Engines[0].Binding.DesiredRevision, Kind: "apply"}, Policy: RuntimePolicy{Hash: strings.Repeat("b", 64)}}
	b := e.Engines[0].Binding
	m.Manifest = RuntimeManifest{OrgID: b.OrgID, NodeID: b.GatewayID, ConnectionID: b.ConnectionID, SiteID: e.SiteID, DesiredRevision: b.DesiredRevision, ConfigurationRevision: b.ConfigurationRevision, ProfileID: "aws-static-ipv4-v1", CustomerOutsideAddress: "192.0.2.1", LocalPrefixes: []string{"10.10.0.0/24"}, RemotePrefixes: []string{"10.20.0.0/24"}}
	for i, t := range e.Allocation.Tunnels {
		inside := netip.MustParsePrefix([]string{"169.254.20.0/30", "169.254.20.4/30"}[i])
		m.Manifest.Tunnels[i] = RuntimeTunnel{ID: t.TunnelID, Slot: i + 1, SecretRevision: 1, LinkName: KernelTunnelName(t.TunnelID), XFRMID: KernelTunnelID(t.TunnelID), ReqID: KernelTunnelID(t.TunnelID), OutsideAddress: []string{"198.51.100.1", "198.51.100.2"}[i], InsideCIDR: inside.String(), CustomerInsideAddress: inside.Addr().Next().String(), CloudInsideAddress: inside.Addr().Next().Next().String(), RouteTable: 254, RouteProtocol: 242, RouteMetric: uint32(50001 + i), Selected: i == 0}
		m.Secrets[i] = RuntimeSecret{TunnelID: t.TunnelID, Revision: 1, PSK: "Synthetic_PSK_123"}
	}
	runtimeReseal(&m)
	return m
}
func runtimeReseal(m *RuntimeMaterial) {
	raw, _ := json.Marshal(m.Manifest)
	sum := sha256.Sum256(raw)
	m.OwnershipDigest = hex.EncodeToString(sum[:])
}
func TestRuntimeMaterialClosedBindings(t *testing.T) {
	cases := map[string]func(*RuntimeMaterial){"foreign org": func(m *RuntimeMaterial) { m.Manifest.OrgID = m.Manifest.SiteID }, "hash": func(m *RuntimeMaterial) { m.OwnershipDigest = strings.Repeat("a", 64) }, "foreign secret": func(m *RuntimeMaterial) { m.Secrets[0].TunnelID = m.Secrets[1].TunnelID }, "reqid": func(m *RuntimeMaterial) { m.Manifest.Tunnels[0].ReqID++; runtimeReseal(m) }, "selected": func(m *RuntimeMaterial) { m.Manifest.Tunnels[1].Selected = true; runtimeReseal(m) }, "ipv6 inside": func(m *RuntimeMaterial) {
		m.Manifest.Tunnels[0].InsideCIDR = "2001:db8::/30"
		m.Manifest.Tunnels[0].CustomerInsideAddress = "2001:db8::1"
		m.Manifest.Tunnels[0].CloudInsideAddress = "2001:db8::2"
		runtimeReseal(m)
	}, "outside grant": func(m *RuntimeMaterial) {
		m.Policy.Grants = []RuntimeGrant{{Source: "10.10.0.0/24", Destination: "8.8.8.0/24", Protocol: "any"}}
	}}
	base := runtimeMaterialFixture()
	if _, _, e := runtimeMaterialEntry(base, base.Manifest.OrgID, base.Manifest.NodeID, "net:[4026531992]"); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := runtimeMaterialFixture()
			org, node := m.Manifest.OrgID, m.Manifest.NodeID
			mutate(&m)
			if _, _, e := runtimeMaterialEntry(m, org, node, "net:[4026531992]"); e == nil {
				t.Fatal("invalid material accepted")
			}
		})
	}
}

func TestRuntimeCleanupDigestBindsEntireLineage(t *testing.T) {
	m := runtimeMaterialFixture()
	c := RuntimeCleanup{RuntimeDelivery: m.RuntimeDelivery, RetainGuard: true, Lineage: []RuntimeDelivery{m.RuntimeDelivery}}
	c.ID = uuid.New()
	c.Kind = "cleanup"
	c.DesiredRevision = m.DesiredRevision + 1
	c.CoversDeliveryRevision = m.DesiredRevision
	raw, _ := json.Marshal(c.Lineage)
	sum := sha256.Sum256(raw)
	c.OwnershipDigest = hex.EncodeToString(sum[:])
	if !runtimeCleanupValid(c, m.Manifest.OrgID, m.Manifest.NodeID) {
		t.Fatal("valid lineage digest refused")
	}
	c.Lineage[0].ID = uuid.New()
	if runtimeCleanupValid(c, m.Manifest.OrgID, m.Manifest.NodeID) {
		t.Fatal("changed lineage accepted")
	}
}
