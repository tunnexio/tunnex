package ipsec

import (
	"encoding/json"
	"strings"
	"testing"
)

func classicMaterialFixture() RuntimeMaterial {
	m := runtimeMaterialFixture()
	v, c := 1, 1
	m.Manifest.ProfileID = GCPClassicStaticProfile
	m.Manifest.TransportVersion = &v
	m.Manifest.TunnelCount = &c
	m.Manifest.Tunnels[1] = RuntimeTunnel{}
	m.Secrets[1] = RuntimeSecret{}
	runtimeReseal(&m)
	return m
}
func TestClassicOneRealTunnelContract(t *testing.T) {
	m := classicMaterialFixture()
	if n, err := runtimeMaterialTransportContract(m); err != nil || n != 1 {
		t.Fatal("single-slot intent refused", err)
	}
	if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
		t.Fatal("unfinished lifecycle activated")
	}
	for name, mutate := range map[string]func(*RuntimeMaterial){"missing version": func(m *RuntimeMaterial) { m.Manifest.TransportVersion = nil }, "future version": func(m *RuntimeMaterial) { v := 2; m.Manifest.TransportVersion = &v }, "two slots": func(m *RuntimeMaterial) { v := 2; m.Manifest.TunnelCount = &v }, "hidden tunnel": func(m *RuntimeMaterial) { m.Manifest.Tunnels[1].Slot = 2 }, "hidden secret": func(m *RuntimeMaterial) { m.Secrets[1].Revision = 1 }, "bgp": func(m *RuntimeMaterial) { m.Manifest.BGP = &BGPConfig{} }, "recovery": func(m *RuntimeMaterial) { v := 1; m.Manifest.RecoveryVersion = &v }} {
		t.Run(name, func(t *testing.T) {
			m := classicMaterialFixture()
			mutate(&m)
			if _, err := runtimeMaterialTransportContract(m); err == nil {
				t.Fatal("ambiguous cardinality accepted")
			}
		})
	}
}
func TestTransportMetadataDoesNotChangeLegacyDigests(t *testing.T) {
	for _, m := range []RuntimeMaterial{runtimeMaterialFixture(), bgpMaterialFixture(), gcpMaterialFixture()} {
		if n, err := runtimeTransportContract(m.Manifest); err != nil || n != 2 {
			t.Fatal("existing contract changed")
		}
		raw, _ := json.Marshal(m.Manifest)
		if strings.Contains(string(raw), "transport_version") || strings.Contains(string(raw), "tunnel_count") {
			t.Fatal("legacy digest shape changed")
		}
		v := 1
		m.Manifest.TunnelCount = &v
		runtimeReseal(&m)
		if runtimeDeliveryValid(m.RuntimeDelivery, m.Manifest.OrgID, m.Manifest.NodeID, "apply") {
			t.Fatal("mixed metadata accepted")
		}
	}
}
