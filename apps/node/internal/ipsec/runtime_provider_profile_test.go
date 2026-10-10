package ipsec

import (
	"encoding/json"
	"strings"
	"testing"
)

func gcpMaterialFixture() RuntimeMaterial {
	m := bgpMaterialFixture()
	v := 2
	m.Manifest.ProfileID = GCPHABGPProfile
	m.Manifest.BGPVersion = &v
	m.Manifest.BGP.RemoteASN = 65001
	runtimeReseal(&m)
	return m
}
func TestGCPHAReusesOwnedBGPTransport(t *testing.T) {
	m := gcpMaterialFixture()
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil || !validJournalBGP(e) || !validKernelAllocation(e.Allocation) {
		t.Fatal("GCP intent refused", err)
	}
	if e.Allocation.ProfileID != GCPHABGPProfile {
		t.Fatal("profile lineage absent")
	}
	for _, engine := range e.Engines {
		if engine.ProfileID != GCPHABGPProfile || !engine.BGP || engineTransportPrefixes(engine, true)[0].Bits() != 0 {
			t.Fatal("common transport not reused")
		}
	}
	if !validJournalPayload(runtimeJournalPayload{Version: 5, OwnerID: m.Manifest.NodeID, Entries: []RuntimeJournalEntry{e}}) {
		t.Fatal("GCP lineage invalid")
	}
	e.Engines[0].ProfileID = ""
	if validJournalBGP(e) {
		t.Fatal("mixed provider lineage accepted")
	}
}
func TestGCPHARefusesMixedVersionsAndUnsupportedClassic(t *testing.T) {
	for name, mutate := range map[string]func(*RuntimeMaterial){
		"aws version":     func(m *RuntimeMaterial) { v := 1; m.Manifest.BGPVersion = &v },
		"missing version": func(m *RuntimeMaterial) { m.Manifest.BGPVersion = nil },
		"classic":         func(m *RuntimeMaterial) { m.Manifest.ProfileID = GCPClassicStaticProfile },
		"aws ASN":         func(m *RuntimeMaterial) { m.Manifest.BGP.RemoteASN = 7224 },
		"unknown":         func(m *RuntimeMaterial) { m.Manifest.ProfileID = "gcp-ha-bgp-ipv4-v2" },
	} {
		t.Run(name, func(t *testing.T) {
			m := gcpMaterialFixture()
			mutate(&m)
			runtimeReseal(&m)
			if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
				t.Fatal("unsupported contract accepted")
			}
		})
	}
}
func TestProviderMTUIsIndependentAndLoweringOnly(t *testing.T) {
	for _, tc := range []struct {
		profile     string
		outer, want uint32
	}{{"", 1500, 1422}, {GCPHABGPProfile, 1500, 1382}, {GCPHABGPProfile, 1460, 1382}, {GCPHABGPProfile, 1400, 1326}} {
		v, ok := runtimeProfileInnerMTU(tc.profile, tc.outer)
		if !ok || v != tc.want {
			t.Fatalf("%s/%d got%d want%d", tc.profile, tc.outer, v, tc.want)
		}
	}
	if _, ok := runtimeProfileInnerMTU("unsupported", 1500); ok {
		t.Fatal("unsupported profile MTU accepted")
	}
	if runtimeChildLifetime(GCPHABGPProfile) != "10800s" || runtimeChildRekey(GCPHABGPProfile) != "9000s" || runtimeIKERekey(GCPHABGPProfile) != "32400s" {
		t.Fatal("GCP lifetimes incorrect")
	}
}
func TestAWSProfileJournalShapePreserved(t *testing.T) {
	m := bgpMaterialFixture()
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(e)
	if strings.Contains(string(raw), "ProfileID") {
		t.Fatal("legacy journal shape changed")
	}
	if (*RuntimeController)(nil).GCPHACapability() != 0 {
		t.Fatal("nil controller advertised support")
	}
}
