package ipsec

import (
	"encoding/json"
	"testing"
)

func TestBGPManifestCompatibilityAndStaticHash(t *testing.T) {
	var m RuntimeManifest
	if err := json.Unmarshal([]byte(recoveryManifestLegacyGolden), &m); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	if string(raw) != recoveryManifestLegacyGolden {
		t.Fatal("static canonical bytes changed")
	}
	if !runtimeBGPCompatible(m, false) {
		t.Fatal("static requires BGP capability")
	}
	b := BGPConfig{LocalASN: 65000, RemoteASN: 7224, RouterID: "10.10.0.1", MaximumPrefixes: 64}
	v := 1
	m.ProfileID = "aws-bgp-ipv4-v1"
	m.BGP = &b
	m.BGPVersion = &v
	for i := range m.Tunnels {
		m.Tunnels[i].Selected = false
	}
	if !runtimeBGPCompatible(m, true) || runtimeBGPCompatible(m, false) {
		t.Fatal("BGP capability mismatch")
	}
	rv := 1
	m.RecoveryVersion = &rv
	if runtimeBGPCompatible(m, true) {
		t.Fatal("BGP uses static recovery")
	}
	m.RecoveryVersion = nil
	m.Tunnels[0].Selected = true
	if runtimeBGPCompatible(m, true) {
		t.Fatal("BGP selected static slot")
	}
	m.Tunnels[0].Selected = false
	oldID := b.RouterID
	b.RouterID = "224.1.1.1"
	if runtimeBGPCompatible(m, true) {
		t.Fatal("multicast BGP router ID accepted")
	}
	b.RouterID = oldID
	v = 2
	if runtimeBGPCompatible(m, true) {
		t.Fatal("future BGP version admitted")
	}
	v = 1
	m.ProfileID = "aws-static-ipv4-v1"
	if runtimeBGPCompatible(m, true) {
		t.Fatal("static aliases BGP fields")
	}
}
