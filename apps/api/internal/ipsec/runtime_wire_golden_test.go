package ipsec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// This fixture is produced by the CP's typed canonical serializer, independently
// of node fixture constructors. It contains fixed documentation addresses only.
func TestAPIRuntimeManifestWireGolden(t *testing.T) {
	var m RuntimeManifest
	if err := json.Unmarshal([]byte(recoveryManifestLegacyGolden), &m); err != nil {
		t.Fatal(err)
	}
	type golden struct {
		Name     string          `json:"name"`
		Manifest json.RawMessage `json:"manifest"`
		SHA256   string          `json:"sha256"`
	}
	var rows []golden
	add := func(name string) { raw, digest := runtimeHash(m); rows = append(rows, golden{name, raw, digest}) }
	add("static")
	v := 1
	m.RecoveryVersion = &v
	add("recovery")
	m.RecoveryVersion = nil
	m.ProfileID = "aws-bgp-ipv4-v1"
	m.BGP = &BGPConfig{LocalASN: 65000, RemoteASN: 7224, RouterID: "10.10.0.1", MaximumPrefixes: 64}
	m.BGPVersion = &v
	for i := range m.Tunnels {
		m.Tunnels[i].Selected = false
	}
	add("bgp")
	raw, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "..", "node", "internal", "ipsec", "testdata", "api_runtime_manifest_golden.json")
	if os.Getenv("TUNNEX_WRITE_API_WIRE_GOLDEN") == "1" {
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Indented fixture bytes need not share compact ownership canonical bytes.
	var got []golden
	if err = json.Unmarshal(existing, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(rows) {
		t.Fatal("fixture cardinality")
	}
	for i, want := range rows {
		if got[i].Name != want.Name || got[i].SHA256 != want.SHA256 {
			t.Fatalf("%s CP digest changed", want.Name)
		}
		var decoded RuntimeManifest
		if err = json.Unmarshal(got[i].Manifest, &decoded); err != nil {
			t.Fatal(err)
		}
		actual, digest := runtimeHash(decoded)
		if string(actual) != string(want.Manifest) || digest != want.SHA256 {
			t.Fatalf("%s canonical CP bytes changed", want.Name)
		}
	}
}

// GCP is independently serialized by the CP. Classic metadata participates in
// the ownership digest; its field order must match the node's wire contract.
func TestAPIGCPRuntimeManifestWireGolden(t *testing.T) {
	var m RuntimeManifest
	if err := json.Unmarshal([]byte(recoveryManifestLegacyGolden), &m); err != nil {
		t.Fatal(err)
	}
	type golden struct {
		Name     string          `json:"name"`
		Manifest json.RawMessage `json:"manifest"`
		SHA256   string          `json:"sha256"`
	}
	var rows []golden
	add := func(name string) { raw, digest := runtimeHash(m); rows = append(rows, golden{name, raw, digest}) }
	v := 2
	m.ProfileID = GCPHAProfile
	m.BGP = &BGPConfig{LocalASN: 65000, RemoteASN: 65002, RouterID: "10.10.0.1", MaximumPrefixes: 64}
	m.BGPVersion = &v
	for i := range m.Tunnels {
		m.Tunnels[i].Selected = false
	}
	add("gcp-ha")
	m.ProfileID = GCPClassicProfile
	m.BGP = nil
	m.BGPVersion = nil
	transport, count := 1, 1
	m.TransportVersion = &transport
	m.TunnelCount = &count
	m.Tunnels[0].Selected = true
	m.Tunnels[0].InsideCIDR = ""
	m.Tunnels[0].CustomerInsideAddress = ""
	m.Tunnels[0].CloudInsideAddress = ""
	m.Tunnels[1] = RuntimeTunnel{}
	add("gcp-classic")
	raw, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("testdata", "api_gcp_runtime_manifest_golden.json")
	if os.Getenv("TUNNEX_WRITE_API_WIRE_GOLDEN") == "1" {
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []golden
	if json.Unmarshal(existing, &got) != nil || len(got) != len(rows) {
		t.Fatal("GCP fixture cardinality")
	}
	for i, want := range rows {
		var decoded RuntimeManifest
		if json.Unmarshal(got[i].Manifest, &decoded) != nil {
			t.Fatal("GCP fixture decode")
		}
		actual, digest := runtimeHash(decoded)
		if got[i].Name != want.Name || got[i].SHA256 != want.SHA256 || string(actual) != string(want.Manifest) || digest != want.SHA256 {
			t.Fatalf("%s CP canonical bytes changed", want.Name)
		}
	}
}
