package ipsec

import (
	"encoding/json"
	"testing"
)

func bgpStatusUnitFixture(t *testing.T) (RuntimeManifest, RuntimeStatusReport) {
	t.Helper()
	var m RuntimeManifest
	if e := json.Unmarshal([]byte(recoveryManifestLegacyGolden), &m); e != nil {
		t.Fatal(e)
	}
	v := 1
	m.BGPVersion = &v
	m.ProfileID = "aws-bgp-ipv4-v1"
	m.BGP = &BGPConfig{LocalASN: 65000, RemoteASN: 7224, RouterID: "10.10.0.1", MaximumPrefixes: 64}
	r := RuntimeStatusReport{BGP: &RuntimeBGPStatus{Version: 1, Sequence: 1, Peers: [2]RuntimeBGPPeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1, InstalledPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1}}, Routes: []RuntimeBGPRoute{{Prefix: m.RemotePrefixes[0], Slot: 1}}}}
	for i := range m.Tunnels {
		m.Tunnels[i].Selected = false
		r.Tunnels[i] = RuntimeTunnelStatus{ID: m.Tunnels[i].ID, Slot: i + 1, Status: "up"}
	}
	return m, r
}
func TestBGPStatusValidation(t *testing.T) {
	m, r := bgpStatusUnitFixture(t)
	if !validBGPStatus(m, r) {
		t.Fatal("valid exact bounded BGP status refused")
	}
	cases := []struct {
		name   string
		mutate func(*RuntimeStatusReport)
	}{
		{"subprefix", func(r *RuntimeStatusReport) { r.BGP.Routes[0].Prefix = "10.20.1.0/24" }},
		{"unknown prefix", func(r *RuntimeStatusReport) { r.BGP.Routes[0].Prefix = "10.30.0.0/24" }},
		{"duplicate", func(r *RuntimeStatusReport) { r.BGP.Routes = append(r.BGP.Routes, r.BGP.Routes[0]) }},
		{"wrong slot", func(r *RuntimeStatusReport) { r.BGP.Routes[0].Slot = 3 }},
		{"wrong count", func(r *RuntimeStatusReport) { r.BGP.Peers[0].InstalledPrefixes = 0 }},
		{"unaccepted install", func(r *RuntimeStatusReport) { r.BGP.Peers[0].AcceptedPrefixes = 0 }},
		{"nonestablished", func(r *RuntimeStatusReport) { r.BGP.Peers[0].State = "idle" }},
		{"peer slot", func(r *RuntimeStatusReport) { r.BGP.Peers[0].Slot = 2 }},
		{"unknown state", func(r *RuntimeStatusReport) { r.BGP.Peers[0].State = "broken" }},
		{"negative rejection", func(r *RuntimeStatusReport) { x := -1; r.BGP.Peers[0].RejectedPrefixes = &x }},
		{"future version", func(r *RuntimeStatusReport) { r.BGP.Version = 2 }},
		{"unsafe JS sequence", func(r *RuntimeStatusReport) { r.BGP.Sequence = 9007199254740992 }},
		{"zero sequence", func(r *RuntimeStatusReport) { r.BGP.Sequence = 0 }},
		{"static selected", func(r *RuntimeStatusReport) { r.Tunnels[0].Selected = true }},
		{"static active", func(r *RuntimeStatusReport) { x := 1; r.ActiveSlot = &x }},
		{"down IPsec", func(r *RuntimeStatusReport) { r.Tunnels[0].Status = "down" }},
		{"nil routes", func(r *RuntimeStatusReport) { r.BGP.Routes = nil }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			m, r := bgpStatusUnitFixture(t)
			tt.mutate(&r)
			if validBGPStatus(m, r) {
				t.Fatal("invalid BGP status admitted")
			}
		})
	}
}
func TestBGPStatusJSONPeerCardinality(t *testing.T) {
	for _, raw := range []string{`{"version":1,"sequence":1,"peers":[],"routes":[]}`, `{"version":1,"sequence":1,"peers":[{},{},{}],"routes":[]}`, `{"version":1,"sequence":1,"peers":[{},{}],"routes":[],"extra":1}`} {
		var b RuntimeBGPStatus
		if json.Unmarshal([]byte(raw), &b) == nil {
			t.Fatal("wrong peer count silently truncated")
		}
	}
}

func TestBGPPeerJSONExplicitObservedCounts(t *testing.T) {
	const good = `{"slot":1,"state":"idle","accepted_prefixes":0,"installed_prefixes":0}`
	var p RuntimeBGPPeerStatus
	if err := json.Unmarshal([]byte(good), &p); err != nil || p.RejectedPrefixes != nil {
		t.Fatalf("known zero or unknown rejected lost: %v", err)
	}
	for _, raw := range []string{
		`{"slot":1,"state":"idle","installed_prefixes":0}`,
		`{"slot":1,"state":"idle","accepted_prefixes":null,"installed_prefixes":0}`,
		`{"slot":1,"state":"idle","accepted_prefixes":0,"installed_prefixes":null}`,
		`{"slot":null,"state":"idle","accepted_prefixes":0,"installed_prefixes":0}`,
		`{"slot":1,"state":null,"accepted_prefixes":0,"installed_prefixes":0}`,
		`{"slot":1,"state":"idle","accepted_prefixes":0,"installed_prefixes":0,"secret":"not allowed"}`,
	} {
		if json.Unmarshal([]byte(raw), &p) == nil {
			t.Fatal("missing/null/unknown peer observation silently admitted")
		}
	}
}

func TestBGPStatusPerPrefixPathsAndWithdrawal(t *testing.T) {
	m, r := bgpStatusUnitFixture(t)
	m.RemotePrefixes = append(m.RemotePrefixes, "10.21.0.0/24")
	r.BGP.Routes = append(r.BGP.Routes, RuntimeBGPRoute{Prefix: "10.21.0.0/24", Slot: 2})
	for i := range r.BGP.Peers {
		r.BGP.Peers[i].AcceptedPrefixes = 2
		r.BGP.Peers[i].InstalledPrefixes = 1
	}
	if !validBGPStatus(m, r) || r.ActiveSlot != nil {
		t.Fatal("different per-prefix best paths incorrectly require global slot")
	}
	r.BGP.Sequence++
	r.BGP.Routes = []RuntimeBGPRoute{{Prefix: m.RemotePrefixes[0], Slot: 2}}
	r.BGP.Peers[0].AcceptedPrefixes = 0
	r.BGP.Peers[0].InstalledPrefixes = 0
	r.BGP.Peers[0].State = "idle"
	r.Tunnels[0].Status = "down"
	r.BGP.Peers[1].AcceptedPrefixes = 1
	r.BGP.Peers[1].InstalledPrefixes = 1
	if !validBGPStatus(m, r) {
		t.Fatal("withdrawal/surviving peer projection rejected")
	}
	r.BGP.Routes = append(r.BGP.Routes, RuntimeBGPRoute{Prefix: m.RemotePrefixes[0], Slot: 1})
	if validBGPStatus(m, r) {
		t.Fatal("withdrawn prefix retained duplicate paths")
	}
}

func TestBGPStatusMaximumPrefixesIsPerPeer(t *testing.T) {
	m, r := bgpStatusUnitFixture(t)
	m.BGP.MaximumPrefixes = 1
	m.RemotePrefixes = append(m.RemotePrefixes, "10.21.0.0/24")
	r.BGP.Routes = append(r.BGP.Routes, RuntimeBGPRoute{Prefix: "10.21.0.0/24", Slot: 2})
	r.BGP.Peers[1].InstalledPrefixes = 1
	if !validBGPStatus(m, r) {
		t.Fatal("disjoint per-peer accepted prefixes incorrectly limited globally")
	}
	r.BGP.Peers[0].AcceptedPrefixes = 2
	if validBGPStatus(m, r) {
		t.Fatal("per-peer accepted prefix limit exceeded")
	}
}
