package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func bgpMaterialFixture() RuntimeMaterial {
	m := runtimeMaterialFixture()
	v := 1
	m.Manifest.ProfileID = "aws-bgp-ipv4-v1"
	m.Manifest.BGPVersion = &v
	m.Manifest.BGP = &BGPConfig{LocalASN: 65000, RemoteASN: 7224, RouterID: "10.10.0.1", MaximumPrefixes: 64}
	for i := range m.Manifest.Tunnels {
		m.Manifest.Tunnels[i].Selected = false
	}
	runtimeReseal(&m)
	return m
}
func bgpEntryFixture(t *testing.T) RuntimeJournalEntry {
	t.Helper()
	m := bgpMaterialFixture()
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestBGPTransportSeparatesPolicySelectors(t *testing.T) {
	e := bgpEntryFixture(t)
	if e.ContractVersion != 3 || e.Recovery != nil || !e.Allocation.BGP || !validJournalBGP(e) {
		t.Fatal("BGP lineage invalid")
	}
	for _, engine := range e.Engines {
		if !validEngineTunnel(engine) || engine.LocalPrefixes[0].Bits() == 0 || engine.RemotePrefixes[0].Bits() == 0 {
			t.Fatal("policy widened")
		}
		if engineTransportPrefixes(engine, true)[0].String() != "0.0.0.0/0" || engineTransportPrefixes(engine, false)[0].Bits() != 0 {
			t.Fatal("route-based selector absent")
		}
	}
	payload := runtimeJournalPayload{Version: 5, OwnerID: e.Engines[0].Binding.GatewayID, Entries: []RuntimeJournalEntry{e}}
	if !validJournalPayload(payload) {
		t.Fatal("version5 BGP entry refused")
	}
	payload.Version = 4
	if validJournalPayload(payload) {
		t.Fatal("BGP journal accepted legacy format")
	}
	for name, mutate := range map[string]func(*RuntimeMaterial){"missing version": func(m *RuntimeMaterial) { m.Manifest.BGPVersion = nil }, "unknown version": func(m *RuntimeMaterial) { v := 2; m.Manifest.BGPVersion = &v }, "static fallback": func(m *RuntimeMaterial) { m.Manifest.ProfileID = "aws-static-ipv4-v1" }, "static selected": func(m *RuntimeMaterial) { m.Manifest.Tunnels[0].Selected = true }, "mixed recovery": func(m *RuntimeMaterial) { v := 1; m.Manifest.RecoveryVersion = &v }} {
		t.Run(name, func(t *testing.T) {
			m := bgpMaterialFixture()
			mutate(&m)
			runtimeReseal(&m)
			if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
				t.Fatal("invalid BGP contract accepted")
			}
		})
	}
}
func TestBGPTransportJournalPreservesLegacyFields(t *testing.T) {
	raw, _ := json.Marshal(journalFixture())
	for _, field := range []string{`"BGP"`, `"BGPVersion"`} {
		if strings.Contains(string(raw), field) {
			t.Fatal("legacy checksum shape changed")
		}
	}
	e := bgpEntryFixture(t)
	for i := range e.Allocation.Tunnels {
		e.Allocation.Tunnels[i].Selected = true
	}
	if validKernelAllocation(e.Allocation) {
		t.Fatal("BGP selected route admitted")
	}
}
func TestBGPGuardControlSeparateFromGrants(t *testing.T) {
	g := guardFixture()
	c := &g.Connections[0]
	c.Grants = nil
	c.BGPPeers = []GuardBGPPeer{{Local: netip.MustParseAddr("169.254.20.1"), Remote: netip.MustParseAddr("169.254.20.2"), InterfaceIndex: 10}}
	rendered, err := RenderGuard(g)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"tcp dport 179", "tcp sport 179", "ip daddr 169.254.20.2/32 counter drop", "ip saddr 169.254.20.2/32 counter drop"} {
		if !strings.Contains(rendered.NFT, line) {
			t.Fatal("missing exact control protection", line)
		}
	}
	for _, line := range strings.Split(rendered.NFT, "\n") {
		if strings.Contains(line, "counter accept") && strings.Contains(line, "ct direction") && (!strings.Contains(line, "179") || !strings.Contains(line, "169.254.20.") || !strings.Contains(line, "@lease_")) {
			t.Fatal("control widened application authority", line)
		}
	}
	c.PermitFor = 0
	rendered, err = RenderGuard(g)
	if err != nil || strings.Contains(rendered.NFT, "counter accept") {
		t.Fatal("expired BGP lease admitted control", err)
	}
	c.PrefixOnly = true
	c.Tunnels = [2]Ownership{}
	c.LocalIngressIndices = nil
	c.PermittedInterfaceIndices = nil
	c.BGPPeers[0].InterfaceIndex = 0
	rendered, err = RenderGuard(g)
	if err != nil || !strings.Contains(rendered.NFT, "ip daddr 169.254.20.2/32 counter drop") {
		t.Fatal("retained peer denial missing", err)
	}
}

func TestBGPJournalRefusalRetainsPeerDenials(t *testing.T) {
	e := bgpEntryFixture(t)
	j, err := OpenRuntimeJournal(journalDir(t), e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	var rendered GuardManifest
	c := &RuntimeController{config: RuntimeControllerConfig{OrgID: e.Engines[0].Binding.OrgID, GatewayID: e.Engines[0].Binding.GatewayID}, journal: j, namespace: func() (string, error) { return e.Allocation.Namespace, nil }, replace: func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		var err error
		rendered, err = RenderGuard(in)
		return rendered, err
	}}
	if _, err = c.refuse(context.Background(), []RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	for _, peer := range bgpRefusalPeers(e) {
		if !strings.Contains(rendered.NFT, "ip daddr "+peer.Remote.String()+"/32 counter drop") {
			t.Fatal("startup refusal lost BGP peer denial")
		}
	}
	if strings.Contains(rendered.NFT, "counter accept") {
		t.Fatal("startup refusal manufactured BGP authority")
	}
	altered := e
	copyConfig := *e.BGP
	copyConfig.LocalASN = 65001
	altered.BGP = &copyConfig
	if j.Save([]RuntimeJournalEntry{altered}) == nil {
		t.Fatal("BGP immutable config mutation accepted")
	}
}
