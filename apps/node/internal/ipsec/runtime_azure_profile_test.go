package ipsec

import (
	"context"
	"encoding/json"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"strings"
	"testing"
)

func azureMaterialFixture(profile string) RuntimeMaterial {
	m := runtimeMaterialFixture()
	if IsAzureBGPProfile(profile) {
		m = bgpMaterialFixture()
		v := 3
		m.Manifest.BGPVersion = &v
		m.Manifest.BGP.RemoteASN = 65515
	}
	m.Manifest.ProfileID = profile
	for i := range m.Manifest.Tunnels {
		m.Manifest.Tunnels[i].InsideCIDR = []string{"169.254.21.0/30", "169.254.22.0/30"}[i]
		m.Manifest.Tunnels[i].CustomerInsideAddress = []string{"169.254.21.1", "169.254.22.1"}[i]
		m.Manifest.Tunnels[i].CloudInsideAddress = []string{"169.254.21.2", "169.254.22.2"}[i]
		if IsAzureBGPProfile(profile) {
			m.Manifest.Tunnels[i].InsideCIDR = "169.254.10.1/32"
			m.Manifest.Tunnels[i].CustomerInsideAddress = "169.254.10.1"
		}
	}
	if IsSingleTunnelProfile(profile) {
		v, n := 1, 1
		m.Manifest.TransportVersion = &v
		m.Manifest.TunnelCount = &n
		m.Manifest.Tunnels[1] = RuntimeTunnel{}
		m.Secrets[1] = RuntimeSecret{}
	}
	runtimeReseal(&m)
	return m
}
func TestAzureProfilesReuseOwnedRuntimeAndJournal(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			m := azureMaterialFixture(profile)
			e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
			if err != nil || !validKernelAllocation(e.Allocation) || !validClassicJournal(e) || !validJournalBGP(e) {
				t.Fatalf("Azure owned contract refused: %v", err)
			}
			if e.Allocation.ProfileID != profile || e.Allocation.activeTunnelCount() != map[bool]int{true: 1, false: 2}[IsSingleTunnelProfile(profile)] {
				t.Fatal("lineage/cardinality lost")
			}
			if !validJournalPayload(runtimeJournalPayload{Version: 10, OwnerID: m.Manifest.NodeID, Entries: []RuntimeJournalEntry{e}}) {
				t.Fatal("journal refused")
			}
			for _, engine := range e.Engines[:e.Allocation.activeTunnelCount()] {
				if engineTransportPrefixes(engine, true)[0] != netip.MustParsePrefix("0.0.0.0/0") {
					t.Fatal("route-based transport not reused")
				}
			}
			if IsAzureBGPProfile(profile) {
				cfg, err := runtimeBGPProcessConfig(e)
				if err != nil {
					t.Fatal(err)
				}
				text, err := bgpengine.RenderConfig(cfg)
				if err != nil || strings.Count(text, " remote-as ") != e.Allocation.activeTunnelCount() || !strings.Contains(text, "deny 0.0.0.0/0 le 32") {
					t.Fatal("shared FRR policy/cardinality incorrect", err)
				}
			}
			report, err := (*RuntimeController)(nil).ObserveIPsecStatus(context.Background(), m.RuntimeDelivery)
			if err != nil || report.Tunnels[0].Status != "unknown" {
				t.Fatal("configuration claimed health", err)
			}
		})
	}
}
func TestAzureRefusesUnboundedContracts(t *testing.T) {
	for name, mutate := range map[string]func(*RuntimeMaterial){
		"wrong version":       func(m *RuntimeMaterial) { v := 2; m.Manifest.BGPVersion = &v },
		"reserved local ASN":  func(m *RuntimeMaterial) { m.Manifest.BGP.LocalASN = 65515 },
		"reserved remote ASN": func(m *RuntimeMaterial) { m.Manifest.BGP.RemoteASN = 23456 },
		"outside Azure APIPA": func(m *RuntimeMaterial) {
			m.Manifest.Tunnels[0].InsideCIDR = "169.254.20.0/30"
			m.Manifest.Tunnels[0].CustomerInsideAddress = "169.254.20.1"
			m.Manifest.Tunnels[0].CloudInsideAddress = "169.254.20.2"
		},
		"inactive tunnel": func(m *RuntimeMaterial) {
			m.Manifest.Tunnels[1] = azureMaterialFixture(AzureActiveActiveBGPProfile).Manifest.Tunnels[1]
		},
		"inactive secret":     func(m *RuntimeMaterial) { m.Secrets[1] = azureMaterialFixture(AzureActiveActiveBGPProfile).Secrets[1] },
		"missing cardinality": func(m *RuntimeMaterial) { m.Manifest.TunnelCount = nil },
	} {
		t.Run(name, func(t *testing.T) {
			m := azureMaterialFixture(AzureActiveStandbyBGPProfile)
			mutate(&m)
			runtimeReseal(&m)
			if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
				t.Fatal("unsafe Azure contract accepted")
			}
		})
	}
}
func TestAzurePSKAndMTURemainProviderBounded(t *testing.T) {
	for _, p := range []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveStandbyStaticProfile} {
		if !validProfileEnginePSK(p, []byte("0-safe-shared-secret!")) || validProfileEnginePSK(p, []byte("unsafe\nsecret")) {
			t.Fatal("secret contract", p)
		}
		mtu, ok := runtimeProfileInnerMTU(p, 1400)
		if !ok || mtu > 1400-74 {
			t.Fatal("underlay budget", p, mtu)
		}
	}
	if (*RuntimeController)(nil).AzureCapability() != 0 {
		t.Fatal("nil capability")
	}
}

func TestAzureStaticSharedRecoveryContract(t *testing.T) {
	m := azureMaterialFixture(AzureActiveActiveStaticProfile)
	v := 1
	m.Manifest.RecoveryVersion = &v
	runtimeReseal(&m)
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil || e.ContractVersion != 2 || !validClassicJournal(e) || !validJournalRecovery(e) {
		t.Fatal("shared static recovery refused", err)
	}
	for _, p := range []string{AzureActiveStandbyStaticProfile, AzureActiveActiveBGPProfile, AzureActiveStandbyBGPProfile} {
		m := azureMaterialFixture(p)
		m.Manifest.RecoveryVersion = &v
		runtimeReseal(&m)
		if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
			t.Fatal("unbounded recovery accepted", p)
		}
	}
}

func TestAzureSingleConnectionContractRejectsSeparateLocalPeersAndKeys(t *testing.T) {
	for name, mutate := range map[string]func(*RuntimeMaterial){
		"separate LNG local peer": func(m *RuntimeMaterial) {
			m.Manifest.Tunnels[1].InsideCIDR = "169.254.10.5/32"
			m.Manifest.Tunnels[1].CustomerInsideAddress = "169.254.10.5"
		},
		"same Azure instance": func(m *RuntimeMaterial) {
			m.Manifest.Tunnels[1].CloudInsideAddress = m.Manifest.Tunnels[0].CloudInsideAddress
		},
		"different connection keys": func(m *RuntimeMaterial) { m.Secrets[1].PSK = "Different_Key_123" },
		"legacy /30": func(m *RuntimeMaterial) {
			for i := range m.Manifest.Tunnels {
				m.Manifest.Tunnels[i].InsideCIDR = []string{"169.254.21.0/30", "169.254.22.0/30"}[i]
				m.Manifest.Tunnels[i].CustomerInsideAddress = []string{"169.254.21.1", "169.254.22.1"}[i]
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := azureMaterialFixture(AzureActiveActiveBGPProfile)
			mutate(&m)
			runtimeReseal(&m)
			if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
				t.Fatal("separate connection accepted")
			}
		})
	}
	m := azureMaterialFixture(AzureActiveActiveStaticProfile)
	m.Secrets[1].PSK = "Different_Key_123"
	if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
		t.Fatal("static connection keys differ")
	}
}
func TestAzureAPIPAGuardIsExplicitAndBounded(t *testing.T) {
	m := azureMaterialFixture(AzureActiveActiveBGPProfile)
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	peers := bgpRefusalPeers(e)
	g := GuardConnection{ID: m.Manifest.ConnectionID, PrefixOnly: true, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, BGPPeers: peers}
	intent := GuardIntent{Namespace: e.Allocation.Namespace, OwnerID: m.Manifest.NodeID, Revision: 1, Connections: []GuardConnection{g}}
	if _, err := RenderGuard(intent); err != nil {
		t.Fatal("Azure refusal guard", err)
	}
	for _, p := range peers {
		if p.TransportProfile != "azure-apipa-v1" || p.InterfaceIndex != 0 {
			t.Fatal("refusal leaked authority")
		}
	}
	intent.Connections[0].BGPPeers[0].TransportProfile = ""
	if _, err := RenderGuard(intent); err == nil {
		t.Fatal("legacy guard widened to Azure host transport")
	}
	intent.Connections[0].BGPPeers[0].TransportProfile = "azure-apipa-v1"
	intent.Connections[0].BGPPeers[0].Remote = netip.MustParseAddr("10.99.0.1")
	if _, err := RenderGuard(intent); err == nil {
		t.Fatal("non-Azure peer guard accepted")
	}
}

func TestAzurePublicASNContractPreservesOtherProviders(t *testing.T) {
	for _, asn := range []uint32{13335, 196608} {
		m := azureMaterialFixture(AzureActiveActiveBGPProfile)
		m.Manifest.BGP.LocalASN = asn
		runtimeReseal(&m)
		e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
		if err != nil {
			t.Fatal("Azure public ASN refused", asn, err)
		}
		cfg, err := runtimeBGPProcessConfig(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = bgpengine.RenderConfig(cfg); err != nil {
			t.Fatal("FRR public ASN refused", err)
		}
		if validBGPConfig(*m.Manifest.BGP) {
			t.Fatal("AWS/GCP ASN restriction widened")
		}
	}
	for _, asn := range []uint32{0, 8074, 8075, 12076, 23456, 64496, 64511, 65515, 65517, 65520, 65535, 65551, 4294967295} {
		b := BGPConfig{LocalASN: asn, RemoteASN: 65515, RouterID: "10.10.0.1", MaximumPrefixes: 64}
		if validAzureBGPConfig(b) {
			t.Fatal("reserved local ASN admitted", asn)
		}
	}
	for _, asn := range []uint32{8074, 8075, 12076, 65517, 65520} {
		b := BGPConfig{LocalASN: 13335, RemoteASN: asn, RouterID: "10.10.0.1", MaximumPrefixes: 64}
		if validAzureBGPConfig(b) {
			t.Fatal("reserved gateway ASN admitted", asn)
		}
	}
}

func TestLegacyBGPPeerSerializationRemainsExact(t *testing.T) {
	// Independent persisted shape before provider metadata existed. Omitting the
	// Azure transport tag must preserve canonical bytes and journal-template hashes.
	const original = `{"Local":"169.254.20.1","Remote":"169.254.20.2","InterfaceIndex":7}`
	peer := GuardBGPPeer{Local: netip.MustParseAddr("169.254.20.1"), Remote: netip.MustParseAddr("169.254.20.2"), InterfaceIndex: 7}
	raw, err := json.Marshal(peer)
	if err != nil || string(raw) != original || stringDigest(raw) != stringDigest([]byte(original)) {
		t.Fatal("legacy guard peer bytes drifted")
	}
}
