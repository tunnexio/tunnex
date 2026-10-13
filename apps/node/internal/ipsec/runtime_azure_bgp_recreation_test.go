package ipsec

import (
	"encoding/json"
	"github.com/google/uuid"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func azureRecreationMaterial(t *testing.T, prior []RuntimeJournalEntry, remote []string, max int) (RuntimeMaterial, RuntimeJournalEntry) {
	t.Helper()
	m := azureMaterialFixture(AzureActiveActiveBGPProfile)
	m.Manifest.RemotePrefixes = remote
	m.Manifest.BGP.MaximumPrefixes = max
	if len(prior) > 0 {
		source := prior[0]
		m.Manifest.OrgID = source.Engines[0].Binding.OrgID
		m.Manifest.NodeID = source.Engines[0].Binding.GatewayID
		m.Manifest.SiteID = source.SiteID
		v := 1
		m.Manifest.AzureBGPRecreationVersion = &v
		for _, old := range prior {
			m.Manifest.RetainedGuardPredecessors = append(m.Manifest.RetainedGuardPredecessors, RuntimeRetainedGuardPredecessor{old.Allocation.ConnectionID, old.DeliveryID, old.CleanupID, old.OwnershipDigest})
		}
		sort.Slice(m.Manifest.RetainedGuardPredecessors, func(i, j int) bool {
			return m.Manifest.RetainedGuardPredecessors[i].DeliveryID.String() < m.Manifest.RetainedGuardPredecessors[j].DeliveryID.String()
		})
	}
	m.ID = uuid.New()
	m.Manifest.ConnectionID = uuid.New()
	for i := range m.Manifest.Tunnels {
		id := uuid.New()
		m.Manifest.Tunnels[i].ID = id
		m.Manifest.Tunnels[i].LinkName = KernelTunnelName(id)
		m.Manifest.Tunnels[i].XFRMID = KernelTunnelID(id)
		m.Manifest.Tunnels[i].ReqID = KernelTunnelID(id)
		m.Secrets[i].TunnelID = id
	}
	runtimeReseal(&m)
	entry, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	return m, entry
}
func retainedAzure(e RuntimeJournalEntry) RuntimeJournalEntry {
	e.Phase = RuntimeRetainedRefusal
	e.CleanupID = uuid.New()
	e.CleanupDesiredRevision = e.Engines[0].Binding.DesiredRevision + 1
	e.CoveredDeliveryRevision = e.Engines[0].Binding.DesiredRevision
	return e
}
func TestAzureBGPRecreationChainPreservesResidualDenialAndEmptyLeases(t *testing.T) {
	_, first := azureRecreationMaterial(t, nil, []string{"10.231.0.0/16"}, 8)
	first = retainedAzure(first)
	_, limit := azureRecreationMaterial(t, []RuntimeJournalEntry{first}, []string{"10.231.0.0/16", "10.235.77.0/24"}, 1)
	limit = retainedAzure(limit)
	_, baseline := azureRecreationMaterial(t, []RuntimeJournalEntry{first, limit}, []string{"10.231.0.0/16"}, 8)
	entries := []RuntimeJournalEntry{first, limit, baseline}
	before, _ := json.Marshal(entries)
	projected, retired, err := runtimeGuardProjection(entries)
	if err != nil || len(projected) != 1 || projected[0].DeliveryID != baseline.DeliveryID || len(retired) != 2 {
		t.Fatal("full chain refused", err)
	}
	residual := retainedRefusalPrefixes(entries, projected, retired)
	if !reflect.DeepEqual(residual, []netip.Prefix{netip.MustParsePrefix("10.235.77.0/24")}) {
		t.Fatal("old disjoint denial lost", residual)
	}
	intent := GuardIntent{Namespace: baseline.Allocation.Namespace, OwnerID: baseline.Engines[0].Binding.GatewayID, Revision: 1, RetainedLeaseIDs: retired, RefusalPrefixes: residual, Connections: []GuardConnection{{ID: baseline.Allocation.ConnectionID, PrefixOnly: true, Local: baseline.Engines[0].LocalPrefixes, Remote: baseline.Engines[0].RemotePrefixes, BGPPeers: bgpRefusalPeers(baseline)}}}
	rendered, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"ip daddr 10.235.77.0/24 counter drop", "ip saddr 10.235.77.0/24 counter drop"} {
		if !strings.Contains(rendered.NFT, line) {
			t.Fatal("residual refusal missing", line)
		}
	}
	if strings.Contains(rendered.NFT, "counter accept") {
		t.Fatal("handoff manufactured authority")
	}
	for _, id := range retired {
		if !strings.Contains(rendered.NFT, guardLeaseName(id)) {
			t.Fatal("old empty lease set lost")
		}
	}
	after, _ := json.Marshal(entries)
	if string(before) != string(after) {
		t.Fatal("projection changed journal")
	}
	if !validJournalPayload(runtimeJournalPayload{Version: 11, OwnerID: baseline.Engines[0].Binding.GatewayID, Entries: entries}) || validJournalPayload(runtimeJournalPayload{Version: 10, OwnerID: baseline.Engines[0].Binding.GatewayID, Entries: entries}) {
		t.Fatal("version gate")
	}
}
func TestAzureBGPRecreationRejectsChangedBindingsAndPartialLineage(t *testing.T) {
	_, old := azureRecreationMaterial(t, nil, []string{"10.231.0.0/16"}, 8)
	old = retainedAzure(old)
	m, next := azureRecreationMaterial(t, []RuntimeJournalEntry{old}, []string{"10.231.0.0/16", "10.235.77.0/24"}, 1)
	for name, change := range map[string]func(*RuntimeJournalEntry){
		"peer": func(e *RuntimeJournalEntry) {
			p := *e.Allocation.Tunnels[0].BGP
			p.Peer = netip.MustParseAddr("169.254.21.9")
			e.Allocation.Tunnels[0].BGP = &p
		},
		"outside": func(e *RuntimeJournalEntry) { e.Engines[0].RemoteAddress = netip.MustParseAddr("203.0.113.99") },
		"ASN":     func(e *RuntimeJournalEntry) { b := *e.BGP; b.LocalASN = 65020; e.BGP = &b },
		"router":  func(e *RuntimeJournalEntry) { b := *e.BGP; b.RouterID = "10.1.1.99"; e.BGP = &b },
		"overlap": func(e *RuntimeJournalEntry) {
			for i := range e.Engines {
				e.Engines[i].RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.231.0.0/16"), netip.MustParsePrefix("10.231.2.0/24")}
			}
		},
		"no shared": func(e *RuntimeJournalEntry) {
			for i := range e.Engines {
				e.Engines[i].RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.235.77.0/24")}
			}
		},
		"cleanup": func(e *RuntimeJournalEntry) {
			refs := append([]RuntimeRetainedGuardPredecessor(nil), e.RetainedGuardPredecessors...)
			refs[0].CleanupDeliveryID = uuid.New()
			e.RetainedGuardPredecessors = refs
		},
		"version omitted": func(e *RuntimeJournalEntry) { e.AzureBGPRecreationVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := next
			change(&changed)
			if validRetainedGuardJournal([]RuntimeJournalEntry{old, changed}) {
				t.Fatal("changed bound domain accepted")
			}
		})
	}
	unclean := old
	unclean.DeliveryID = uuid.New()
	unclean.Phase = RuntimeCleanupPending
	if validRetainedGuardJournal([]RuntimeJournalEntry{old, unclean, next}) {
		t.Fatal("omitted uncleaned delivery accepted")
	}
	m.Manifest.AzureBGPRecreationVersion = nil
	runtimeReseal(&m)
	if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, old.Allocation.Namespace); err == nil {
		t.Fatal("old BGP reader contract accepted recreation")
	}
	for _, profile := range []string{AzureActiveStandbyBGPProfile, AzureActiveActiveStaticProfile, GCPHABGPProfile} {
		bad := m
		v := 1
		bad.Manifest.AzureBGPRecreationVersion = &v
		bad.Manifest.ProfileID = profile
		runtimeReseal(&bad)
		if validAzureRecreationManifest(bad.Manifest) {
			t.Fatal("scope widened", profile)
		}
	}
}
func TestAzureBGPRecreationJournalRestartAndCrashProjection(t *testing.T) {
	_, old := azureRecreationMaterial(t, nil, []string{"10.231.0.0/16"}, 8)
	old = retainedAzure(old)
	_, next := azureRecreationMaterial(t, []RuntimeJournalEntry{old}, []string{"10.231.0.0/16", "10.235.77.0/24"}, 1)
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, old.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	saveRetainedHandoffFixture(t, j, old, next)
	j.Close()
	j, err = OpenRuntimeJournal(dir, old.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	entries, err := j.Entries()
	if err != nil || len(entries) != 2 || entries[1].AzureBGPRecreationVersion != 1 {
		t.Fatal("restart lost bound reference", err)
	}
	projected, _, err := runtimeGuardProjection(entries)
	if err != nil || len(projected) != 1 || projected[0].Phase != RuntimeReserved {
		t.Fatal("crash treated reservation as health", err)
	}
}
func TestAzureBGPRecreationRefusalIntentPreservesLegacyAndRejectsOverlap(t *testing.T) {
	in := guardFixture()
	raw, _ := json.Marshal(in)
	if strings.Contains(string(raw), "RefusalPrefixes") {
		t.Fatal("omitted field changes old digest")
	}
	in.RefusalPrefixes = []netip.Prefix{in.Connections[0].Remote[0]}
	if _, err := RenderGuard(in); err == nil {
		t.Fatal("overlapping residual accepted")
	}
	if (*RuntimeController)(nil).AzureBGPRecreationCapability() != 0 {
		t.Fatal("nil advertises authority")
	}
}
