package ipsec

import (
	"bytes"
	"encoding/json"
	"github.com/google/uuid"
	"net/netip"
	"sort"
	"strings"
	"testing"
)

func TestAzureProfileRecreationBGPToStaticCausal(t *testing.T) {
	oldm := azureMaterialFixture(AzureActiveActiveBGPProfile)
	old, _, err := runtimeMaterialEntry(oldm, oldm.Manifest.OrgID, oldm.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	m := azureMaterialFixture(AzureActiveActiveStaticProfile)
	m.Manifest.OrgID = oldm.Manifest.OrgID
	m.Manifest.NodeID = oldm.Manifest.NodeID
	m.Manifest.SiteID = oldm.Manifest.SiteID
	runtimeReseal(&m)
	next, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	next.AzureProfileRecreationVersion = 1
	if !sameHandoffDomain(next, retainedAzure(old)) {
		t.Fatal("authorized cross-profile handoff refused")
	}
}

func profileRecreationMaterial(t *testing.T, profile string, prior []RuntimeJournalEntry) (RuntimeMaterial, RuntimeJournalEntry) {
	t.Helper()
	m := azureMaterialFixture(profile)
	if len(prior) > 0 {
		old := prior[0]
		m.Manifest.OrgID = old.Engines[0].Binding.OrgID
		m.Manifest.NodeID = old.Engines[0].Binding.GatewayID
		m.Manifest.SiteID = old.SiteID
		one := 1
		m.Manifest.AzureProfileRecreationVersion = &one
		for _, e := range prior {
			m.Manifest.RetainedGuardPredecessors = append(m.Manifest.RetainedGuardPredecessors, RuntimeRetainedGuardPredecessor{e.Allocation.ConnectionID, e.DeliveryID, e.CleanupID, e.OwnershipDigest})
		}
		sort.Slice(m.Manifest.RetainedGuardPredecessors, func(i, j int) bool {
			return m.Manifest.RetainedGuardPredecessors[i].DeliveryID.String() < m.Manifest.RetainedGuardPredecessors[j].DeliveryID.String()
		})
	}
	runtimeReseal(&m)
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	return m, e
}
func TestAzureProfileRecreationFourProfileContracts(t *testing.T) {
	profiles := []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveStandbyStaticProfile}
	for _, a := range profiles {
		for _, b := range profiles {
			if a == b {
				continue
			}
			t.Run(a+"-to-"+b, func(t *testing.T) {
				_, old := profileRecreationMaterial(t, a, nil)
				old = retainedAzure(old)
				_, next := profileRecreationMaterial(t, b, []RuntimeJournalEntry{old})
				entries := []RuntimeJournalEntry{old, next}
				before, _ := json.Marshal(entries)
				if !validRetainedGuardJournal(entries) || !validJournalPayload(runtimeJournalPayload{Version: 13, OwnerID: next.Engines[0].Binding.GatewayID, Entries: entries}) || validJournalPayload(runtimeJournalPayload{Version: 12, OwnerID: next.Engines[0].Binding.GatewayID, Entries: entries}) {
					t.Fatal("complete versioned lineage refused")
				}
				projected, retired, err := runtimeGuardProjection(entries)
				if err != nil || len(projected) != 1 || len(retired) != 1 {
					t.Fatal("projection")
				}
				intent := GuardIntent{Namespace: next.Allocation.Namespace, OwnerID: next.Engines[0].Binding.GatewayID, Revision: 1, RetainedLeaseIDs: retired, RefusalPrefixes: retainedRefusalPrefixes(entries, projected, retired), Connections: []GuardConnection{{ID: next.Allocation.ConnectionID, PrefixOnly: true, Local: next.Engines[0].LocalPrefixes, Remote: next.Engines[0].RemotePrefixes, BGPPeers: bgpRefusalPeers(next)}}}
				guard, err := RenderGuard(intent)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(guard.NFT, "counter accept") || !strings.Contains(guard.NFT, guardLeaseName(old.Allocation.ConnectionID)) {
					t.Fatal("manufactured authority")
				}
				for _, p := range intent.RefusalPrefixes {
					if !strings.Contains(guard.NFT, "ip daddr "+p.String()+" counter drop") {
						t.Fatal("removed tuple denied projection absent")
					}
				}
				after, _ := json.Marshal(entries)
				if !bytes.Equal(before, after) {
					t.Fatal("historical entry changed")
				}
			})
		}
	}
}
func TestAzureProfileRecreationRejectsForeignAndIncompleteLineage(t *testing.T) {
	_, old := profileRecreationMaterial(t, AzureActiveActiveBGPProfile, nil)
	old = retainedAzure(old)
	_, next := profileRecreationMaterial(t, AzureActiveStandbyStaticProfile, []RuntimeJournalEntry{old})
	for name, change := range map[string]func(*RuntimeJournalEntry){
		"version omitted": func(e *RuntimeJournalEntry) { e.AzureProfileRecreationVersion = 0 }, "version unknown": func(e *RuntimeJournalEntry) { e.AzureProfileRecreationVersion = 2 }, "mixed flags": func(e *RuntimeJournalEntry) { e.AzureBGPRecreationVersion = 1 }, "site": func(e *RuntimeJournalEntry) { e.SiteID = uuid.New() }, "local": func(e *RuntimeJournalEntry) {
			e.Engines[0].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}
		}, "unequal overlap": func(e *RuntimeJournalEntry) {
			e.Engines[0].RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.20.1.0/24")}
		}, "outside": func(e *RuntimeJournalEntry) { e.Engines[0].RemoteAddress = netip.MustParseAddr("203.0.113.9") }, "partial": func(e *RuntimeJournalEntry) { e.RetainedGuardPredecessors = nil }, "digest": func(e *RuntimeJournalEntry) { e.RetainedGuardPredecessors[0].OwnershipDigest = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneJournal(runtimeJournalPayload{Entries: []RuntimeJournalEntry{next}}).Entries[0]
			change(&changed)
			if validRetainedGuardJournal([]RuntimeJournalEntry{old, changed}) {
				t.Fatal("foreign lineage accepted")
			}
		})
	}
	_, same := profileRecreationMaterial(t, AzureActiveActiveBGPProfile, []RuntimeJournalEntry{old})
	if validRetainedGuardJournal([]RuntimeJournalEntry{old, same}) {
		t.Fatal("cross version inferred for same-profile only")
	}
}

func TestAzureProfileRecreationCompleteChainRestart(t *testing.T) {
	profiles := []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveActiveBGPProfile}
	var entries []RuntimeJournalEntry
	for _, profile := range profiles {
		_, next := profileRecreationMaterial(t, profile, entries)
		if len(entries) > 0 {
			all := append(append([]RuntimeJournalEntry(nil), entries...), next)
			if !validRetainedGuardJournal(all) {
				t.Fatal("full cross-profile history refused")
			}
			projected, retired, err := runtimeGuardProjection(all)
			if err != nil || len(projected) != 1 || len(retired) != len(entries) {
				t.Fatal("ancestor lineage dropped")
			}
			before, _ := json.Marshal(all)
			retainedRefusalPrefixes(all, projected, retired)
			after, _ := json.Marshal(all)
			if !bytes.Equal(before, after) {
				t.Fatal("ancestor mutation")
			}
			for i := range entries {
				bad := cloneJournal(runtimeJournalPayload{Entries: all}).Entries
				bad[i].Phase = RuntimeCleanupPending
				if validRetainedGuardJournal(bad) {
					t.Fatal("unfinished ancestor accepted")
				}
			}
		}
		entries = append(entries, retainedAzure(next))
	}
	// A final current reservation is saved through genuine journal transitions.
	old := entries[0]
	_, next := profileRecreationMaterial(t, AzureActiveActiveStaticProfile, []RuntimeJournalEntry{old})
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
	loaded, err := j.Entries()
	if err != nil || len(loaded) != 2 || loaded[1].AzureProfileRecreationVersion != 1 || loaded[1].Phase != RuntimeReserved {
		t.Fatal("restart manufactured health or lost lineage")
	}
	projected, retired, err := runtimeGuardProjection(loaded)
	if err != nil || len(projected) != 1 || len(retired) != 1 {
		t.Fatal("durable denial projection lost")
	}
}
