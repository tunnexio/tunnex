package ipsec

import (
	"github.com/google/uuid"
	"net/netip"
	"strings"
	"testing"
)

func TestAzureProfileRemovedTransportCannotCoalesceWithUnrelatedProjection(t *testing.T) {
	_, old := profileRecreationMaterial(t, AzureActiveActiveBGPProfile, nil)
	old = retainedAzure(old)
	_, next := profileRecreationMaterial(t, AzureActiveStandbyStaticProfile, []RuntimeJournalEntry{old})
	_, unrelated := profileRecreationMaterial(t, AzureActiveStandbyStaticProfile, nil)
	unrelated.SiteID = old.SiteID
	unrelated.Engines[0].Binding.OrgID = old.Engines[0].Binding.OrgID
	unrelated.Engines[0].Binding.GatewayID = old.Engines[0].Binding.GatewayID
	removed := old.Engines[1].RemoteAddress
	unrelated.Engines[0].RemoteAddress = removed
	unrelated.Engines[0].RemoteIdentity = removed
	unrelated.Engines[0].RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}
	unrelated.Allocation.Tunnels[0].RemotePrefixes = append([]netip.Prefix(nil), unrelated.Engines[0].RemotePrefixes...)
	entries := []RuntimeJournalEntry{old, next, unrelated}
	projected, retired, err := runtimeGuardProjection(entries)
	if err != nil || !validJournalPayload(runtimeJournalPayload{Version: 13, OwnerID: old.Engines[0].Binding.GatewayID, Entries: entries}) {
		t.Fatal("causal full-journal fixture refused", err)
	}
	target := netip.PrefixFrom(removed, 32)
	found := false
	for _, p := range retainedAzureTransportRefusals(entries, projected, retired) {
		found = found || p == target
	}
	if !found {
		t.Fatal("unrelated address collision concealed removed predecessor transport")
	}
}

func TestAzureProfileTransportCoalescingRequiresAuthenticatedReference(t *testing.T) {
	_, old := profileRecreationMaterial(t, AzureActiveActiveBGPProfile, nil)
	old = retainedAzure(old)
	_, next := profileRecreationMaterial(t, AzureActiveStandbyStaticProfile, []RuntimeJournalEntry{old})
	shared := netip.PrefixFrom(old.Engines[0].RemoteAddress, 32)
	contains := func(values []netip.Prefix) bool {
		for _, p := range values {
			if p == shared {
				return true
			}
		}
		return false
	}
	if contains(retainedAzureTransportRefusals([]RuntimeJournalEntry{old, next}, []RuntimeJournalEntry{next}, []uuid.UUID{old.Allocation.ConnectionID})) {
		t.Fatal("authenticated shared outside tuple not coalesced")
	}
	for name, mutate := range map[string]func(*RuntimeJournalEntry){
		"missing": func(e *RuntimeJournalEntry) { e.RetainedGuardPredecessors = nil },
		"digest":  func(e *RuntimeJournalEntry) { e.RetainedGuardPredecessors[0].OwnershipDigest = strings.Repeat("0", 64) },
		"cleanup": func(e *RuntimeJournalEntry) { e.RetainedGuardPredecessors[0].CleanupDeliveryID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneJournal(runtimeJournalPayload{Entries: []RuntimeJournalEntry{next}}).Entries[0]
			mutate(&changed)
			if !contains(retainedAzureTransportRefusals([]RuntimeJournalEntry{old, changed}, []RuntimeJournalEntry{changed}, []uuid.UUID{old.Allocation.ConnectionID})) {
				t.Fatal("unauthenticated successor erased predecessor denial")
			}
		})
	}
}
