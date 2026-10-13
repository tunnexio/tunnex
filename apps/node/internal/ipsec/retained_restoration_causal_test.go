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

func retainedRestorationThreeFixture(t *testing.T) ([]RuntimeJournalEntry, RuntimeJournalEntry) {
	t.Helper()
	old, successor, _ := retainedHandoffFixture(t)
	old.ContractVersion = 2
	old.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Stage: "completed"}
	successor.ContractVersion = 2
	successor.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Stage: "completed"}
	olds := []RuntimeJournalEntry{old}
	for i := 0; i < 2; i++ {
		v := old
		v.DeliveryID = uuid.New()
		v.CleanupID = uuid.New()
		olds = append(olds, v)
	}
	successor.RetainedGuardPredecessors = nil
	for _, v := range olds {
		successor.RetainedGuardPredecessors = append(successor.RetainedGuardPredecessors, RuntimeRetainedGuardPredecessor{ConnectionID: v.Allocation.ConnectionID, DeliveryID: v.DeliveryID, CleanupDeliveryID: v.CleanupID, OwnershipDigest: v.OwnershipDigest})
	}
	sort.Slice(successor.RetainedGuardPredecessors, func(i, j int) bool {
		return successor.RetainedGuardPredecessors[i].DeliveryID.String() < successor.RetainedGuardPredecessors[j].DeliveryID.String()
	})
	successor.Phase = RuntimeApplied
	return olds, successor
}
func retainedRestorationClone(t *testing.T, entries []RuntimeJournalEntry) []RuntimeJournalEntry {
	t.Helper()
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	var out []RuntimeJournalEntry
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("clone")
	}
	return out
}
func TestRetainedGuardThreeLineagesGenuineRestorationAccepted(t *testing.T) {
	olds, successor := retainedRestorationThreeFixture(t)
	owner := successor.Engines[0].Binding.GatewayID
	before := append(append([]RuntimeJournalEntry{}, olds...), successor)
	original, _ := json.Marshal(before)
	if !validJournalPayload(runtimeJournalPayload{Version: 9, OwnerID: owner, Entries: before}) {
		t.Fatal("full three-lineage fixture not valid")
	}
	next := restoredFixture(successor)
	after := append(append([]RuntimeJournalEntry{}, olds...), next)
	if !validRestoration(next) || !validRestorationSuccessor(successor, next) || !validJournalPayload(runtimeJournalPayload{Version: 9, OwnerID: owner, Entries: after}) {
		t.Fatal("genuine restoration with unchanged exact three predecessor refs refused")
	}
	if !reflect.DeepEqual(next.Restoration.Retired[0].Entry.RetainedGuardPredecessors, successor.RetainedGuardPredecessors) {
		t.Fatal("archived refs erased")
	}
	if !reflect.DeepEqual(next.RetainedGuardPredecessors, successor.RetainedGuardPredecessors) {
		t.Fatal("current refs erased")
	}
	if !validJournalSuccessor(runtimeJournalPayload{Version: 9, OwnerID: owner, Entries: before}, runtimeJournalPayload{Version: 9, OwnerID: owner, Entries: after}) {
		t.Fatal("whole journal successor rejected")
	}
	unchanged, _ := json.Marshal(before)
	if string(unchanged) != string(original) {
		t.Fatal("validation mutated old entry bytes")
	}
	// A second genuine namespace reset retains the same original references in both epochs.
	second := restoredFixture(next)
	if !validRestoration(second) || !validJournalPayload(runtimeJournalPayload{Version: 9, OwnerID: owner, Entries: append(append([]RuntimeJournalEntry{}, olds...), second)}) {
		t.Fatal("second restoration lost predecessor obligations")
	}
}
func TestRetainedGuardRestorationRejectsChangedHistoryOrOuterGraph(t *testing.T) {
	olds, successor := retainedRestorationThreeFixture(t)
	next := restoredFixture(successor)
	base := append(append([]RuntimeJournalEntry{}, olds...), next)
	owner := successor.Engines[0].Binding.GatewayID
	cases := map[string]func([]RuntimeJournalEntry) []RuntimeJournalEntry{
		"archived refs omitted": func(e []RuntimeJournalEntry) []RuntimeJournalEntry {
			e[3].Restoration.Retired[0].Entry.RetainedGuardPredecessors = nil
			return e
		},
		"archived cleanup changed": func(e []RuntimeJournalEntry) []RuntimeJournalEntry {
			e[3].Restoration.Retired[0].Entry.RetainedGuardPredecessors[0].CleanupDeliveryID = uuid.New()
			return e
		},
		"archived digest changed": func(e []RuntimeJournalEntry) []RuntimeJournalEntry {
			e[3].Restoration.Retired[0].Entry.RetainedGuardPredecessors[0].OwnershipDigest = strings.Repeat("a", 64)
			return e
		},
		"archived structural foreign gateway": func(e []RuntimeJournalEntry) []RuntimeJournalEntry {
			e[3].Restoration.Retired[0].Entry.Engines[0].Binding.GatewayID = uuid.New()
			return e
		},
		"outer predecessor missing": func(e []RuntimeJournalEntry) []RuntimeJournalEntry { return e[1:] },
		"outer cleanup changed":     func(e []RuntimeJournalEntry) []RuntimeJournalEntry { e[0].CleanupID = uuid.New(); return e },
		"outer digest changed": func(e []RuntimeJournalEntry) []RuntimeJournalEntry {
			e[0].OwnershipDigest = strings.Repeat("b", 64)
			return e
		},
		"outer uncleared lineage": func(e []RuntimeJournalEntry) []RuntimeJournalEntry { e[0].Phase = RuntimeCleanupPending; return e },
		"partial lineage references": func(e []RuntimeJournalEntry) []RuntimeJournalEntry {
			e[3].RetainedGuardPredecessors = e[3].RetainedGuardPredecessors[:2]
			e[3].Restoration.Retired[0].Entry.RetainedGuardPredecessors = e[3].Restoration.Retired[0].Entry.RetainedGuardPredecessors[:2]
			return e
		},
		"partial remote domain": func(e []RuntimeJournalEntry) []RuntimeJournalEntry {
			for i := 0; i < 2; i++ {
				e[3].Engines[i].RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/25")}
				e[3].Allocation.Tunnels[i].RemotePrefixes = e[3].Engines[i].RemotePrefixes
				e[3].Restoration.Retired[0].Entry.Engines[i].RemotePrefixes = e[3].Engines[i].RemotePrefixes
				e[3].Restoration.Retired[0].Entry.Allocation.Tunnels[i].RemotePrefixes = e[3].Engines[i].RemotePrefixes
			}
			return e
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e := change(retainedRestorationClone(t, base))
			if validJournalPayload(runtimeJournalPayload{Version: 9, OwnerID: owner, Entries: e}) {
				t.Fatal("corrupt archive or outer predecessor graph accepted")
			}
		})
	}
}
