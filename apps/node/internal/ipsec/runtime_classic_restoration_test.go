package ipsec

import (
	"github.com/google/uuid"
	"reflect"
	"testing"
)

func TestClassicRestorationReservationRetainsExactSingleDuty(t *testing.T) {
	old, _, _, _ := classicProofFixture(t)
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, old.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	old = saveAppliedRestorationFixture(t, j, old)
	next := old
	next.Allocation.Generation = uuid.New()
	next.Allocation.Tunnels[0].Alias = KernelTunnelAlias(next.Allocation.Generation, next.Allocation.Tunnels[0].TunnelID)
	next.Observed = [2]Ownership{}
	// Inode reuse is permitted only with an exact supervisor receipt; this
	// journal regression models that already-verified reservation, not a receipt.
	next.Restoration = &RuntimeRestoration{BootID: uuid.NewString(), Epoch: 1}
	next.Restoration.Retired = []RuntimeRetiredEpoch{{Entry: flattenedRestorationEntry(old), NewBootID: next.Restoration.BootID, NewNamespace: next.Allocation.Namespace, NewGeneration: next.Allocation.Generation, Termination: "supervisor-confirmed-runtime-stop", EvidenceDigest: stringDigest([]byte("synthetic reservation test only"))}}
	if err = j.Save([]RuntimeJournalEntry{next}); err != nil {
		t.Fatal("Classic same-inode reservation refused", err)
	}
	if j.payload.Version != 10 {
		t.Fatal("Classic journal downgraded")
	}
	j.Close()
	j, err = OpenRuntimeJournal(dir, old.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	entries, err := j.Entries()
	if err != nil || len(entries) != 1 || !reflect.DeepEqual(entries[0], next) {
		t.Fatal("durable Classic restoration lost", err)
	}
	if !reflect.DeepEqual(entries[0].Restoration.Retired[0].Entry, flattenedRestorationEntry(old)) || entries[0].Observed[1] != (Ownership{}) || !reflect.DeepEqual(entries[0].Allocation.Tunnels[1], KernelTunnelAllocation{}) {
		t.Fatal("single duty changed")
	}
	bad := next
	bad.Restoration = &RuntimeRestoration{BootID: next.Restoration.BootID, Epoch: 1, Retired: append([]RuntimeRetiredEpoch(nil), next.Restoration.Retired...)}
	bad.Restoration.Retired[0].Entry.Observed[1] = old.Observed[0]
	if validRestoration(bad) {
		t.Fatal("inactive Classic ownership accepted")
	}
}
