//go:build linux

package ipsec

import (
	"context"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"os"
	"path/filepath"
	"testing"
)

func TestAzureObserverHistoryCensusIncludesCompactedAndNestedDuties(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root-private native directory census")
	}
	parent := journalDir(t)
	selected := RuntimeJournalEntry{DeliveryID: uuid.New(), BGPProcess: &bgpengine.ProcessIdentity{Generation: 3}}
	retained := RuntimeJournalEntry{DeliveryID: uuid.New(), Phase: RuntimeRetainedRefusal}
	nested := RuntimeJournalEntry{DeliveryID: uuid.New()}
	retained.Restoration = &RuntimeRestoration{Retired: []RuntimeRetiredEpoch{{Entry: nested}}}
	payload := runtimeJournalPayload{Entries: []RuntimeJournalEntry{selected, retained}}
	directory := func(delivery uuid.UUID, generation string) string {
		return filepath.Join(parent, "bgp-"+delivery.String()+"-g"+generation)
	}
	live := directory(selected.DeliveryID, "3")
	if os.Mkdir(live, 0700) != nil || os.WriteFile(filepath.Join(live, "bgpd.conf"), []byte("live fixture"), 0600) != nil {
		t.Fatal("fixture")
	}
	if azureProofHistoryCensus(context.Background(), payload, selected, true, parent) != nil {
		t.Fatal("selected current generation wrongly censused as retired")
	}
	for _, item := range []struct {
		id  uuid.UUID
		gen string
	}{{selected.DeliveryID, "2"}, {selected.DeliveryID, "100"}, {retained.DeliveryID, "100"}, {nested.DeliveryID, "1"}} {
		path := directory(item.id, item.gen)
		if os.Mkdir(path, 0700) != nil || os.WriteFile(filepath.Join(path, "survivor"), []byte("unowned"), 0600) != nil {
			t.Fatal("fixture")
		}
		if azureProofHistoryCensus(context.Background(), payload, selected, true, parent) == nil {
			t.Fatal("historical survivor accepted")
		}
		if _, err := os.Stat(filepath.Join(path, "survivor")); err != nil {
			t.Fatal("census mutated survivor")
		}
		if os.Remove(filepath.Join(path, "survivor")) != nil || os.Remove(path) != nil {
			t.Fatal("fixture cleanup")
		}
	}
	// Generation one has no predecessors but must still check later residue.
	first := selected
	first.BGPProcess = &bgpengine.ProcessIdentity{Generation: 1}
	firstPayload := runtimeJournalPayload{Entries: []RuntimeJournalEntry{first}}
	if os.Remove(filepath.Join(live, "bgpd.conf")) != nil || os.Remove(live) != nil {
		t.Fatal("fixture cleanup")
	}
	liveOne := directory(first.DeliveryID, "1")
	if os.Mkdir(liveOne, 0700) != nil || os.WriteFile(filepath.Join(liveOne, "bgpd.conf"), []byte("live"), 0600) != nil {
		t.Fatal("fixture")
	}
	if azureProofHistoryCensus(context.Background(), firstPayload, first, true, parent) != nil {
		t.Fatal("generation one falsely refused")
	}
	future := directory(first.DeliveryID, "2")
	if os.Mkdir(future, 0700) != nil || os.WriteFile(filepath.Join(future, "orphan"), []byte("unowned"), 0600) != nil {
		t.Fatal("fixture")
	}
	if azureProofHistoryCensus(context.Background(), firstPayload, first, true, parent) == nil {
		t.Fatal("future residue accepted")
	}
	if azureProofHistoryCensus(context.Background(), payload, selected, false, parent) == nil {
		t.Fatal("absence mode skipped current artifacts")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if azureProofHistoryCensus(ctx, payload, selected, true, parent) == nil {
		t.Fatal("canceled census accepted")
	}
	selected.BGPProcess.Generation = 0
	if azureProofHistoryCensus(context.Background(), payload, selected, true, parent) == nil {
		t.Fatal("zero active generation accepted")
	}
}
