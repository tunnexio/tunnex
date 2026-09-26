package ipsec

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func restorationFixture() RuntimeJournalEntry {
	e := journalFixture()
	e.ContractVersion = 2
	e.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Stage: "completed"}
	return e
}
func restoredFixture(old RuntimeJournalEntry) RuntimeJournalEntry {
	b, _ := json.Marshal(old)
	var n RuntimeJournalEntry
	json.Unmarshal(b, &n)
	v := RuntimeRestoration{BootID: uuid.NewString()}
	oldBoot := ""
	if old.Restoration != nil {
		v.Epoch = old.Restoration.Epoch
		v.Retired = append(v.Retired, old.Restoration.Retired...)
		oldBoot = old.Restoration.BootID
	}
	n.Allocation.Namespace = "net:[87654]"
	if old.Allocation.Namespace == n.Allocation.Namespace {
		n.Allocation.Namespace = "net:[87655]"
	}
	n.Allocation.Generation = uuid.New()
	for i := range n.Allocation.Tunnels {
		n.Allocation.Tunnels[i].Alias = KernelTunnelAlias(n.Allocation.Generation, n.Allocation.Tunnels[i].TunnelID)
	}
	n.Observed = [2]Ownership{}
	termination := "kernel-boot-change"
	if oldBoot == "" {
		termination = "supervisor-confirmed-runtime-stop"
	}
	v.Epoch++
	v.Retired = append(v.Retired, RuntimeRetiredEpoch{Entry: flattenedRestorationEntry(old), BootID: oldBoot, NewBootID: v.BootID, NewNamespace: n.Allocation.Namespace, NewGeneration: n.Allocation.Generation, Termination: termination, EvidenceDigest: stringDigest([]byte("test-only termination evidence"))})
	n.Restoration = &v
	return n
}
func saveAppliedRestorationFixture(t *testing.T, j *RuntimeJournal, e RuntimeJournalEntry) RuntimeJournalEntry {
	t.Helper()
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		e.Phase = phase
		if err := j.Save([]RuntimeJournalEntry{e}); err != nil {
			t.Fatal(err)
		}
	}
	return e
}
func TestRestorationJournalReservationSurvivesRestart(t *testing.T) {
	e := restorationFixture()
	dir := journalDir(t)
	owner := e.Engines[0].Binding.GatewayID
	j, err := OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	e = saveAppliedRestorationFixture(t, j, e)
	e.Restoration = &RuntimeRestoration{BootID: uuid.NewString()}
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal("boot reservation", err)
	}
	e.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Sequence: 1, PendingFrom: 1, PendingTo: 2, Stage: "pending"}
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	n := restoredFixture(e)
	if err = j.Save([]RuntimeJournalEntry{n}); err != nil {
		t.Fatal("restoration reservation", err)
	}
	j.Close()
	j, err = OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	got, err := j.Entries()
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], n) {
		t.Fatal("reservation or pending route duty lost", err)
	}
	if !reflect.DeepEqual(got[0].Restoration.Retired[0].Entry, flattenedRestorationEntry(e)) {
		t.Fatal("prior obligation changed")
	}
	if j.payload.Version != 4 {
		t.Fatal("must refuse old readers")
	}
	// A subsequent boot before recreation still retains both retired epochs.
	n2 := restoredFixture(n)
	if err = j.Save([]RuntimeJournalEntry{n2}); err != nil {
		t.Fatal("second restoration", err)
	}
	if err = j.Save([]RuntimeJournalEntry{n}); err == nil {
		t.Fatal("restoration epoch rolled back")
	}
}
func TestRestorationJournalRejectsUnprovenTransitions(t *testing.T) {
	e := restorationFixture()
	e.Phase = RuntimeApplied
	e.Restoration = &RuntimeRestoration{BootID: uuid.NewString()}
	p := func(r RuntimeJournalEntry) runtimeJournalPayload {
		return runtimeJournalPayload{Version: 4, OwnerID: e.Engines[0].Binding.GatewayID, Entries: []RuntimeJournalEntry{r}}
	}
	for name, change := range map[string]func(*RuntimeJournalEntry){
		"missing history": func(n *RuntimeJournalEntry) { n.Restoration.Retired = nil },
		"same boot asserted reboot": func(n *RuntimeJournalEntry) {
			n.Restoration.BootID = e.Restoration.BootID
			n.Restoration.Retired[0].NewBootID = e.Restoration.BootID
		},
		"lost route duty": func(n *RuntimeJournalEntry) {
			n.Recovery = &RuntimeRecoveryState{SelectedSlot: 2, Sequence: 1, Stage: "completed"}
		},
		"retired entry edited":  func(n *RuntimeJournalEntry) { n.Restoration.Retired[0].Entry.SiteID = uuid.New() },
		"proof removed":         func(n *RuntimeJournalEntry) { n.Restoration.Retired[0].EvidenceDigest = "" },
		"old generation reused": func(n *RuntimeJournalEntry) { n.Allocation.Generation = e.Allocation.Generation },
		"old ownership reused": func(n *RuntimeJournalEntry) {
			n.Observed[0] = Ownership{Namespace: n.Allocation.Namespace, InterfaceName: n.Allocation.Tunnels[0].Name, XFRMID: n.Allocation.Tunnels[0].XFRMID, InterfaceIndex: 10}
		},
		"configuration changed": func(n *RuntimeJournalEntry) { n.OwnershipDigest = stringDigest([]byte("changed")) },
	} {
		t.Run(name, func(t *testing.T) {
			n := restoredFixture(e)
			change(&n)
			if validJournalPayload(p(n)) && validJournalSuccessor(p(e), p(n)) {
				t.Fatal("unsafe restoration accepted")
			}
		})
	}
	n := restoredFixture(e)
	n.Restoration = nil
	if validJournalSuccessor(p(e), p(n)) {
		t.Fatal("history removed")
	}
}
func TestRestorationJournalAmbiguousWriteRetainsRefusal(t *testing.T) {
	e := restorationFixture()
	dir := journalDir(t)
	owner := e.Engines[0].Binding.GatewayID
	j, err := OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	e = saveAppliedRestorationFixture(t, j, e)
	n := restoredFixture(e)
	j.syncDirectory = func() error { return errors.New("synthetic fsync failure") }
	if j.Save([]RuntimeJournalEntry{n}) == nil || !j.poisoned {
		t.Fatal("ambiguous write accepted")
	}
	j.Close()
	j, err = OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	got, _ := j.Entries()
	if !reflect.DeepEqual(got[0], n) {
		t.Fatal("potentially committed restoration forgotten")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "journal.json"))
	if len(raw) == 0 {
		t.Fatal("missing durable reservation")
	}
}

func TestRestorationHistorySurvivesCleanup(t *testing.T) {
	e := restorationFixture()
	j, err := OpenRuntimeJournal(journalDir(t), e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	e = saveAppliedRestorationFixture(t, j, e)
	n := restoredFixture(e)
	if err = j.Save([]RuntimeJournalEntry{n}); err != nil {
		t.Fatal(err)
	}
	history, _ := json.Marshal(n.Restoration)
	n.Phase = RuntimeCleanupPending
	n.CleanupID = uuid.New()
	n.CleanupDesiredRevision = n.Engines[0].Binding.DesiredRevision + 1
	n.CoveredDeliveryRevision = n.Engines[0].Binding.DesiredRevision
	if err = j.Save([]RuntimeJournalEntry{n}); err != nil {
		t.Fatal("cleanup reservation", err)
	}
	n.Phase = RuntimeRetainedRefusal
	if err = j.Save([]RuntimeJournalEntry{n}); err != nil {
		t.Fatal("cleanup retention", err)
	}
	entries, err := j.Entries()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(entries[0].Restoration)
	if string(got) != string(history) {
		t.Fatal("cleanup dropped retired ownership evidence")
	}
}
