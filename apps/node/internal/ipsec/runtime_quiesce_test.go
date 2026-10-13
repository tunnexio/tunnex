package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"testing"
)

func quiescedFixture(t *testing.T) RuntimeJournalEntry {
	t.Helper()
	e := processStateFixture(t)
	e.Phase = RuntimeApplied
	e.BGPProcess.Stage = "cleaned"
	e.Restoration = &RuntimeRestoration{BootID: e.BGPProcess.BootID, Retired: []RuntimeRetiredEpoch{}}
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	for i, a := range e.Allocation.Tunnels {
		e.Observed[i] = Ownership{Namespace: e.Allocation.Namespace, InterfaceName: a.Name, InterfaceIndex: 10 + i, XFRMID: a.XFRMID}
	}
	return e
}
func TestRuntimeQuiescedJournalPreservesIntentAndCompatibility(t *testing.T) {
	e := quiescedFixture(t)
	p := runtimeJournalPayload{Version: 7, OwnerID: e.Engines[0].Binding.GatewayID, Sequence: 1, Entries: []RuntimeJournalEntry{e}}
	if !validJournalPayload(p) {
		t.Fatal("original applied fixture invalid")
	}
	next := cloneJournal(p)
	next.Version = 12
	next.Sequence++
	next.Entries[0].Phase = RuntimeQuiesced
	if !validJournalPayload(next) || !validJournalSuccessor(p, next) {
		t.Fatal("proved-negative checkpoint refused")
	}
	for _, v := range []int{7, 11} {
		old := cloneJournal(next)
		old.Version = v
		if validJournalPayload(old) {
			t.Fatal("legacy format admitted quiesced")
		}
	}
	restored := cloneJournal(next)
	restored.Sequence++
	restored.Entries[0].Phase = RuntimeApplying
	restored.Entries[0].Observed = [2]Ownership{}
	if !validJournalPayload(restored) || !validJournalSuccessor(next, restored) {
		t.Fatal("exact restage reservation refused")
	}
	original := restored.Entries[0]
	original.Phase = e.Phase
	original.Observed = e.Observed
	if !reflect.DeepEqual(original, e) {
		t.Fatal("immutable intent/history changed")
	}
	for name, change := range map[string]func(*RuntimeJournalEntry){
		"live process":         func(e *RuntimeJournalEntry) { e.BGPProcess.Stage = "ready" },
		"foreign process boot": func(e *RuntimeJournalEntry) { e.BGPProcess.BootID = uuid.NewString() },
		"missing process":      func(e *RuntimeJournalEntry) { e.BGPProcess = nil },
		"missing boot":         func(e *RuntimeJournalEntry) { e.Restoration = nil },
		"missing routes":       func(e *RuntimeJournalEntry) { e.BGPRoutes = nil },
		"not withdrawal":       func(e *RuntimeJournalEntry) { e.BGPRoutes.Withdrawal = false },
		"invented cleanup":     func(e *RuntimeJournalEntry) { e.CleanupID = uuid.New() },
		"erased ownership":     func(e *RuntimeJournalEntry) { e.Observed = [2]Ownership{} },
		"changed delivery":     func(e *RuntimeJournalEntry) { e.DeliveryID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			bad := cloneJournal(next)
			change(&bad.Entries[0])
			if validJournalPayload(bad) && validJournalSuccessor(p, bad) {
				t.Fatal("unsafe quiescence accepted")
			}
		})
	}
	if e.Phase != RuntimeApplied || e.Restoration.Epoch != 0 {
		t.Fatal("crash inferred graceful stop")
	}
}
func TestRuntimeQuiesceDenialFailureNeverJoinsOrCheckpoints(t *testing.T) {
	c, _, _, _ := bgpControllerFixture(t, false)
	before, _ := c.journal.Entries()
	joined := false
	c.replace = func(context.Context, GuardIntent) (GuardManifest, error) { return GuardManifest{}, ErrGuardReadback }
	if c.Quiesce(context.Background(), func() error { joined = true; return nil }) == nil {
		t.Fatal("unproved denial accepted")
	}
	after, _ := c.journal.Entries()
	if joined || !reflect.DeepEqual(before, after) {
		t.Fatal("failure joined or rewrote entry")
	}
}
func TestRuntimeQuiescedForeignSurvivorStillRefuses(t *testing.T) {
	e := quiescedFixture(t)
	e.Phase = RuntimeQuiesced
	k := KernelInventory{Namespace: e.Allocation.Namespace}
	x := XFRMInventory{Namespace: e.Allocation.Namespace}
	d := DaemonInventory{}
	if !runtimeObjectsAbsent(e, d, k, x) {
		t.Fatal("negative fixture invalid")
	}
	x.States = []XFRMState{{IfID: e.Engines[0].XFRMID, ReqID: e.Engines[0].ReqID}}
	if runtimeObjectsAbsent(e, d, k, x) {
		t.Fatal("native survivor accepted")
	}
}

func TestRuntimeQuiescedMissingFreshLeaseCannotReserve(t *testing.T) {
	e := quiescedFixture(t)
	e.Phase = RuntimeQuiesced
	entries := []RuntimeJournalEntry{e}
	before := cloneRuntimeEntries(entries)
	c := &RuntimeController{}
	for _, a := range []*PermitLeaseAuthority{nil, NewPermitLeaseAuthority()} {
		if c.reserveQuiescedApply(context.Background(), entries, 0, a, PermitLeaseIdentity{DeliveryID: e.DeliveryID, Binding: e.Engines[0].Binding}) == nil {
			t.Fatal("missing lease admitted")
		}
		if !reflect.DeepEqual(entries, before) {
			t.Fatal("missing lease changed checkpoint")
		}
	}
}

func TestRuntimeQuiescedFailedOrCanceledJoinLeavesApplied(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		c, _, _, _ := bgpControllerFixture(t, false)
		before, _ := c.journal.Entries()
		prepared := cloneRuntimeEntries(before)
		prepared[0].Phase = RuntimeQuiesced
		ctx, cancel := context.WithCancel(context.Background())
		joined := false
		err := c.completeQuiesce(ctx, prepared, DaemonInventory{}, func() error {
			joined = true
			if canceled {
				cancel()
				return nil
			}
			return ErrRuntimeController
		})
		cancel()
		after, _ := c.journal.Entries()
		if err == nil || !joined || !reflect.DeepEqual(before, after) || after[0].Phase != RuntimeApplied {
			t.Fatal("incomplete join gained restage checkpoint")
		}
	}
}
