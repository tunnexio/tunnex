package ipsec

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A real journal successor retains the old cleaned delivery alongside the
// current enabled delivery of the SAME connection, exactly as normal disable
// and enable revisions do. The history belongs to the current delivery only.
func historyLineageFixture(t *testing.T) *recoveryTestRig {
	t.Helper()
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	r.m.DesiredRevision, r.m.Manifest.DesiredRevision = 4, 4
	runtimeReseal(&r.m)
	current, _, err := runtimeMaterialEntry(r.m, r.m.Manifest.OrgID, r.m.Manifest.NodeID, r.env.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range current.Allocation.Tunnels {
		current.Observed[i] = Ownership{Namespace: current.Allocation.Namespace, InterfaceName: a.Name, InterfaceIndex: 10 + i, XFRMID: a.XFRMID}
	}
	j, err := OpenRuntimeJournal(journalDir(t), r.m.Manifest.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	r.c.journal = j
	entries := []RuntimeJournalEntry{current}
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		entries[0].Phase = phase
		if err = j.Save(entries); err != nil {
			t.Fatal(err)
		}
	}
	if err = r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	old := cloneJournal(runtimeJournalPayload{Entries: entries}).Entries[0]
	old.DeliveryID = uuid.New()
	old.OwnershipDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	old.Allocation.Generation = uuid.New()
	old.Observed = [2]Ownership{}
	for i := range old.Engines {
		old.Engines[i].Binding.DesiredRevision = 1
		old.Allocation.Tunnels[i].Alias = KernelTunnelAlias(old.Allocation.Generation, old.Allocation.Tunnels[i].TunnelID)
	}
	old.Phase = RuntimeReserved
	entries = append(entries, old)
	if err = j.Save(entries); err != nil {
		t.Fatal(err)
	}
	entries[1].Phase = RuntimeCleanupPending
	entries[1].CleanupID, entries[1].CleanupDesiredRevision, entries[1].CoveredDeliveryRevision = uuid.New(), 2, 1
	if err = j.Save(entries); err != nil {
		t.Fatal(err)
	}
	entries[1].Phase = RuntimeRetainedRefusal
	if err = j.Save(entries); err != nil {
		t.Fatal(err)
	}
	// The live journal is not ordered by current delivery. Put retained first to
	// reproduce the actual lab inventory; production validation still sees both.
	if err = j.Save([]RuntimeJournalEntry{entries[1], entries[0]}); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRecoveryRefreshRetainedSameConnectionKeepsCurrentHistory(t *testing.T) {
	r := historyLineageFixture(t)
	id := r.m.Manifest.ConnectionID
	h := r.c.recoveryHistory[id]
	if h == nil || !h.seen || h.epoch.DeliveryID != r.m.ID {
		t.Fatal("current evidence missing")
	}
	beforeHistory := *h
	beforeEntries, _ := r.c.journal.Entries()
	beforeBytes, err := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	beforeActive := r.c.active[id]
	lease := &refreshLeaseFixture{}
	r.c.client = lease
	events, switches := len(r.events), r.switches
	// Not due yet: this callback must retain current evidence and not use native
	// permission, renew authority, mutate a journal, or process historical duty.
	r.now = 500 * time.Millisecond
	if err = r.c.RefreshIPsecRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.c.recoveryHistory[id] != h || *h != beforeHistory {
		t.Fatal("retained predecessor erased current delivery recovery history")
	}
	afterEntries, _ := r.c.journal.Entries()
	afterBytes, _ := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
	if !reflect.DeepEqual(beforeEntries, afterEntries) || !reflect.DeepEqual(beforeBytes, afterBytes) || !reflect.DeepEqual(beforeActive, r.c.active[id]) || len(lease.requests) != 0 || len(r.events) != events || r.switches != switches {
		t.Fatal("historical skip mutated authority or persisted obligations")
	}
	// Preserve all three fresh denial observations and the existing 10-second
	// hold. A historical row must not reset evidence between each callback.
	r.status = [2]string{"down", "up"}
	for _, at := range []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second} {
		r.now = at
		if err = r.c.RefreshIPsecRecovery(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	h = r.c.recoveryHistory[id]
	if h == nil || h.consecutive != 3 || h.lastNow-h.firstDown != 10*time.Second || len(lease.requests) != 3 {
		t.Fatal("current fresh evidence/hold did not survive retained history")
	}
	if r.c.active[id].Authority != beforeActive.Authority || len(r.events) != events || r.switches != switches {
		t.Fatal("observation created forwarding authority")
	}
	afterEntries, _ = r.c.journal.Entries()
	if !reflect.DeepEqual(beforeEntries, afterEntries) {
		t.Fatal("retained or current journal entry changed")
	}
}

func TestRecoveryRefreshCurrentDeliveryCleanupStillDiscardsHistory(t *testing.T) {
	r := historyLineageFixture(t)
	entries, _ := r.c.journal.Entries()
	for i := range entries {
		if entries[i].DeliveryID == r.m.ID {
			entries[i].Phase = RuntimeCleanupPending
			entries[i].CleanupID, entries[i].CleanupDesiredRevision, entries[i].CoveredDeliveryRevision = uuid.New(), 5, 4
		}
	}
	if err := r.c.journal.Save(entries); err != nil {
		t.Fatal(err)
	}
	r.now = 500 * time.Millisecond
	if err := r.c.RefreshIPsecRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.c.recoveryHistory[r.m.Manifest.ConnectionID] != nil {
		t.Fatal("current cleanup retained obsolete recovery evidence")
	}
}

func TestRecoveryRefreshRetainedHistoryDoesNotStarveActiveHeartbeat(t *testing.T) {
	r := historyLineageFixture(t)
	id := r.m.Manifest.ConnectionID
	a := r.c.active[id]
	e := a.Entry
	g := GuardConnection{ID: id, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, Tunnels: e.Observed, PermitFor: 50 * time.Second, PermittedInterfaceIndices: []int{e.Observed[0].InterfaceIndex}, ReplyIngressIndices: []int{e.Observed[0].InterfaceIndex, e.Observed[1].InterfaceIndex}, EncryptedEgress: []GuardEncryptedEgress{{TunnelInterfaceIndex: e.Observed[0].InterfaceIndex, ReqID: e.Engines[0].ReqID, Peer: e.Engines[0].RemoteAddress, UnderlayInterfaceIndex: a.Environment.Underlays[0].InterfaceIndex}}}
	_, seq, _ := r.c.journal.guardTemplates()
	m, err := RenderGuard(GuardIntent{Namespace: e.Allocation.Namespace, OwnerID: r.c.config.GatewayID, Revision: int64(seq) + 1, Connections: []GuardConnection{g}})
	if err != nil || r.c.journal.prepareGuard(m) != nil || r.c.journal.finishGuard(m) != nil {
		t.Fatal("positive native guard fixture", err)
	}
	raw := []byte(m.ExpectedJSON)
	r.c.guard.reader.run = func(context.Context, ...string) ([]byte, error) { return raw, nil }
	entries, _ := r.c.journal.Entries()
	beforeBytes, _ := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
	lease := &refreshLeaseFixture{}
	r.c.client = lease
	r.now = 500 * time.Millisecond
	if err = r.c.RefreshIPsecRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.now = 5 * time.Second
	reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(reports) != 1 || reports[0].ConnectionID != id || reports[0].Report.SelectionSequence == nil || reports[0].Report.ActiveSlot == nil || *reports[0].Report.ActiveSlot != 1 || reports[0].Report.Tunnels[0].Status != "up" || reports[0].Report.Tunnels[1].Status != "up" {
		t.Fatal("current due native heartbeat missing after retained predecessor", err, len(reports))
	}
	after, _ := r.c.journal.Entries()
	afterBytes, _ := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
	if !reflect.DeepEqual(entries, after) || !reflect.DeepEqual(beforeBytes, afterBytes) || r.c.active[id].Authority != a.Authority || len(lease.requests) != 1 {
		t.Fatal("heartbeat changed history/native authority instead of reporting")
	}
}
