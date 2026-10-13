package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// Extends TestRecoveryRefreshThenOrdinaryApplySwitches at its existing
// post-qualification seams. This is a local source regression, not Linux proof.
func TestRecoveryNaturalSlotSwitchInvalidatesOldAdvisoryHistory(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	lease := &refreshLeaseFixture{}
	r.c.client = lease
	before := r.switches
	r.status = [2]string{"down", "up"}
	for _, at := range []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second} {
		r.now = at
		if err := r.c.RefreshIPsecRecovery(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if r.switches != before {
		t.Fatal("observation mutated route")
	}
	r.now = 16 * time.Second
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	entries, err := r.c.journal.Entries()
	if err != nil || len(entries) != 1 || r.switches != before+1 || selectedRuntimeSlot(entries[0]) != 2 || entries[0].Recovery.Sequence != 1 {
		t.Fatal("ordinary Apply did not consume genuine held evidence", err, r.switches, entries)
	}
	id := entries[0].Allocation.ConnectionID
	active := r.c.active[id]
	if !reflect.DeepEqual(active.Entry, entries[0]) || active.Authority == nil {
		t.Fatal("new selected entry/authority was not installed")
	}
	if h := r.c.recoveryHistory[id]; h != nil && h.seen && h.current != selectedRuntimeSlot(entries[0]) {
		t.Errorf("successful slot2 commit retained old-slot advisory history: history.current=%d journal.selected=%d", h.current, selectedRuntimeSlot(entries[0]))
	}
	// The unchanged heartbeat discards mismatched advice before any CP/native
	// sampling; it must not withdraw this independently installed active owner.
	requests, events, switches := len(lease.requests), len(r.events), r.switches
	_, sequence, err := r.c.journal.guardTemplates()
	if err != nil {
		t.Fatal(err)
	}
	r.now = 17 * time.Second
	reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	after, readErr := r.c.journal.Entries()
	_, afterSequence, guardErr := r.c.journal.guardTemplates()
	if err != nil || readErr != nil || guardErr != nil || len(reports) != 0 || r.c.recoveryHistory[id] != nil || !reflect.DeepEqual(entries, after) || sequence != afterSequence || !reflect.DeepEqual(active, r.c.active[id]) || len(lease.requests) != requests || len(r.events) != events || r.switches != switches {
		t.Fatal("advisory invalidation changed authority/native/journal duty", err, readErr, guardErr, len(reports))
	}
	t.Log("natural successful slot1-to-slot2 Apply; stale advice heartbeat clearing preserves current owner/lease/route/journal and requests no new nonce")
}
