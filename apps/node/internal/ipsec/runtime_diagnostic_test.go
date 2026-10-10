package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRuntimeDiagnosticOnlyFixedLabelsAndContextClasses(t *testing.T) {
	var events []RuntimeDiagnostic
	c := &RuntimeController{config: RuntimeControllerConfig{Diagnostic: func(event RuntimeDiagnostic) { events = append(events, event) }}}
	id := uuid.New()
	started := time.Now().Add(-time.Second)
	c.emitRuntimeDiagnostic(context.Background(), "heartbeat", "native_status", id, started, false)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	c.emitRuntimeDiagnostic(canceled, "bgp_apply", "permit_lease", id, started, true)
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	c.emitRuntimeDiagnostic(expired, "validate", "combined_guard", uuid.Nil, started, true)
	c.emitRuntimeDiagnostic(context.Background(), "secret-material", "native_status", id, started, true)
	c.emitRuntimeDiagnostic(context.Background(), "apply", "password=forbidden", id, started, true)
	if len(events) != 3 || events[0].ContextState != "active" || events[1].ContextState != "canceled" || events[2].ContextState != "deadline" {
		t.Fatalf("unexpected fixed diagnostics: %+v", events)
	}
	for _, event := range events {
		if event.ElapsedMillis < 0 || !validRuntimeDiagnostic(event.Operation, event.Stage) {
			t.Fatal("unbounded diagnostic label")
		}
	}
}

func TestRuntimeDiagnosticHeartbeatPreservesAuthorityAndJournal(t *testing.T) {
	c, _, reads, denials := heartbeatBudgetRig(t)
	before, _ := c.journal.Entries()
	beforeAuthority := map[uuid.UUID]*PermitLeaseAuthority{}
	for id, active := range c.active {
		beforeAuthority[id] = active.Authority
	}
	var events []RuntimeDiagnostic
	c.config.Diagnostic = func(event RuntimeDiagnostic) { events = append(events, event) }
	reports, err := c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(reports) != 2 || len(reads) != 2 || *denials != 0 {
		t.Fatal("diagnostic changed healthy callback", err)
	}
	if len(events) != 3 {
		t.Fatalf("two observed targets plus completed drain: events=%d", len(events))
	}
	for _, event := range events {
		if event.Refused || event.ContextState != "active" || event.Operation != "heartbeat" {
			t.Fatalf("cleanup cancellation mislabeled as a refused observation: %+v", event)
		}
	}
	after, _ := c.journal.Entries()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("diagnostic wrote journal")
	}
	for id, authority := range beforeAuthority {
		if c.active[id].Authority != authority {
			t.Fatal("diagnostic replaced authority")
		}
	}
}

func TestRuntimeDiagnosticRefusalKeepsExistingCancellationWithdrawal(t *testing.T) {
	c, _, reads, denials := heartbeatBudgetRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observe := c.recoveryObserve
	c.recoveryObserve = func(ctx context.Context, entry RuntimeJournalEntry) [2]string {
		status := observe(ctx, entry)
		if len(reads) == 2 {
			cancel()
		}
		return status
	}
	var events []RuntimeDiagnostic
	c.config.Diagnostic = func(event RuntimeDiagnostic) { events = append(events, event) }
	reports, err := c.RefreshIPsecActiveRecovery(ctx)
	if err == nil || len(reports) != 0 || *denials != 1 || len(c.active) != 1 || len(events) != 2 || !events[1].Refused || events[1].ContextState != "canceled" {
		t.Fatalf("refusal semantics changed: err=%v reports=%d denials=%d active=%d events=%+v", err, len(reports), *denials, len(c.active), events)
	}
}

func TestRuntimeDiagnosticCapturesQuietNativeProofEviction(t *testing.T) {
	c, _, _, denials := heartbeatBudgetRig(t)
	before, _ := c.journal.Entries()
	expected := map[uuid.UUID]bool{}
	for id := range c.active {
		expected[id] = true
	}
	c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return ErrRuntimeController }
	var events []RuntimeDiagnostic
	c.config.Diagnostic = func(event RuntimeDiagnostic) { events = append(events, event) }
	if err := c.installActive(context.Background(), before); err != nil || len(c.active) != 0 || *denials != 1 {
		t.Fatal("native refusal changed", err)
	}
	failed := map[uuid.UUID]bool{}
	for _, event := range events {
		if event.Refused {
			if event.Operation != "install_active" || event.Stage != "entry_current_proof" || event.ContextState != "active" || !expected[event.ConnectionID] {
				t.Fatalf("wrong native eviction stage: %+v", event)
			}
			failed[event.ConnectionID] = true
		}
	}
	if len(failed) != 2 {
		t.Fatal("quiet native eviction not diagnosed")
	}
	after, _ := c.journal.Entries()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("diagnostic wrote journal")
	}
}
func TestRuntimeDiagnosticGuardForeignRefusalBeforeMutation(t *testing.T) {
	j, err := OpenRuntimeJournal(journalDir(t), guardFixture().OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	calls := 0
	var events []RuntimeDiagnostic
	reader := &GuardReader{namespace: func() (string, error) { return guardFixture().Namespace, nil }, interfaces: func() ([]GuardInterface, error) { return nil, nil }, run: func(context.Context, ...string) ([]byte, error) {
		return []byte(`{"nftables":[{"table":{"family":"inet","name":"tunnex_ipsec"}}]}`), nil
	}}
	g := &RuntimeGuard{journal: j, reader: reader, diagnostic: func(event RuntimeDiagnostic) { events = append(events, event) }, apply: func(context.Context, []byte) error { calls++; return nil }}
	if _, err = g.Replace(context.Background(), guardFixture()); err == nil || calls != 0 {
		t.Fatal("diagnostic changed foreign-table refusal")
	}
	if len(events) != 1 || events[0].Operation != "guard_replace" || events[0].Stage != "guard_prior_ownership" || !events[0].Refused || events[0].ContextState != "active" || events[0].ConnectionID != uuid.Nil {
		t.Fatalf("foreign refusal classification: %+v", events)
	}
}

func TestRuntimeDiagnosticChildDeadlineIsDistinctFromActiveParent(t *testing.T) {
	parent := context.Background()
	child, cancel := context.WithDeadline(parent, time.Now().Add(-time.Second))
	var events []RuntimeDiagnostic
	c := &RuntimeController{config: RuntimeControllerConfig{Diagnostic: func(event RuntimeDiagnostic) { events = append(events, event) }}}
	c.emitRuntimeDiagnostic(child, "install_active", "entry_current_proof", uuid.New(), time.Now(), true)
	cancel()
	c.emitRuntimeDiagnostic(parent, "install_active", "combined_guard_final_binding", uuid.Nil, time.Now(), false)
	if parent.Err() != nil || len(events) != 2 || events[0].ContextState != "deadline" || events[1].ContextState != "active" {
		t.Fatalf("child deadline confused with parent or cleanup cancellation: %+v", events)
	}
}
