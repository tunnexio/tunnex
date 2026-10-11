package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"testing"
	"time"
)

func TestMaintenanceDiagnosticScopedWithdrawalParity(t *testing.T) {
	type observation struct {
		Trace                    []int
		RPCs                     int
		Results                  int
		ClassicDenied, HAPresent bool
	}
	run := func(enabled bool) observation {
		r := newRenewalCycleRigInput(t, true, gcpMaintenanceRestoredClassic)
		id := r.entries[1].Allocation.ConnectionID
		trace := []int{}
		oldProve := r.c.prove
		failed := false
		r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
			kind := 3
			if e.Allocation.ConnectionID == id {
				kind = 4
			}
			trace = append(trace, kind)
			if kind == 4 && !failed {
				failed = true
				return ErrRuntimeController
			}
			return oldProve(ctx, e, env)
		}
		events := []RuntimeDiagnostic{}
		if enabled {
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
		}
		r.phase = "maintenance"
		results, err := r.c.maintainIPsecRuntime(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		if enabled {
			native, scoped, finished := 0, 0, 0
			for _, d := range events {
				if d.Operation == "maintenance_current" && d.Stage == "maintenance_current_native" && d.Refused && d.ConnectionID == id {
					native++
				}
				if d.Operation == "maintenance" && d.Stage == "maintenance_eligibility_proof" && d.Refused && d.ConnectionID == id {
					scoped++
				}
				if d.Operation == "maintenance" && !d.Refused {
					finished++
				}
			}
			if native != 1 || scoped != 1 || finished != 2 {
				t.Fatalf("native=%d scoped=%d completed=%d", native, scoped, finished)
			}
		}
		_, ha := r.c.active[r.entries[0].Allocation.ConnectionID]
		return observation{trace, r.leases, len(results), r.applicationDenied[id], ha}
	}
	off, on := run(false), run(true)
	if !reflect.DeepEqual(off, on) || on.Results != 1 || !on.ClassicDenied || !on.HAPresent {
		t.Fatalf("without=%+v with=%+v", off, on)
	}
}

func TestMaintenanceDiagnosticCurrentOrderAndError(t *testing.T) {
	for _, mode := range []string{"native", "guard", "success"} {
		t.Run(mode, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true, gcpMaintenanceRestoredClassic)
			old := r.c.active[r.entries[1].Allocation.ConnectionID]
			calls := []string{}
			original := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				calls = append(calls, "native")
				if mode == "native" {
					return ErrRuntimeController
				}
				return original(ctx, e, env)
			}
			read := r.c.guard.reader.run
			r.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
				calls = append(calls, "guard")
				if mode == "guard" {
					return nil, ErrGuardRead
				}
				return read(ctx, args...)
			}
			events := []RuntimeDiagnostic{}
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
				if d.Operation == "maintenance_current" {
					events = append(events, d)
				}
			}
			err := r.c.maintenanceCurrent(context.Background(), old, func() bool { return true })
			stage := "maintenance_current_authority_after"
			if mode == "native" {
				stage = "maintenance_current_native"
				if !reflect.DeepEqual(calls, []string{"native"}) {
					t.Fatal(calls)
				}
			}
			if mode == "guard" {
				stage = "maintenance_current_guard"
			}
			if mode != "native" && !reflect.DeepEqual(calls, []string{"native", "guard"}) {
				t.Fatal(calls)
			}
			if mode == "success" && err != nil || mode != "success" && err != ErrRuntimeController {
				t.Fatal(err)
			}
			if len(events) != 1 || events[0].Stage != stage || events[0].Refused != (err != nil) || events[0].ConnectionID != old.Entry.Allocation.ConnectionID {
				t.Fatal(events)
			}
		})
	}
}

func TestMaintenanceDiagnosticGlobalPublishFailure(t *testing.T) {
	r := newRenewalCycleRigInput(t, true, gcpMaintenanceRestoredClassic)
	events := []RuntimeDiagnostic{}
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
	r.phase = "maintenance"
	_, err := r.c.maintainIPsecRuntimeObserved(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { return ErrRuntimeController })
	if err != ErrRuntimeController || len(r.c.active) != 0 {
		t.Fatal("publish failure must preserve global refusal", err, len(r.c.active))
	}
	last := events[len(events)-1]
	if last.Operation != "maintenance" || last.Stage != "maintenance_publish" || !last.Refused {
		t.Fatal(last)
	}
}

func TestMaintenanceDiagnosticClosedVocabulary(t *testing.T) {
	for _, op := range []string{"maintenance", "maintenance_current"} {
		for _, bad := range []string{"input", "material_contract", "secret-value", "maintenance_unknown"} {
			if validRuntimeDiagnostic(op, bad) {
				t.Fatal(op, bad)
			}
		}
	}
	if validRuntimeDiagnostic("maintenance", "maintenance_current_native") || validRuntimeDiagnostic("maintenance_current", "maintenance_publish") {
		t.Fatal("cross-operation stage admitted")
	}
	var count int
	emitRuntimeDiagnostic(func(RuntimeDiagnostic) { count++ }, context.Background(), "maintenance", "secret-value", uuid.Nil, time.Now(), true)
	if count != 0 {
		t.Fatal("unknown emitted")
	}
}
