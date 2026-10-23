package ipsec

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestPriorityPrepareDiagnosticExactBoundary(t *testing.T) {
	for _, kind := range []string{"owner", "stale_journal", "process_journal", "routes_journal", "recovery_journal", "missing_journal", "valid"} {
		t.Run(kind, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			id := r.target
			if kind == "process_journal" || kind == "routes_journal" || kind == "recovery_journal" {
				id = uuid.Nil
				for candidate, active := range r.c.active {
					if kind == "process_journal" && active.Entry.BGPProcess != nil || kind == "routes_journal" && active.Entry.BGPRoutes != nil || kind == "recovery_journal" && active.Entry.Recovery != nil {
						id = candidate
						break
					}
				}
				if id == uuid.Nil {
					t.Fatal("missing actual journal duty in fixture")
				}
			}
			a := cloneMaintenanceActive(r.c.active[id])
			want := ""
			switch kind {
			case "owner":
				a.Delivery.OwnershipDigest = "bad"
				r.c.active[id] = a
				want = "maintenance_priority_owner"
			case "stale_journal":
				a.Entry.SiteID = uuid.New()
				r.c.active[id] = a
				want = "maintenance_priority_journal_binding"
			case "process_journal":
				a.Entry.BGPProcess.Generation++
				r.c.active[id] = a
				want = "maintenance_priority_journal_process"
			case "routes_journal":
				a.Entry.BGPRoutes.Sequence++
				r.c.active[id] = a
				want = "maintenance_priority_journal_routes"
			case "recovery_journal":
				a.Entry.Recovery.Sequence++
				r.c.active[id] = a
				want = "maintenance_priority_journal_recovery"
			case "missing_journal":
				// A process-local delivery absent from the trusted journal cannot
				// be retained. Leave the trusted on-disk journal intact.
				a.Delivery.ID = uuid.New()
				a.Entry.DeliveryID = a.Delivery.ID
				a.Identity.DeliveryID = a.Delivery.ID
				r.c.active[id] = a
				want = "maintenance_priority_journal_count"
			}
			var events []RuntimeDiagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
			leasesBefore := r.leases
			r.phase = "maintenance"
			err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			if kind == "valid" {
				if err != nil || len(r.c.active) != 5 || r.leases-leasesBefore != 5 || !allPriorityMembersLive(r) {
					t.Fatal("valid priority renewal changed", err)
				}
				for _, d := range events {
					if d.Operation == "maintenance" && d.Refused {
						t.Fatal("valid renewal reported refusal", d)
					}
				}
				return
			}
			if !errors.Is(err, ErrRuntimeController) || len(r.c.active) != 0 || r.leases != leasesBefore {
				t.Fatal("invalid priority preparation did not preserve fail-closed behavior", err)
			}
			found := 0
			for _, d := range events {
				if d.Operation == "maintenance" {
					found++
					if !d.Refused || d.Stage != want || d.ConnectionID != id {
						t.Fatal("priority failure inherited unrelated stage/owner", d)
					}
				}
			}
			if found != 1 {
				t.Fatal("missing exact outer diagnostic", found)
			}
		})
	}
}

func TestMaintenancePrepareDiagnosticCallbackBoundary(t *testing.T) {
	for _, callbackError := range []bool{true, false} {
		name, want := "callback_error", "maintenance_prepare"
		if !callbackError {
			name, want = "count_mismatch", "maintenance_prepare_count"
		}
		t.Run(name, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			var events []RuntimeDiagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
			prepare := func(string, []RuntimeJournalEntry, *string, *uuid.UUID) ([]maintenanceItem, error) {
				if callbackError {
					return nil, ErrRuntimeController
				}
				return nil, nil
			}
			results, err := r.c.maintainIPsecRuntimeItems(context.Background(), 1, prepare, maintenanceAuthority(r), func() bool { return true }, nil, nil, true)
			if !errors.Is(err, ErrRuntimeController) || len(results) != 0 || len(r.c.active) != 0 {
				t.Fatal("prepare failure changed behavior", err)
			}
			found := 0
			for _, d := range events {
				if d.Operation == "maintenance" {
					found++
					if d.Stage != want || d.ConnectionID != uuid.Nil || !d.Refused {
						t.Fatal("callback/count failure mislabeled", d)
					}
				}
			}
			if found != 1 {
				t.Fatal("missing callback boundary event")
			}
		})
	}
}

func TestPriorityPrepareDiagnosticClosedVocabulary(t *testing.T) {
	for _, stage := range []string{"maintenance_prepare", "maintenance_prepare_count", "maintenance_priority_owner", "maintenance_priority_journal_binding", "maintenance_priority_journal_process", "maintenance_priority_journal_routes", "maintenance_priority_journal_recovery", "maintenance_priority_journal_count", "maintenance_priority_fqdn_current"} {
		if !validRuntimeDiagnostic("maintenance", stage) {
			t.Fatal("missing fixed stage", stage)
		}
		if validRuntimeDiagnostic("apply", stage) || validRuntimeDiagnostic("maintenance_pending_fqdn", stage) || validRuntimeDiagnostic("maintenance", stage+":untrusted-detail") {
			t.Fatal("open or cross-operation stage accepted", stage)
		}
	}
}
