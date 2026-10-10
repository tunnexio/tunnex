package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"testing"
)

func TestCleanupDiagnosticValidationAndJournalRefusal(t *testing.T) {
	for _, poison := range []bool{false, true} {
		t.Run(map[bool]string{false: "validation", true: "journal"}[poison], func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			cleanup := RuntimeCleanup{RuntimeDelivery: f.material.RuntimeDelivery, RetainGuard: true, Lineage: []RuntimeDelivery{f.material.RuntimeDelivery}}
			cleanup.ID, cleanup.Kind = uuid.New(), "cleanup"
			cleanup.DesiredRevision = f.material.DesiredRevision + 1
			cleanup.CoversDeliveryRevision = f.material.DesiredRevision
			raw, _ := json.Marshal(cleanup.Lineage)
			cleanup.OwnershipDigest = stringDigest(raw)
			want := "cleanup_validation"
			if poison {
				f.c.journal.mu.Lock()
				f.c.journal.poisoned = true
				f.c.journal.mu.Unlock()
				want = "cleanup_journal_read"
			} else {
				cleanup.RetainGuard = false
			}
			var events []RuntimeDiagnostic
			f.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
			ack, err := f.c.Cleanup(context.Background(), cleanup)
			if err != ErrRuntimeController || ack != (RuntimeAcknowledgement{}) {
				t.Fatal("diagnostic altered refusal")
			}
			if len(events) != 1 || events[0].Operation != "cleanup" || events[0].Stage != want || !events[0].Refused || events[0].ConnectionID != cleanup.Manifest.ConnectionID {
				t.Fatalf("incorrect bounded stage: %+v", events)
			}
			if poison {
				if _, err := f.prove(context.Background()); err == nil {
					t.Fatal("cleanup retained DNS authority")
				}
			}
		})
	}
}
func TestCleanupDiagnosticFixedLabels(t *testing.T) {
	for _, stage := range []string{"cleanup_validation", "cleanup_journal_read", "cleanup_lineage", "cleanup_journal_commit", "cleanup_covered_lineage", "cleanup_install_active", "cleanup_environment", "cleanup_reset_receipt", "cleanup_prove_reset_absent", "cleanup_prove_absent", "cleanup_bgp_duties", "cleanup_remove_tunnel", "cleanup_kernel_remove", "cleanup_environment_drain", "cleanup_retained_guard_commit"} {
		if !validRuntimeDiagnostic("cleanup", stage) {
			t.Fatal("fixed stage refused", stage)
		}
	}
	if validRuntimeDiagnostic("cleanup", "cleanup_error=private") {
		t.Fatal("unknown label accepted")
	}
}
