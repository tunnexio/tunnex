package ipsec

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRuntimeMaterialJournalDiagnosticStagesClosedAndPrivate(t *testing.T) {
	stages := []string{"material_entry", "material_fqdn_withdraw", "material_fqdn_current", "material_bgp_qualification", "journal_handoff_refused", "journal_save_refused", "journal_boot_refused", "journal_restoration_refused", "journal_cleanup_phase_refused", "journal_retained_phase_refused", "journal_mismatch_lineage", "journal_mismatch_contract", "journal_mismatch_cleanup", "journal_mismatch_allocation", "journal_mismatch_engines", "journal_mismatch_history", "journal_mismatch_other"}
	id := uuid.New()
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			var events []RuntimeDiagnostic
			cb := func(d RuntimeDiagnostic) { events = append(events, d) }
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			emitRuntimeDiagnostic(cb, ctx, "apply", stage, id, time.Now(), true)
			if len(events) != 1 || events[0].Operation != "apply" || events[0].Stage != stage || events[0].ConnectionID != id || events[0].ContextState != "canceled" || !events[0].Refused || events[0].ElapsedMillis < 0 {
				t.Fatal("fixed event changed", events)
			}
			b, err := json.Marshal(events[0])
			if err != nil {
				t.Fatal(err)
			}
			var projected map[string]any
			if json.Unmarshal(b, &projected) != nil || len(projected) != 6 {
				t.Fatal("diagnostic schema widened")
			}
			for _, secret := range []string{"PSK", "Material", "PolicyHash", "Grant", "Password", "raw_error"} {
				if strings.Contains(string(b), secret) {
					t.Fatal("private field exported")
				}
			}
			emitRuntimeDiagnostic(cb, ctx, "apply", stage+"/raw_error_secret", id, time.Now(), true)
			emitRuntimeDiagnostic(cb, ctx, "unknown", stage, id, time.Now(), true)
			if len(events) != 1 {
				t.Fatal("unclassified event exported")
			}
			emitRuntimeDiagnostic(nil, ctx, "apply", stage, id, time.Now(), true)
		})
	}
}
