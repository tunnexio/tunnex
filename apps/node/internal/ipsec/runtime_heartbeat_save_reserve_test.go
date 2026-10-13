package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"reflect"
	"testing"
	"time"
)

// This is a finite-clock causal counterexample, not a measurement or assertion
// of the live journal_sequence leaf. A successful telemetry Save may consume
// the original owner's reserve; its exact three-set withdrawal is local, but
// the maintenance caller currently converts the returned error to global deny.
func TestHeartbeatSuccessfulSaveReserveCrossingScope(t *testing.T) {
	for _, scenario := range []string{"inner_local_withdrawal", "maintenance_preserves_unrelated", "canceled_after_withdrawal", "qualification_after_withdrawal", "daemon_after_withdrawal"} {
		t.Run(scenario, func(t *testing.T) {
			outer := scenario != "inner_local_withdrawal"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			daemonAlive := true
			r := newRenewalCycleRigInput(t, true)
			r.c.config.DaemonAlive = func() bool { return daemonAlive }
			materials := maintenanceMaterials(r)
			target := materials[len(materials)-1].Manifest.ConnectionID
			before := r.c.active[target]
			if len(r.c.active) != 5 || before.Entry.ContractVersion != 2 {
				t.Fatal("real five-owner static fixture required")
			}
			oldDeadline := before.Authority.deadline
			*r.now = 3 * time.Second
			// The authority uses its own original elapsed-clock seam. Its genuine
			// accepted deadline is unchanged, and all original rendered members remain
			// finite. This models a nearly exhausted CP reserve independently of the
			// kernel's currently positive observation, not any measured cloud age.
			offset := oldDeadline - *r.now - 6600*time.Millisecond
			before.Authority.elapsed = func() time.Duration { return *r.now + offset }
			original := map[uuid.UUID]runtimeActive{}
			nativeBefore := map[string]time.Duration{}
			for id, a := range r.c.active {
				original[id] = a
				if id != target && r.c.recoveryHistory[id] != nil {
					r.c.recoveryHistory[id].lastNow = *r.now
				}
			}
			for name, end := range r.installed {
				nativeBefore[name] = end
			}
			names := map[string]bool{guardLeaseName(target): true, guardReplyLeaseName(target): true, guardSALeaseName(target): true}
			withdrawn := 0
			r.c.guard.apply = func(_ context.Context, raw []byte) error {
				var doc struct {
					NFTables []map[string]struct {
						Set map[string]any `json:"set"`
					} `json:"nftables"`
				}
				if json.Unmarshal(raw, &doc) != nil || len(doc.NFTables) != 3 {
					t.Fatal("exact withdrawal required")
				}
				seen := map[string]bool{}
				for _, obj := range doc.NFTables {
					flush, ok := obj["flush"]
					if !ok {
						t.Fatal("non-flush mutation")
					}
					n, ok := flush.Set["name"].(string)
					if !ok || !names[n] || seen[n] || flush.Set["family"] != "inet" || flush.Set["table"] != "tunnex_ipsec" || len(flush.Set) != 3 {
						t.Fatal("foreign or additional withdrawal")
					}
					seen[n] = true
					r.installed[n] = *r.now
				}
				withdrawn++
				switch scenario {
				case "canceled_after_withdrawal":
					cancel()
				case "qualification_after_withdrawal":
					r.c.qualification.invalid = true
				case "daemon_after_withdrawal":
					daemonAlive = false
				}
				return nil
			}
			saved := 0
			syncDir := r.c.journal.syncDirectory
			r.c.journal.syncDirectory = func() error {
				if saved == 0 {
					saved++
					if _, err := before.Authority.RemainingForApply(before.Identity, 5*time.Second); err != nil {
						t.Fatal("reserve already crossed before successful Save", err)
					}
					r.charge("successful_telemetry_save", 500*time.Millisecond)
				}
				return syncDir()
			}
			var events []RuntimeDiagnostic
			r.c.config.Diagnostic = func(e RuntimeDiagnostic) { events = append(events, e) }
			started := *r.now
			r.phase = "maintenance"
			var err error
			if outer {
				results, e := r.c.maintainIPsecRuntimeRecoveryObserved(ctx, materials, maintenanceAuthority(r), func() bool { return true }, nil, func(context.Context, RuntimeRecoveryHeartbeat) error {
					t.Fatal("positive publication after reserve crossing")
					return nil
				})
				err = e
				if len(results) != 0 {
					t.Fatal("ACK escaped failed pulse")
				}
			} else {
				r.c.mu.Lock()
				_, err = r.c.refreshIPsecActiveRecoveryLocked(ctx, map[uuid.UUID]bool{}, true, time.Now())
				r.c.mu.Unlock()
			}
			r.phase = ""
			remaining := oldDeadline - before.Authority.elapsed()
			if err == nil || saved != 1 || withdrawn != 1 || before.Authority.deadline != oldDeadline || remaining <= 0 {
				t.Fatal("specific successful-Save floor-crossing seam not reached", err, saved, withdrawn, remaining)
			}
			exactStage := false
			for _, e := range events {
				if e.Operation == "heartbeat" && e.Stage == "journal_sequence" && e.ConnectionID == target && e.Refused {
					exactStage = true
				}
			}
			if !exactStage {
				t.Fatal("expected broad live-compatible stage absent", events)
			}
			expectLocal := scenario == "inner_local_withdrawal" || scenario == "maintenance_preserves_unrelated"
			if expectLocal {
				if len(r.c.active) != 4 {
					t.Fatal("classified local withdrawal must preserve other four owners", len(r.c.active))
				}
				for id, a := range original {
					if id != target && !reflect.DeepEqual(a, r.c.active[id]) {
						t.Fatal("healthy authority/entry changed")
					}
				}
				for name, end := range nativeBefore {
					if !names[name] && r.installed[name] != end {
						t.Fatal("unrelated native deadline changed")
					}
				}
			} else if len(r.c.active) != 0 {
				t.Fatal("lost context/qualification/daemon must retain global refusal", len(r.c.active))
			}

			t.Logf("mode_outer=%t model_elapsed=%s old_remaining=%s telemetry_Save_succeeded=true target_only_withdrawals=%d active_after=%d live_leaf_not_proven=true", outer, *r.now-started, remaining, withdrawn, len(r.c.active))
		})
	}
}
