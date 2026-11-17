package ipsec

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func inFundedCadencePulse() bool {
	var pcs [32]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".(*maintenancePulseDeferral).pulseBeforeAssembly") {
			return true
		}
		if !more {
			return false
		}
	}
}

func multiOwnerCadenceRig(t *testing.T) *renewalCycleRig {
	t.Helper()
	ids := pulseDeferralIDs()
	return newRenewalCycleRigWithIDs(t, true, ids, func(t *testing.T, c *RuntimeController, entries []RuntimeJournalEntry, materials []RuntimeMaterial) ([]RuntimeJournalEntry, []RuntimeMaterial) {
		keep := map[uuid.UUID]bool{ids[0]: true, ids[3]: true, ids[4]: true}
		var selectedEntries []RuntimeJournalEntry
		var selectedMaterials []RuntimeMaterial
		for _, e := range entries {
			if keep[e.Allocation.ConnectionID] {
				selectedEntries = append(selectedEntries, e)
			} else {
				delete(c.active, e.Allocation.ConnectionID)
				delete(c.bgpProcesses, e.DeliveryID)
			}
		}
		for _, m := range materials {
			if keep[m.Manifest.ConnectionID] {
				selectedMaterials = append(selectedMaterials, m)
			}
		}
		return selectedEntries, selectedMaterials
	})
}

// The ordinary maintenance entry owns all sequencing, deferral and publication.
// Two real static owners and one BGP owner incur bounded native reads. The
// 1.6-second sample cost alone is insufficient: without an earlier checkpoint,
// three serial preproofs let the other returned report cross ten seconds while
// the oldest owner's fresh sample is being published.
func TestMaintenanceMultiOwnerCadence(t *testing.T) {
	for _, extra := range []time.Duration{0, 2200 * time.Millisecond, 11 * time.Second} {
		t.Run(extra.String(), func(t *testing.T) {
			r := multiOwnerCadenceRig(t)
			r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
				cost := 800 * time.Millisecond
				if pulseDeferralInCall("installActiveCandidatesFQDN") {
					cost = 1150 * time.Millisecond
				}
				r.charge("native_status", cost)
				return [2]string{"up", "up"}
			}
			proofs, earlyReports, publications, commits := 0, 0, 0, 0
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				if pulseDeferralInCall("installActiveCandidatesFQDN") && !pulseDeferralInCall("refreshIPsecActiveRecoveryLockedQualified") {
					proofs++
					r.charge("serial_preproof", extra)
				}
				return prove(ctx, e, env)
			}
			client := r.c.client
			r.c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
				if r.phase == "maintenance" {
					r.charge("cp_roundtrip", 100*time.Millisecond)
				}
				return client.RenewIPsecLease(ctx, id, q)
			})
			allowed := map[uuid.UUID]bool{}
			for id := range r.c.active {
				allowed[id] = true
			}
			publish := func(context.Context, RuntimeRecoveryHeartbeat) error { return nil }
			r.charge("initial_due", time.Second)
			for i := 0; i < 2; i++ {
				if err := r.c.refreshMaintenanceActiveRecovery(context.Background(), allowed, publish); err != nil {
					t.Fatal(err)
				}
			}
			originalDeadlines := map[*PermitLeaseAuthority]time.Duration{}
			originalClocks := map[uuid.UUID]runtimeRecoveryReportClock{}
			for id, a := range r.c.active {
				originalDeadlines[a.Authority] = a.Authority.deadline
				if a.Entry.ContractVersion == 2 {
					originalClocks[id] = r.c.recoveryReportClocks[id]
				}
			}
			var diagnostics []RuntimeDiagnostic
			r.c.config.Diagnostic = func(e RuntimeDiagnostic) {
				if e.Refused {
					diagnostics = append(diagnostics, e)
				}
			}
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				commits++
				return replace(ctx, in)
			}
			publish = func(ctx context.Context, out RuntimeRecoveryHeartbeat) error {
				if ctx.Err() != nil {
					t.Fatal("expected active native sample context")
				}
				// This private producer is called only when deferral.used is true.
				// No test writes a clock or forces the deferral into that state.
				if inFundedCadencePulse() {
					earlyReports++
					if extra == 2200*time.Millisecond && proofs >= 3 && earlyReports == 1 {
						t.Fatal("first funded pulse waited for all serial preproofs")
					}
				}
				publications++
				for id, a := range r.c.active {
					if id == out.ConnectionID || a.Entry.ContractVersion != 2 {
						continue
					}
					clock, known := r.c.recoveryReportClock(a)
					if !known || *r.now-clock.returned > 10*time.Second {
						t.Fatal("stale other owner passed publication")
					}
				}
				return nil
			}
			r.phase = "maintenance"
			result, err := r.c.maintainIPsecRuntimeRecoveryObserved(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { return nil }, publish)
			for authority, deadline := range originalDeadlines {
				if authority.deadline != deadline {
					t.Fatal("original authority deadline changed")
				}
			}
			t.Logf("extra=%s result=%d commits=%d proofs=%d funded_reports=%d publications=%d err=%v diagnostics=%+v", extra, len(result), commits, proofs, earlyReports, publications, err, diagnostics)
			if extra == 11*time.Second {
				if err == nil || len(result) != 0 || len(r.c.active) != 0 {
					t.Fatal("unbounded native read retained or acknowledged authority")
				}
				return
			}
			if err != nil || len(result) != 3 || len(r.c.active) != 3 || commits != 1 || earlyReports < 2 {
				t.Fatal("normal three-owner renewal lost continuity", err)
			}
			for id, clock := range originalClocks {
				current := r.c.recoveryReportClocks[id]
				if current.sequence <= clock.sequence || current.returned <= clock.returned {
					t.Fatal("real returned report did not advance")
				}
			}
			for _, a := range r.c.active {
				if err := r.c.maintenanceGuard(context.Background(), a.Entry); err != nil {
					t.Fatal("committed combined guard lost exact owner proof", err)
				}
			}
		})
	}
}

func TestMaintenanceReportDiagnosticClosedReasons(t *testing.T) {
	var events []RuntimeDiagnostic
	c := &RuntimeController{config: RuntimeControllerConfig{Diagnostic: func(e RuntimeDiagnostic) { events = append(events, e) }}}
	for _, operation := range []string{"maintenance_report_freshness", "maintenance_report_commit"} {
		for _, hostile := range []string{"password=private", "peer=192.0.2.1", "other_report_age\nprivate", "future_unreviewed_reason"} {
			c.emitRuntimeDiagnostic(context.Background(), operation, hostile, uuid.Nil, time.Now(), true)
		}
	}
	if len(events) != 0 {
		t.Fatal("arbitrary diagnostic text escaped fixed reason whitelist")
	}
	c.emitRuntimeDiagnostic(context.Background(), "maintenance_report_freshness", "other_report_age", uuid.Nil, time.Now(), true)
	c.emitRuntimeDiagnostic(context.Background(), "maintenance_report_commit", "candidate", uuid.Nil, time.Now(), true)
	if len(events) != 2 || !events[0].Refused || !events[1].Refused {
		t.Fatal("closed refusal stages omitted")
	}
}
