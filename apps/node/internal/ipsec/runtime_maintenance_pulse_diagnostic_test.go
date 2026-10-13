package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"testing"
	"time"
)

// This is a controlled virtual-clock safety/diagnostic reproduction. It is not
// a measurement of the live 1107ms invocation or its unexported old deadline.
func TestMaintenancePulseShortPublishCrossesOldReserve(t *testing.T) {
	r, target := maintainedMissingStandby(t, 2)
	r.target = target
	before := r.c.active[target]
	oldDeadline := before.Authority.deadline
	*r.now = oldDeadline - 7*time.Second
	if r.installed[guardLeaseName(target)] <= *r.now {
		t.Fatal("native permit must be live at the seam")
	}
	for id, h := range r.c.recoveryHistory {
		if id != target {
			h.lastNow = *r.now
		}
	}
	var events []RuntimeDiagnostic
	r.c.config.Diagnostic = func(e RuntimeDiagnostic) { events = append(events, e) }
	commits, callbacks := 0, 0
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		for _, g := range in.Connections {
			if !g.PrefixOnly {
				commits++
			}
		}
		return replace(ctx, in)
	}
	started := *r.now
	var published RuntimeRecoveryHeartbeat
	r.phase = "maintenance"
	results, err := r.c.maintainIPsecRuntimeRecoveryObserved(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, nil, func(ctx context.Context, out RuntimeRecoveryHeartbeat) error {
		callbacks++
		published = out
		if out.ConnectionID != target || out.Report.ActiveSlot == nil || *out.Report.ActiveSlot != 2 {
			t.Fatal("wrong fresh sampled owner")
		}
		if ctx.Err() != nil {
			t.Fatal("child context expired before callback")
		}
		if _, e := before.Authority.RemainingForApply(before.Identity, 5*time.Second); e != nil {
			t.Fatal("must cross only after publish", e)
		}
		r.charge("short_publish", time.Second)
		if ctx.Err() != nil {
			t.Fatal("one-second virtual cost cannot cause child deadline")
		}
		return nil
	})
	r.phase = ""
	if err == nil || len(results) != 0 || callbacks != 1 || commits != 0 || len(r.c.active) != 0 {
		t.Fatalf("original global fail-closed path missing: err=%v reports=%d callbacks=%d commits=%d active=%d events=%v model_elapsed=%s old_remaining=%s", err, len(results), callbacks, commits, len(r.c.active), events, *r.now-started, oldDeadline-*r.now)
	}
	if before.Authority.deadline != oldDeadline || oldDeadline-*r.now <= 0 {
		t.Fatal("original deadline must remain unextended and still unexpired")
	}
	if _, e := before.Authority.RemainingForApply(before.Identity, 5*time.Second); e == nil {
		t.Fatal("old five-second reserve must now refuse")
	}
	if *r.now-started >= 5*time.Second || *r.now-started != 2150*time.Millisecond {
		t.Fatal("must be short virtual pulse, not 5s timeout", *r.now-started)
	}
	for _, e := range events {
		if e.Operation == "heartbeat" && e.Refused {
			t.Fatal("inner heartbeat succeeded; no inner refusal expected", e)
		}
	}
	if _, known := r.c.recoveryReportClocks[target]; known {
		t.Fatal("failed post-publish reserve stamped telemetry scheduling clock")
	}
	precise := false
	for _, e := range events {
		if e.Operation == "maintenance_pulse" {
			if e.Stage != "prior_reserve" || e.ConnectionID != target || e.ContextState != "active" || !e.Refused {
				t.Fatal("incorrect microstage", e)
			}
			precise = true
		}
	}
	t.Logf("expected safety reproduced; model_elapsed=%s original_remaining=%s published_sequence=%d no_inner_heartbeat_refusal=true global_active=0", *r.now-started, oldDeadline-*r.now, *published.Report.SelectionSequence)
	if !precise {
		t.Fatal("precise post-publish microstage absent")
	}
}

func TestMaintenancePulseGlobalSequenceKeepsBothOwnerClocks(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	old := map[uuid.UUID]runtimeActive{}
	allowed := map[uuid.UUID]bool{}
	for id, a := range r.c.active {
		old[id] = a
		if a.Entry.ContractVersion == 2 {
			allowed[id] = true
		}
	}
	if len(old) != 5 || len(allowed) != 2 {
		t.Fatal("real five-owner/two-static fixture required")
	}
	r.charge("due", 3*time.Second)
	published := map[uuid.UUID]RuntimeRecoveryHeartbeat{}
	run := func() {
		t.Helper()
		r.c.mu.Lock()
		e := r.c.refreshMaintenanceActiveRecovery(context.Background(), allowed, func(ctx context.Context, out RuntimeRecoveryHeartbeat) error {
			if ctx.Err() != nil || out.Report.SelectionSequence == nil {
				t.Fatal("invalid publication")
			}
			published[out.ConnectionID] = out
			return nil
		})
		r.c.mu.Unlock()
		if e != nil {
			t.Fatal("unchanged owner pulse failed", e)
		}
	}
	run()
	if len(published) != 1 {
		t.Fatal("one bounded static owner per pulse")
	}
	firstID := uuid.Nil
	for id := range published {
		firstID = id
	}
	first := r.c.recoveryReportClocks[firstID]
	run()
	if len(published) != 2 || len(r.c.recoveryReportClocks) != 2 {
		t.Fatal("both independent static owners not stamped")
	}
	if r.c.recoveryReportClocks[firstID] != first {
		t.Fatal("second owner's global sequence changed first owner's clock")
	}
	for id, out := range published {
		clock, known := r.c.recoveryReportClock(r.c.active[id])
		if !known || clock.sequence != *out.Report.SelectionSequence || clock.sequence != r.c.recoveryStatusSequence[out.Delivery.ID] {
			t.Fatal("clock incorrectly depends on current global sequence")
		}
	}
	if len(r.c.active) != 5 {
		t.Fatal("unrelated owner withdrawn")
	}
	for id, a := range old {
		if !reflect.DeepEqual(a, r.c.active[id]) || a.Authority.deadline != r.c.active[id].Authority.deadline {
			t.Fatal("telemetry changed owner authority")
		}
	}
	t.Log("two global journal Save operations preserve each owner's exact independent sequence and clock")
}

func TestMaintenancePulseHistoryFailureIdentifiesOwnerAndPredicate(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	allowed := map[uuid.UUID]bool{}
	invalid := uuid.Nil
	for id, a := range r.c.active {
		if a.Entry.ContractVersion == 2 {
			allowed[id] = true
			invalid = id
			r.c.recoveryHistory[id].epoch.Namespace = "net:[4026539999]"
			break
		}
	}
	var events []RuntimeDiagnostic
	r.c.config.Diagnostic = func(e RuntimeDiagnostic) { events = append(events, e) }
	calls := 0
	r.c.mu.Lock()
	err := r.c.refreshMaintenanceActiveRecovery(context.Background(), allowed, func(context.Context, RuntimeRecoveryHeartbeat) error { calls++; return nil })
	r.c.mu.Unlock()
	if err == nil || calls != 0 || len(events) != 1 || events[0].Operation != "maintenance_pulse" || events[0].Stage != "history_epoch" || events[0].ConnectionID != invalid || events[0].ContextState != "active" {
		t.Fatal("history refusal must identify the failing owner and predicate", err, events, calls)
	}
	if len(r.c.active) != 5 {
		t.Fatal("helper must preserve original caller-owned refusal semantics")
	}
	for _, s := range []string{"input", "history", "history_entry", "history_epoch", "history_selection", "history_clock", "clock", "sample", "report_binding", "publish", "final_binding", "prior_reserve", "remember"} {
		if !validRuntimeDiagnostic("maintenance_pulse", s) {
			t.Fatal("fixed microstage absent", s)
		}
	}
	if validRuntimeDiagnostic("maintenance_pulse", "lease_nonce=private") {
		t.Fatal("dynamic stage allowed")
	}
}
