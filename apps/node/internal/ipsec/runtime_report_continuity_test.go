package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestMaintenanceReportContinuityBoundedCommit(t *testing.T) {
	r, _ := maintainedMissingStandby(t, 2, pulseDeferralIDs()...)
	earliest := time.Duration(1<<63 - 1)
	for _, d := range r.installed {
		if d < earliest {
			earliest = d
		}
	}
	r.charge("forward_to_35s", earliest-*r.now-35*time.Second)
	start := *r.now
	var diagnostics []RuntimeDiagnostic
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
		if d.Refused {
			diagnostics = append(diagnostics, d)
			t.Logf("REFUSAL operation=%s stage=%s now=%s", d.Operation, d.Stage, *r.now-start)
		}
	}
	old := map[*PermitLeaseAuthority]time.Duration{}
	for _, a := range r.c.active {
		old[a.Authority] = a.Authority.deadline
	}
	callbacks, commits, assemblyCallbacks := 0, 0, 0
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		positive := false
		for _, g := range in.Connections {
			positive = positive || !g.PrefixOnly
		}
		if positive {
			r.charge("bounded_commit", 2250*time.Millisecond)
			for id, a := range r.c.active {
				if a.Entry.ContractVersion == 2 {
					clock, _ := r.c.recoveryReportClock(a)
					t.Logf("PRECOMMIT owner=%s age=%s remaining=%s now=%s callbacks=%d", id, *r.now-clock.returned, a.Authority.deadline-*r.now, *r.now-start, callbacks)
				}
			}
		}
		out, err := replace(ctx, in)
		if positive && err == nil {
			commits++
		}
		return out, err
	}
	pulse := func(context.Context, RuntimeRecoveryHeartbeat) error {
		callbacks++
		if pulseDeferralInCall("installActiveCandidatesFQDN") {
			assemblyCallbacks++
			if !allPriorityMembersLive(r) {
				t.Fatal("optional report lost original native member")
			}
		}
		return nil
	}
	r.phase = "maintenance"
	err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { return nil }, pulse)
	r.phase = ""
	for a, d := range old {
		if a.deadline != d {
			t.Fatal("original deadline changed")
		}
	}
	t.Logf("RESULT assembly=%d err=%v commits=%d callbacks=%d alive=%t now=%s diagnostics=%v costs=%v", assemblyCallbacks, err, commits, callbacks, allPriorityMembersLive(r), *r.now-start, diagnostics, r.charged)
	// Two returned reports at the original assembly boundary, plus the bounded
	// per-owner collection boundary before each native proof in
	// installActiveCandidatesFQDN.
	if err != nil || commits != 1 || assemblyCallbacks != 4 || !allPriorityMembersLive(r) {
		t.Fatal("bounded successful commit/report work lost finite ordinary authority")
	}
}

func TestMaintenanceReportContinuityOriginalBounds(t *testing.T) {
	for _, mode := range []string{"returned_reports", "unused", "no_publish", "tight_original", "missing_clock", "regressed_clock", "canceled", "native_unknown", "callback_failure", "callback_canceled", "callback_slow", "other_delivery", "other_entry", "other_authority", "other_removed", "other_expired", "tracked_delivery", "returned_clock_regressed", "qualification_lost"} {
		t.Run(mode, func(t *testing.T) {
			r, _, d := pulseDeferralFixture(t)
			r.charge("fast_collection", 900*time.Millisecond)
			if !d.deferPulse(context.Background(), r.c) || !d.used {
				t.Fatal("real due deferral missing")
			}
			d.finishCollection(r.c.active)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tracked, other := pulseDeferralIDs()[3], pulseDeferralIDs()[0]
			wantErr, wantCalls := true, 1
			switch mode {
			case "returned_reports":
				wantErr, wantCalls = false, 2
			case "unused":
				d.used = false
				wantErr, wantCalls = false, 0
			case "no_publish":
				wantErr, wantCalls = false, 0
			case "tight_original":
				// A shorter existing authority is not replaced by a candidate.
				a := r.c.active[other].Authority
				a.mu.Lock()
				a.deadline = *r.now + 14*time.Second
				a.mu.Unlock()
				wantErr, wantCalls = false, 0
			case "missing_clock":
				delete(r.c.recoveryReportClocks, tracked)
				wantCalls = 0
			case "regressed_clock":
				clock := r.c.recoveryReportClocks[tracked]
				clock.returned -= time.Millisecond
				r.c.recoveryReportClocks[tracked] = clock
				wantCalls = 0
			case "canceled":
				cancel()
				wantCalls = 0
			case "native_unknown":
				r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"unknown", "unknown"} }
				wantCalls = 0
			}
			original := map[*PermitLeaseAuthority]time.Duration{}
			for _, a := range r.c.active {
				original[a.Authority] = a.Authority.deadline
			}
			native := map[string]time.Duration{}
			for k, v := range r.installed {
				native[k] = v
			}
			calls := 0
			publish := func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
				calls++
				switch mode {
				case "callback_failure":
					return ErrRuntimeController
				case "callback_canceled":
					cancel()
				case "callback_slow":
					r.charge("slow_report_return", 6*time.Second)
				case "other_delivery":
					a := r.c.active[other]
					a.Delivery.Manifest.LocalPrefixes[0] = "10.77.0.0/24"
					r.c.active[other] = a
				case "other_entry":
					a := r.c.active[other]
					a.Entry.Observed[0].InterfaceIndex++
					r.c.active[other] = a
				case "other_authority":
					a := r.c.active[other]
					a.Authority = maintenanceAuthority(r)()
					r.c.active[other] = a
				case "other_removed":
					delete(r.c.active, other)
				case "other_expired":
					r.c.active[other].Authority.Invalidate()
				case "tracked_delivery":
					a := r.c.active[out.ConnectionID]
					a.Delivery.Manifest.LocalPrefixes[0] = "10.88.0.0/24"
					r.c.active[out.ConnectionID] = a
				case "returned_clock_regressed":
					for id := range d.owners {
						if id != out.ConnectionID {
							clock := r.c.recoveryReportClocks[id]
							clock.returned -= time.Millisecond
							r.c.recoveryReportClocks[id] = clock
						}
					}
				case "qualification_lost":
					r.c.qualification.invalid = true
				}
				return nil
			}
			if mode == "no_publish" {
				publish = nil
			}
			err := d.pulseBeforeAssembly(ctx, r.c, publish)
			if (err != nil) != wantErr || calls != wantCalls {
				t.Fatalf("mode=%s err=%v calls=%d wantErr=%t wantCalls=%d", mode, err, calls, wantErr, wantCalls)
			}
			for a, deadline := range original {
				if mode != "other_expired" && a.deadline != deadline {
					t.Fatal("original authority changed")
				}
			}
			if !wantErr && !reflect.DeepEqual(native, r.installed) {
				t.Fatal("optional telemetry changed native members")
			}
			if mode == "returned_reports" {
				for id, before := range d.owners {
					after, ok := r.c.recoveryReportClock(r.c.active[id])
					if !ok || after.sequence <= before.clock.sequence || after.returned <= before.clock.returned {
						t.Fatal("no actual newer returned report")
					}
				}
			}
		})
	}
}
