package ipsec

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func pulseDeferralIDs() []uuid.UUID {
	ids := make([]uuid.UUID, 5)
	for i := range ids {
		ids[i] = uuid.MustParse(fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1))
	}
	return ids
}

func pulseDeferralFixture(t *testing.T) (*renewalCycleRig, map[uuid.UUID]bool, *maintenancePulseDeferral) {
	t.Helper()
	r, _ := maintainedMissingStandby(t, 2, pulseDeferralIDs()...)
	allowed := map[uuid.UUID]bool{}
	for id := range r.c.active {
		allowed[id] = true
	}
	publish := func(context.Context, RuntimeRecoveryHeartbeat) error { return nil }
	for i := 0; i < 2; i++ {
		if err := r.c.refreshMaintenanceActiveRecovery(context.Background(), allowed, publish); err != nil {
			t.Fatal("actual initial report", err)
		}
	}
	d := r.c.beginMaintenancePulseDeferral(allowed, publish)
	if d == nil || len(d.owners) != 2 {
		t.Fatal("missing exact fresh static reports")
	}
	return r, allowed, d
}

func TestMaintenancePulseDeferralBoundedAndReadOnly(t *testing.T) {
	r, allowed, d := pulseDeferralFixture(t)
	clocks := map[uuid.UUID]runtimeRecoveryReportClock{}
	deadlines := map[uuid.UUID]time.Duration{}
	for id, a := range r.c.active {
		clocks[id], deadlines[id] = r.c.recoveryReportClocks[id], a.Authority.deadline
	}
	native := map[string]time.Duration{}
	for name, deadline := range r.installed {
		native[name] = deadline
	}
	if !d.deferPulse(context.Background(), r.c) || d.used {
		t.Fatal("no due report at collection entry")
	}
	r.charge("fast_collection", 900*time.Millisecond)
	if !d.deferPulse(context.Background(), r.c) || !d.used || !d.reportsCurrent(r.c) {
		t.Fatal("short exact-bound collection did not defer due optional work")
	}
	for id, a := range r.c.active {
		if r.c.recoveryReportClocks[id] != clocks[id] || a.Authority.deadline != deadlines[id] {
			t.Fatal("deferral changed a clock or original authority")
		}
	}
	if !reflect.DeepEqual(native, r.installed) {
		t.Fatal("deferral changed finite native members")
	}
	r.charge("collection_limit", 100*time.Millisecond)
	if d.deferPulse(context.Background(), r.c) || d.open {
		t.Fatal("one-second collection limit reset per owner")
	}
	published := 0
	if err := r.c.refreshMaintenanceActiveRecovery(context.Background(), allowed, func(context.Context, RuntimeRecoveryHeartbeat) error { published++; return nil }); err != nil || published != 1 {
		t.Fatal("slow collection did not use original fresh pulse", published, err)
	}
	if d.deferPulse(context.Background(), r.c) || !d.reportsCurrent(r.c) {
		t.Fatal("fresh actual report reopened deferral or was rejected")
	}
}

func TestMaintenancePulseDeferralRejectsBindingDrift(t *testing.T) {
	for _, scenario := range []string{"entry", "recovery_stage", "delivery", "environment", "grants", "history", "missing_history", "report_sequence", "report_return", "authority", "revoked", "backwards", "canceled", "qualification"} {
		t.Run(scenario, func(t *testing.T) {
			r, _, d := pulseDeferralFixture(t)
			id := pulseDeferralIDs()[3]
			a := r.c.active[id]
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "entry":
				a.Entry.Observed[0].InterfaceIndex++
			case "recovery_stage":
				a.Entry.Recovery.Stage = "pending"
			case "delivery":
				a.Delivery.Manifest.LocalPrefixes[0] = "10.99.0.0/24"
			case "environment":
				a.Environment.Underlays[0].OuterMTU--
			case "grants":
				a.Grants = append(a.Grants, GuardGrant{})
			case "history":
				r.c.recoveryHistory[id].current = 1
			case "missing_history":
				delete(r.c.recoveryHistory, id)
			case "report_sequence":
				clock := r.c.recoveryReportClocks[id]
				clock.sequence--
				r.c.recoveryReportClocks[id] = clock
			case "report_return":
				clock := r.c.recoveryReportClocks[id]
				clock.returned -= time.Millisecond
				r.c.recoveryReportClocks[id] = clock
			case "authority":
				a.Authority = maintenanceAuthority(r)()
			case "revoked":
				a.Authority.Invalidate()
			case "backwards":
				*r.now = d.started - time.Millisecond
			case "canceled":
				cancel()
			case "qualification":
				r.c.qualification.invalid = true
			}
			r.c.active[id] = a
			if d.deferPulse(ctx, r.c) || d.open {
				t.Fatal("changed binding or invalid execution skipped original pulse")
			}
		})
	}
}

func TestMaintenancePulseDeferralRejectsStaleOrRegressedReports(t *testing.T) {
	for _, scenario := range []string{"age", "sequence", "return", "entry", "recovery_stage", "missing_clock"} {
		t.Run(scenario, func(t *testing.T) {
			r, _, d := pulseDeferralFixture(t)
			r.charge("fast_collection", 900*time.Millisecond)
			if !d.deferPulse(context.Background(), r.c) || !d.used {
				t.Fatal("due deferral not reached")
			}
			id := pulseDeferralIDs()[3]
			clock := r.c.recoveryReportClocks[id]
			switch scenario {
			case "age":
				r.charge("slow_commit", 10*time.Second)
			case "sequence":
				clock.sequence--
				r.c.recoveryReportClocks[id] = clock
			case "return":
				clock.returned -= time.Millisecond
				r.c.recoveryReportClocks[id] = clock
			case "entry":
				a := r.c.active[id]
				a.Entry.Phase = RuntimeApplying
				r.c.active[id] = a
			case "recovery_stage":
				r.c.active[id].Entry.Recovery.Stage = "pending"
			case "missing_clock":
				delete(r.c.recoveryReportClocks, id)
			}
			if d.reportsCurrent(r.c) {
				t.Fatal("stale/regressed/foreign report accepted")
			}
		})
	}
}

func pulseDeferralInCall(name string) bool {
	var pcs [24]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".(*RuntimeController)."+name) {
			return true
		}
		if !more {
			return false
		}
	}
}

func TestMaintenancePulseDeferralSlowIOAndFailure(t *testing.T) {
	for _, scenario := range []string{"cp_slow", "bridge_slow", "assembly_slow", "commit_slow", "cp_failure", "bridge_failure", "commit_failure", "assembly_stale", "commit_stale", "cp_expired", "publish_slow", "publish_stale", "publish_failure", "final_sample_stale"} {
		t.Run(scenario, func(t *testing.T) {
			r, _ := maintainedMissingStandby(t, 2, pulseDeferralIDs()...)
			r.charge("loop_due", time.Second)
			reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
			if err != nil || len(reports) != 2 {
				t.Fatal("actual initial reports", err, len(reports))
			}
			last := map[uuid.UUID]time.Duration{}
			deadlines := map[*PermitLeaseAuthority]time.Duration{}
			for id, a := range r.c.active {
				deadlines[a.Authority] = a.Authority.deadline
				if a.Entry.ContractVersion == 2 {
					last[id] = r.c.recoveryReportClocks[id].returned
				}
			}
			candidate := 0
			var authorities []*PermitLeaseAuthority
			constructor := maintenanceAuthority(r)
			tracked := func() *PermitLeaseAuthority {
				candidate++
				a := constructor()
				authorities = append(authorities, a)
				return a
			}
			injected := false
			inject := func(phase string) error {
				if injected || !strings.HasPrefix(scenario, phase+"_") {
					return nil
				}
				injected = true
				switch {
				case strings.HasSuffix(scenario, "_failure"):
					return ErrRuntimeController
				case strings.HasSuffix(scenario, "_expired"):
					r.charge(scenario, 61*time.Second)
				case scenario == "publish_stale" || scenario == "final_sample_stale":
					r.charge(scenario, 11*time.Second)
				case strings.HasSuffix(scenario, "_stale"):
					r.charge(scenario, 3*time.Second)
				default:
					r.charge(scenario, 1250*time.Millisecond)
				}
				return nil
			}
			client := r.c.client
			r.c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
				out, err := client.RenewIPsecLease(ctx, id, q)
				fresh := len(authorities) > 0 && authorities[len(authorities)-1].pending != nil && authorities[len(authorities)-1].pending.Nonce == q.Nonce
				if fresh && candidate == 4 {
					if injectErr := inject("cp"); injectErr != nil {
						return RuntimeLease{}, injectErr
					}
				}
				return out, err
			})
			read := r.c.guard.reader.run
			r.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
				if candidate == 4 && pulseDeferralInCall("maintenanceCurrentWithNativeProof") {
					if err := inject("bridge"); err != nil {
						return nil, err
					}
				}
				return read(ctx, args...)
			}
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				if candidate == 5 && pulseDeferralInCall("installActiveCandidatesFQDN") {
					if err := inject("assembly"); err != nil {
						return err
					}
				}
				return prove(ctx, e, env)
			}
			replace := r.c.replace
			positiveCommits, targetPositiveCommits := 0, 0
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				positive := false
				for _, g := range in.Connections {
					positive = positive || !g.PrefixOnly
					if g.ID == pulseDeferralIDs()[3] && !g.PrefixOnly {
						targetPositiveCommits++
					}
				}
				if positive {
					if err := inject("commit"); err != nil {
						return GuardManifest{}, err
					}
					positiveCommits++
				}
				return replace(ctx, in)
			}
			maxGap := time.Duration(0)
			record := func(id uuid.UUID) {
				if before, known := last[id]; known {
					gap := *r.now - before
					if gap > maxGap {
						maxGap = gap
					}
					if gap > 10*time.Second {
						t.Fatalf("stale report published after %s", gap)
					}
					last[id] = *r.now
				}
			}
			published := 0
			finalSamples := 0
			clock := r.c.recoveryClock
			r.c.recoveryClock = func() time.Duration {
				if published == 5 && pulseDeferralInCall("refreshMaintenanceRecovery") {
					finalSamples++
					// One post-publication sample, then the five final binding
					// samples. Model time spent by the last optional sample.
					if finalSamples == 6 {
						_ = inject("final_sample")
					}
				}
				return clock()
			}
			targetPublished := false
			r.phase = "maintenance"
			err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), tracked, func() bool { return true }, func(_ context.Context, d RuntimeDelivery, _ RuntimeStatusReport) error {
				published++
				targetPublished = targetPublished || d.Manifest.ConnectionID == pulseDeferralIDs()[3]
				record(d.Manifest.ConnectionID)
				return inject("publish")
			}, func(_ context.Context, out RuntimeRecoveryHeartbeat) error { record(out.ConnectionID); return nil })
			r.phase = ""
			if !injected {
				t.Fatal("test did not reach intended real IO boundary")
			}
			for a, deadline := range deadlines {
				if a.deadline != deadline {
					t.Fatal("original authority deadline changed")
				}
			}
			if strings.HasSuffix(scenario, "_slow") {
				if err != nil || published != 5 || positiveCommits != 1 || !allPriorityMembersLive(r) {
					t.Fatal("bounded slow IO failed continuity", err, published, positiveCommits, len(r.c.active))
				}
			} else if scenario == "bridge_failure" {
				if err != nil || published != 4 || targetPublished || targetPositiveCommits != 0 || len(r.c.active) != 4 || len(r.installed) != 12 {
					t.Fatal("scoped bridge refusal lost other owners or granted failed target", err, published, targetPositiveCommits, len(r.c.active), len(r.installed))
				}
				for id := range r.c.active {
					if id == pulseDeferralIDs()[3] {
						t.Fatal("failed target retained")
					}
					for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
						if r.installed[name] <= *r.now {
							t.Fatal("healthy sibling finite authority lost")
						}
					}
				}
			} else {
				expectedPublications := 0
				if strings.HasPrefix(scenario, "publish_") {
					expectedPublications = 1
				} else if scenario == "final_sample_stale" {
					expectedPublications = 5
				}
				if err == nil || published != expectedPublications || len(r.c.active) != 0 || len(r.installed) != 0 {
					t.Fatal("failed or stale operation retained/acknowledged authority", err, published, len(r.c.active), len(r.installed))
				}
				if scenario != "commit_stale" && scenario != "final_sample_stale" && !strings.HasPrefix(scenario, "publish_") && positiveCommits != 0 {
					t.Fatal("failed precommit path installed positive authority")
				}
			}
			t.Logf("scenario=%s err=%v maxReportGap=%s positiveCommits=%d publications=%d costs=%v", scenario, err, maxGap, positiveCommits, published, r.charged)
		})
	}
}
