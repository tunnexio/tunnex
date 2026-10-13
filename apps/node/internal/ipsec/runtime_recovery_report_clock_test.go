package ipsec

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMaintenanceSkippedSequenceDoesNotResetReportDue(t *testing.T) {
	r, raw := heartbeatRig(t)
	entries, _ := r.c.journal.Entries()
	id := entries[0].Allocation.ConnectionID
	r.c.client = &refreshLeaseFixture{}
	r.now = 5 * time.Second
	reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Report.SelectionSequence == nil {
		t.Fatal("initial real native report missing", err, len(reports))
	}
	active, native := r.c.active[id], append([]byte(nil), (*raw)...)
	deadline := active.Authority.deadline
	sequence := *reports[0].Report.SelectionSequence
	clock := r.c.recoveryReportClocks[id]
	if clock.returned != r.now || clock.sequence != sequence {
		t.Fatal("clock not stamped at the actual returned observation")
	}
	r.now = 9 * time.Second
	reports, err = r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(reports) != 0 || r.c.recoveryHistory[id].lastNow != r.now {
		t.Fatal("genuine equal-sequence sample boundary missing", err, len(reports))
	}
	if r.c.recoveryReportClocks[id] != clock {
		t.Fatal("same-sequence skipped observation moved real report timing")
	}
	// Respect the original one-second native sample interval. The skipped
	// report must not add the maintenance three-second publication delay.
	r.now = 10 * time.Second
	publications := 0
	r.c.mu.Lock()
	err = r.c.refreshMaintenanceActiveRecovery(context.Background(), map[uuid.UUID]bool{id: true}, func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
		publications++
		if out.ConnectionID != id || out.Report.SelectionSequence == nil || *out.Report.SelectionSequence <= sequence || out.Report.ActiveSlot == nil || *out.Report.ActiveSlot != 1 {
			t.Fatal("not a fresh same-owner native report", out)
		}
		return nil
	})
	r.c.mu.Unlock()
	if err != nil || publications != 1 {
		t.Fatal("equal-sequence native observation postponed a due real publication", err, publications)
	}
	if !reflect.DeepEqual(active, r.c.active[id]) || active.Authority.deadline != deadline || !reflect.DeepEqual(native, *raw) {
		t.Fatal("report clock changed original authority or native permit")
	}
}

func TestRecoveryReportClockRejectsStaleBindingAndAuthority(t *testing.T) {
	for _, kind := range []string{"duplicate_sequence", "older_sequence", "delivery", "policy_epoch", "namespace", "ownership_digest", "selected_slot", "revoked", "expired", "canceled", "qualification", "daemon", "backwards_clock"} {
		t.Run(kind, func(t *testing.T) {
			r, _ := heartbeatRig(t)
			r.c.client = &refreshLeaseFixture{}
			r.now = 5 * time.Second
			reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
			if err != nil || len(reports) != 1 {
				t.Fatal("initial genuine report", err, len(reports))
			}
			out := reports[0]
			id := out.ConnectionID
			before := r.c.recoveryReportClocks[id]
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.now = 6 * time.Second
			a := r.c.active[id]
			switch kind {
			case "older_sequence":
				zero := uint64(0)
				out.Report.SelectionSequence = &zero
			case "delivery":
				out.Delivery.ID = uuid.New()
			case "policy_epoch":
				a.Identity.PolicyHash = strings.Repeat("a", 64)
				r.c.active[id] = a
			case "namespace":
				a.Entry.Allocation.Namespace = "net:[4026533999]"
				r.c.active[id] = a
			case "ownership_digest":
				a.Entry.OwnershipDigest = strings.Repeat("b", 64)
				r.c.active[id] = a
			case "selected_slot":
				two := 2
				out.Report.ActiveSlot = &two
			case "revoked":
				a.Authority.Invalidate()
			case "expired":
				a.Authority.elapsed = func() time.Duration { return 61 * time.Second }
			case "canceled":
				cancel()
			case "qualification":
				r.c.qualification.invalid = true
			case "daemon":
				r.c.config.DaemonAlive = func() bool { return false }
			case "backwards_clock":
				r.now = 4 * time.Second
			}
			if r.c.rememberRecoveryReport(ctx, id, out.Delivery, out.Report) || r.c.recoveryReportClocks[id] != before {
				t.Fatal("stale/invalid observation moved scheduling clock")
			}
		})
	}
}

func TestRecoveryReportForeignClockCannotSuppressNativeObservation(t *testing.T) {
	r, raw := heartbeatRig(t)
	r.c.client = &refreshLeaseFixture{}
	r.now = 5 * time.Second
	initial, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(initial) != 1 {
		t.Fatal(err, len(initial))
	}
	id := initial[0].ConnectionID
	active, native := r.c.active[id], append([]byte(nil), (*raw)...)
	foreign := r.c.recoveryReportClocks[id]
	foreign.epoch.DeliveryID, foreign.returned = uuid.New(), time.Hour
	r.c.recoveryReportClocks[id] = foreign
	r.now = 9 * time.Second
	publications := 0
	r.c.mu.Lock()
	err = r.c.refreshMaintenanceActiveRecovery(context.Background(), map[uuid.UUID]bool{id: true}, func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
		publications++
		if out.Report.SelectionSequence == nil || *out.Report.SelectionSequence <= *initial[0].Report.SelectionSequence {
			t.Fatal("foreign clock replaced fresh native sequence")
		}
		return nil
	})
	r.c.mu.Unlock()
	clock, known := r.c.recoveryReportClock(active)
	if err != nil || publications != 1 || !known || clock.returned != r.now || !reflect.DeepEqual(active, r.c.active[id]) || !reflect.DeepEqual(native, *raw) {
		t.Fatal("foreign scheduling metadata masked current owner or altered native authority", err, publications)
	}
}

func TestRecoveryReportClockStampFollowsNativeIOAndReturn(t *testing.T) {
	for _, kind := range []string{"status_native_IO", "status_reader_refusal", "pulse_callback_IO", "pulse_callback_refusal", "pulse_callback_canceled", "pulse_callback_over_budget"} {
		t.Run(kind, func(t *testing.T) {
			r, _ := heartbeatRig(t)
			r.c.client = &refreshLeaseFixture{}
			r.now = 5 * time.Second
			initial, err := r.c.RefreshIPsecActiveRecovery(context.Background())
			if err != nil || len(initial) != 1 {
				t.Fatal(err, len(initial))
			}
			id := initial[0].ConnectionID
			before, active := r.c.recoveryReportClocks[id], r.c.active[id]
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.now = 9 * time.Second
			if strings.HasPrefix(kind, "status_") {
				IO := 0
				r.c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
					IO++
					if r.c.recoveryReportClocks[id] != before {
						t.Fatal("report clock advanced before native IO completed")
					}
					r.now += 2 * time.Second
					return viciMessage{}, nil, errors.New("honest native unknown")
				}}
				r.c.config.IPPath = "/usr/bin/true"
				if kind == "status_reader_refusal" {
					r.c.config.IPPath = "not-an-absolute-executable"
				}
				report, observeErr := r.c.ObserveIPsecStatus(ctx, active.Delivery)
				if observeErr != nil || report.SelectionSequence == nil {
					t.Fatal("original status result changed", observeErr)
				}
				if kind == "status_reader_refusal" {
					if IO != 0 || r.c.recoveryReportClocks[id] != before {
						t.Fatal("sequence assignment without native IO moved clock")
					}
				} else if IO == 0 || r.c.recoveryReportClocks[id].returned != r.now || r.c.recoveryReportClocks[id].sequence != *report.SelectionSequence {
					t.Fatal("clock was not stamped on actual post-native report return", IO, r.c.recoveryReportClocks[id], r.now)
				}
			} else {
				r.c.mu.Lock()
				err = r.c.refreshMaintenanceActiveRecovery(ctx, map[uuid.UUID]bool{id: true}, func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
					if r.c.recoveryReportClocks[id] != before || out.Report.SelectionSequence == nil {
						t.Fatal("clock moved before actual callback")
					}
					r.now += 2 * time.Second
					switch kind {
					case "pulse_callback_refusal":
						return ErrRuntimeController
					case "pulse_callback_canceled":
						cancel()
					case "pulse_callback_over_budget":
						r.now += 4 * time.Second
					}
					return nil
				})
				r.c.mu.Unlock()
				if kind == "pulse_callback_IO" {
					if err != nil || r.c.recoveryReportClocks[id].returned != r.now {
						t.Fatal("real callback return timing missing", err)
					}
				} else if err == nil || r.c.recoveryReportClocks[id] != before {
					t.Fatal("refused/canceled/over-budget callback moved report due clock", err)
				}
			}
			if !reflect.DeepEqual(active, r.c.active[id]) {
				t.Fatal("telemetry scheduling changed original authority")
			}
		})
	}
}

func TestRecoveryReportStandaloneReturnCannotStampInvalidAuthority(t *testing.T) {
	for _, kind := range []string{"expired", "canceled", "qualification", "daemon"} {
		t.Run(kind, func(t *testing.T) {
			r, _ := heartbeatRig(t)
			r.c.client = &refreshLeaseFixture{}
			r.now = 5 * time.Second
			initial, err := r.c.RefreshIPsecActiveRecovery(context.Background())
			if err != nil || len(initial) != 1 {
				t.Fatal(err, len(initial))
			}
			id := initial[0].ConnectionID
			before := r.c.recoveryReportClocks[id]
			entries, _ := r.c.journal.Entries()
			if r.c.journal.Save(entries) != nil {
				t.Fatal("fresh durable observation sequence")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observed, checks, alive := false, 0, true
			r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
				observed = true
				return [2]string{"up", "up"}
			}
			r.c.config.DaemonAlive = func() bool {
				if observed {
					checks++
					// First call is the selected owner's final native gate;
					// second is the empty drain before public report return.
					if checks == 2 {
						switch kind {
						case "expired":
							r.c.active[id].Authority.elapsed = func() time.Duration { return 61 * time.Second }
						case "canceled":
							cancel()
						case "qualification":
							r.c.qualification.invalid = true
						case "daemon":
							alive = false
							return true // The final return must independently recheck.
						}
					}
				}
				return alive
			}
			r.now = 9 * time.Second
			_, _ = r.c.RefreshIPsecActiveRecovery(ctx)
			if checks < 2 || r.c.recoveryReportClocks[id] != before {
				t.Fatal("invalid public-return state advanced report clock", checks)
			}
			// Invalid metadata never suppresses a future observation. Restoring
			// the fixture's test-only gates cannot make this stale report newer.
			if clock, known := r.c.recoveryReportClock(r.c.active[id]); !known || clock.returned != 5*time.Second {
				t.Fatal("invalid return became a fresh scheduling receipt")
			}
		})
	}
}

func TestRecoveryReportFinalOwnerFailureDiscardsAccumulatedClock(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	r.charge("loop_start_due", time.Second)
	initial, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(initial) != 2 {
		t.Fatal("initial two real static observations", err, len(initial))
	}
	before := map[uuid.UUID]runtimeRecoveryReportClock{}
	for id, clock := range r.c.recoveryReportClocks {
		before[id] = clock
	}
	entries, _ := r.c.journal.Entries()
	if r.c.journal.Save(entries) != nil {
		t.Fatal("fresh durable observation sequence")
	}
	r.charge("next_turn", 3*time.Second)
	native, calls := r.c.recoveryObserve, 0
	r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		calls++
		if calls == 2 {
			return [2]string{"unknown", "up"}
		}
		return native(ctx, e)
	}
	reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	if calls != 2 || err == nil || len(reports) != 0 {
		t.Fatal("failed final owner returned accumulated reports", calls, err, len(reports))
	}
	for id, clock := range r.c.recoveryReportClocks {
		if prior, existed := before[id]; !existed || clock != prior {
			t.Fatal("discarded accumulated report moved a clock")
		}
	}
}
