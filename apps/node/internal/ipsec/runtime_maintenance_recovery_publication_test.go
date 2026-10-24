package ipsec

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A native recovery sample may cross its previous report's age limit without
// expiring any application authority. Only the exact newly sampled owner may
// qualify its pending publication; normal returned clocks stay unchanged until
// the existing successful-publication path remembers the report.
func TestMaintenanceFreshRecoveryPublicationCrossesPreviousReportAge(t *testing.T) {
	for _, age := range []time.Duration{7 * time.Second, 9500 * time.Millisecond} {
		t.Run(age.String(), func(t *testing.T) {
			r, _, d := pulseDeferralFixture(t)
			r.charge("collection", 900*time.Millisecond)
			if !d.deferPulse(context.Background(), r.c) || !d.used {
				t.Fatal("existing bounded deferral not reached")
			}
			var oldest uuid.UUID
			for id, before := range d.owners {
				if oldest == uuid.Nil || before.clock.returned < d.owners[oldest].clock.returned {
					oldest = id
				}
			}
			clock := d.owners[oldest].clock
			want := clock.returned + age
			if want < *r.now {
				t.Fatal("fixture clock already too old")
			}
			r.charge("independent_collection_and_assembly", want-*r.now)
			if !d.reportsCurrent(r.c) {
				t.Fatal("reports must be valid before the actual sample")
			}
			before := r.c.active[oldest]
			deadline := before.Authority.deadline
			if _, err := before.Authority.RemainingForApply(before.Identity, 15*time.Second); err != nil {
				t.Fatal("original authority has ample actual reserve", err)
			}
			var events []RuntimeDiagnostic
			r.c.config.Diagnostic = func(e RuntimeDiagnostic) { events = append(events, e) }
			callbacks, published := 0, 0
			// Exact wrapper currently used by maintainIPsecRuntimeItemsAttempt.
			publish := func(ctx context.Context, out RuntimeRecoveryHeartbeat) error {
				callbacks++
				if ctx.Err() != nil {
					t.Fatal("reproduction requires active wall-clock context")
				}
				if out.ConnectionID != oldest && callbacks == 1 {
					t.Fatal("oldest owner not sampled first")
				}
				if out.Report.SelectionSequence == nil || out.Report.ActiveSlot == nil {
					t.Fatal("real fresh heartbeat required")
				}
				if !d.reportsCurrentForRecovery(ctx, r.c, out) {
					return ErrRuntimeController
				}
				published++
				if !d.reportsCurrentForRecovery(ctx, r.c, out) {
					return ErrRuntimeController
				}
				return nil
			}
			err := d.pulseBeforeAssembly(context.Background(), r.c, publish)
			if before.Authority.deadline != deadline || r.c.active[oldest].Authority != before.Authority || deadline <= *r.now {
				t.Fatal("original authority altered/expired")
			}
			t.Logf("old_report_age_before=%s after=%s callbacks=%d published=%d err=%v diagnostics=%+v", age, *r.now-clock.returned, callbacks, published, err, events)
			if err != nil {
				t.Fatalf("fresh bounded sample could not publish despite valid original authority: %v", err)
			}
		})
	}
}
