package control

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"reflect"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

type priorityPollFake struct {
	*recoveryObservedPollFake
	order []string
}

func (f *priorityPollFake) RenewActiveIPsecRuntimeObserved(ctx context.Context, publish func(context.Context, ipsec.RuntimeDelivery, ipsec.RuntimeStatusReport) error, pulse func(context.Context, ipsec.RuntimeRecoveryHeartbeat) error) error {
	f.order = append(f.order, "fresh_active_renewal")

	if f.scenario == "detached_http_cancel" {
		m := f.materials[f.items[0].ConnectionID]
		report, _ := f.runtimePollFake.ObserveIPsecStatus(ctx, m.RuntimeDelivery)
		if m.Manifest.BGP == nil {
			report = staticRecoveryReport(report, 1)
		}
		return publish(context.Background(), m.RuntimeDelivery, report)
	}
	if f.scenario == "renewal_refused" {
		return errors.New("fresh CP refused")
	}
	// Reuse the original complete5/static2 callback rig. It never fetches
	// materials in this hook or ACKs the internally obtained maintained results.
	mats := []ipsec.RuntimeMaterial{}
	for _, item := range f.items {
		mats = append(mats, f.materials[item.ConnectionID])
	}
	_, err := f.MaintainIPsecRuntimeRecoveryObserved(ctx, mats, publish, pulse)
	return err
}
func (f *priorityPollFake) RefreshIPsecActiveRecovery(context.Context) ([]ipsec.RuntimeRecoveryHeartbeat, error) {
	f.order = append(f.order, "original_status")
	return nil, nil
}

func (f *priorityPollFake) IPsecReportStatus(ctx context.Context, id uuid.UUID, out ipsec.RuntimeStatusReport) error {
	if f.scenario == "detached_http_cancel" {
		f.cancel()
		select {
		case <-ctx.Done():
			f.order = append(f.order, "parent_http_canceled")
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			return errors.New("report did not observe polling parent cancellation")
		}
	}
	return f.recoveryObservedPollFake.IPsecReportStatus(ctx, id, out)
}

func TestIPsecPriorityRenewalBeforeStatusNoMaterialOrACK(t *testing.T) {
	for _, scenario := range []string{"positive", "renewal_refused", "duplicate", "zero_sequence", "oversized_sequence", "wrong_connection", "wrong_revision", "duplicate_maintained", "pulse_after_final_older", "parent_canceled", "detached_http_cancel"} {
		t.Run(scenario, func(t *testing.T) {
			f := &priorityPollFake{recoveryObservedPollFake: newRecoveryObservedPollFake(t, scenario)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.cancel = cancel
			err := RefreshIPsecRuntimePriority(ctx, f, f)
			if (scenario == "positive") != (err == nil) {
				t.Fatal("priority result", scenario, err)
			}
			if f.acks != 0 || f.applyCount != 0 {
				t.Fatal("retained context acknowledged/applied", f.acks, f.applyCount)
			}
			expected := []string{"fresh_active_renewal", "original_status"}
			if scenario == "detached_http_cancel" {
				expected = []string{"fresh_active_renewal", "parent_http_canceled", "original_status"}
			}
			if !reflect.DeepEqual(f.order, expected) {
				t.Fatal("optional status ran before renewal or got skipped after refusal", f.order)
			}
			if scenario == "parent_canceled" && len(f.reports) != 0 {
				t.Fatal("priority callback detached parent")
			}
		})
	}
}

func TestIPsecPriorityStatusHTTPFailureRemainsAdvisory(t *testing.T) {
	f := &priorityPollFake{recoveryObservedPollFake: newRecoveryObservedPollFake(t, "positive")}
	f.reportFailure = true
	if RefreshIPsecRuntimePriority(context.Background(), f, f) == nil || !f.completed || f.acks != 0 || f.applyCount != 0 {
		t.Fatal("HTTP telemetry incorrectly substituted ACK or blocked valid native core")
	}
}
