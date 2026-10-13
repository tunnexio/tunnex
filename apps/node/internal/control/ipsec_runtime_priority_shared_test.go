package control

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

type prioritySharedPollFake struct {
	*observedMaintenancePollFake
	order         []string
	scenario      string
	materialReads int
	cancel        context.CancelFunc
}

func (f *prioritySharedPollFake) IPsecMaterial(ctx context.Context, id uuid.UUID, revision int64) (ipsec.RuntimeMaterial, error) {
	f.materialReads++
	return f.runtimePollFake.IPsecMaterial(ctx, id, revision)
}
func (f *prioritySharedPollFake) RenewActiveIPsecRuntimeObserved(ctx context.Context, publish func(context.Context, ipsec.RuntimeDelivery, ipsec.RuntimeStatusReport) error, _ func(context.Context, ipsec.RuntimeRecoveryHeartbeat) error) error {
	f.order = append(f.order, "fresh_active_renewal")
	if f.scenario == "renewal_refused" {
		return errors.New("fresh CP refused")
	}
	mats := []ipsec.RuntimeMaterial{}
	for _, item := range f.items {
		mats = append(mats, f.materials[item.ConnectionID])
	}
	if f.scenario == "parent_canceled" {
		f.cancel()
	}
	_, err := f.MaintainIPsecRuntimeObserved(ctx, mats, publish)
	return err
}
func (f *prioritySharedPollFake) RefreshIPsecActiveRecovery(context.Context) ([]ipsec.RuntimeRecoveryHeartbeat, error) {
	f.order = append(f.order, "original_status")
	return nil, nil
}
func TestIPsecSharedPriorityBeforeOptionalStatusWithoutMaterialOrACK(t *testing.T) {
	for _, scenario := range []string{"positive", "renewal_refused", "wrong_connection", "wrong_revision", "duplicate", "parent_canceled", "detached_parent"} {
		t.Run(scenario, func(t *testing.T) {
			f := &prioritySharedPollFake{observedMaintenancePollFake: newObservedMaintenancePollFake(t), scenario: scenario}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.cancel = cancel
			var firstD ipsec.RuntimeDelivery
			var firstR ipsec.RuntimeStatusReport
			f.observationChange = func(i int, d *ipsec.RuntimeDelivery, r *ipsec.RuntimeStatusReport) {
				if i == 0 {
					firstD, firstR = *d, *r
				}
				switch scenario {
				case "wrong_connection":
					if i == 0 {
						d.Manifest.ConnectionID = uuid.Nil
					}
				case "wrong_revision":
					if i == 0 {
						r.DesiredRevision++
					}
				case "duplicate":
					if i == 1 {
						*d, *r = firstD, firstR
					}
				case "detached_parent":
					if i == 0 {
						cancel()
					}
				}
			}
			if scenario == "detached_parent" {
				f.publicationContext = context.Background()
			}
			err := RefreshIPsecRuntimePriority(ctx, f, f)
			if (scenario == "positive") != (err == nil) {
				t.Fatal("priority result", scenario, err)
			}
			if f.acks != 0 || f.applyCount != 0 || f.materialReads != 0 {
				t.Fatal("priority fetched material or acknowledged/applied", f.materialReads, f.acks, f.applyCount)
			}
			if !reflect.DeepEqual(f.order, []string{"fresh_active_renewal", "original_status"}) {
				t.Fatal("optional IO precedes renewal or is skipped", f.order)
			}
			if (scenario == "parent_canceled" || scenario == "detached_parent") && len(f.reports) != 0 {
				t.Fatal("priority publication detached canceled caller")
			}
		})
	}
}
func TestIPsecSharedPriorityHTTPFailureRemainsAdvisory(t *testing.T) {
	f := &prioritySharedPollFake{observedMaintenancePollFake: newObservedMaintenancePollFake(t), scenario: "positive"}
	f.reportFailure = true
	if RefreshIPsecRuntimePriority(context.Background(), f, f) == nil || !f.completed || f.acks != 0 || f.applyCount != 0 || f.materialReads != 0 {
		t.Fatal("HTTP telemetry changed native completion or escaped ACK/material boundary")
	}
}
