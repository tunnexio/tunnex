package control

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

// The existing five-owner fake supplies unchanged complete results; this seam
// adds independently observed static telemetry before and during that page.
type recoveryObservedPollFake struct {
	*observedMaintenancePollFake
	scenario string
	cancel   context.CancelFunc
}

func newRecoveryObservedPollFake(t *testing.T, scenario string) *recoveryObservedPollFake {
	f := &recoveryObservedPollFake{observedMaintenancePollFake: newObservedMaintenancePollFake(t), scenario: scenario}
	for id, m := range f.materials {
		if m.Manifest.BGP == nil {
			version := 1
			m.Manifest.RecoveryVersion = &version
			f.materials[id] = m
		}
	}
	return f
}

func staticRecoveryReport(r ipsec.RuntimeStatusReport, sequence uint64) ipsec.RuntimeStatusReport {
	version := 1
	r.RecoveryVersion, r.SelectionSequence = &version, &sequence
	return r
}

func (f *recoveryObservedPollFake) MaintainIPsecRuntimeRecoveryObserved(ctx context.Context, mats []ipsec.RuntimeMaterial, publish func(context.Context, ipsec.RuntimeDelivery, ipsec.RuntimeStatusReport) error, pulse func(context.Context, ipsec.RuntimeRecoveryHeartbeat) error) ([]ipsec.RuntimeMaintenanceResult, error) {
	out, err := f.maintenancePollFake.MaintainIPsecRuntime(ctx, mats)
	if err != nil {
		return nil, err
	}
	pubCtx := ctx
	if f.scenario == "parent_canceled" {
		pubCtx = context.Background()
		f.cancel()
	}
	for round := uint64(1); round <= 2; round++ {
		for i, m := range mats {
			if m.Manifest.BGP != nil {
				continue
			}
			p := ipsec.RuntimeRecoveryHeartbeat{ConnectionID: m.Manifest.ConnectionID, Delivery: m.RuntimeDelivery, Report: staticRecoveryReport(out[i].Report, round)}
			if i == 0 {
				switch f.scenario {
				case "unknown_delivery":
					p.Delivery.ID = uuid.New()
					p.Report.DeliveryID = p.Delivery.ID
				case "changed_material":
					p.Delivery.OwnershipDigest = "foreign"
				case "wrong_revision":
					p.Report.DesiredRevision++
				case "wrong_connection":
					p.ConnectionID = uuid.New()
				case "zero_sequence":
					*p.Report.SelectionSequence = 0
				case "oversized_sequence":
					*p.Report.SelectionSequence = 9007199254740992
				case "duplicate", "duplicate_failed_http":
					if round == 2 {
						*p.Report.SelectionSequence = 1
					}
				}
			}
			if err := pulse(pubCtx, p); err != nil {
				return nil, err
			}
		}
	}
	for i, m := range mats {
		r := out[i].Report
		if m.Manifest.BGP == nil {
			r = staticRecoveryReport(r, 3)
		}
		out[i].Report = r
		if err := publish(ctx, m.RuntimeDelivery, r); err != nil {
			return nil, err
		}
		if i == 0 {
			switch f.scenario {
			case "duplicate_maintained":
				if err := publish(ctx, m.RuntimeDelivery, r); err != nil {
					return nil, err
				}
			case "pulse_after_final_older":
				p := ipsec.RuntimeRecoveryHeartbeat{ConnectionID: m.Manifest.ConnectionID, Delivery: m.RuntimeDelivery, Report: staticRecoveryReport(r, 2)}
				if err := pulse(ctx, p); err != nil {
					return nil, err
				}
			}
		}
	}
	f.completed = true
	if f.scenario == "final_digest" {
		out[4].Acknowledgement.OwnershipDigest = "foreign"
	}
	if f.scenario == "changed_final_report" {
		out[0].Report.Tunnels[0].Status = "up"
	}
	return out, nil
}

func TestIPsecMaintenanceActivePulseRepeatedSequenceAndWholeACK(t *testing.T) {
	f := newRecoveryObservedPollFake(t, "positive")
	valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
	if err != nil || !valid || f.acks != 5 || len(f.reports) != 9 || f.applyCount != 0 || !f.completed {
		t.Fatal("fresh pulses consumed maintained attempt or escaped whole ACK", valid, err, f.acks, len(f.reports))
	}
	sequences := map[uuid.UUID]uint64{}
	bgp := 0
	for _, r := range f.reports {
		if r.RecoveryVersion == nil {
			bgp++
			if r.SelectionSequence != nil || r.Tunnels[0].Selected || r.Tunnels[1].Selected {
				t.Fatal("static pulse changed BGP report semantics")
			}
			continue
		}
		if r.SelectionSequence == nil || *r.SelectionSequence != sequences[r.DeliveryID]+1 {
			t.Fatal("nonmonotonic repeated static report")
		}
		sequences[r.DeliveryID] = *r.SelectionSequence
	}
	if len(sequences) != 2 || bgp != 3 {
		t.Fatal("not the canonical two-static/three-BGP page")
	}
	assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
}

func TestIPsecMaintenanceActivePulseBindingAndAttemptRejection(t *testing.T) {
	for _, scenario := range []string{"unknown_delivery", "changed_material", "wrong_revision", "wrong_connection", "zero_sequence", "oversized_sequence", "duplicate", "duplicate_failed_http", "duplicate_maintained", "pulse_after_final_older", "parent_canceled", "final_digest", "changed_final_report"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRecoveryObservedPollFake(t, scenario)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.cancel = cancel
			f.reportFailure = scenario == "duplicate_failed_http"
			valid, err := PollIPsecRuntimeValidated(ctx, f, f)
			if err == nil || valid || f.acks != 0 || f.applyCount != 0 {
				t.Fatal("invalid telemetry/result acknowledged", valid, err, f.acks)
			}
			if scenario == "parent_canceled" && len(f.reports) != 0 {
				t.Fatal("pulse detached parent cancellation")
			}
			assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
		})
	}
}

func TestIPsecMaintenanceActivePulseHTTPFailureKeepsCompleteNativeACK(t *testing.T) {
	f := newRecoveryObservedPollFake(t, "positive")
	f.reportFailure = true
	valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
	if err == nil || valid || f.acks != 5 || f.applyCount != 0 {
		t.Fatal("independent HTTP telemetry failure revoked complete native result", valid, err, f.acks)
	}
	assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
}
