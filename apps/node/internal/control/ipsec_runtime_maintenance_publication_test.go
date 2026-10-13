package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

type observedMaintenancePollFake struct {
	*maintenancePollFake
	elapsed            time.Duration
	arrivals           []time.Duration
	observationChange  func(int, *ipsec.RuntimeDelivery, *ipsec.RuntimeStatusReport)
	finalChange        func([]ipsec.RuntimeMaintenanceResult) []ipsec.RuntimeMaintenanceResult
	publicationContext context.Context
	completed          bool
}

func newObservedMaintenancePollFake(t *testing.T) *observedMaintenancePollFake {
	f := &observedMaintenancePollFake{maintenancePollFake: newMaintenancePollFake(t)}
	// Three BGP and two static materials exercise both actual status contracts.
	for len(f.items) < 5 {
		f.item = ipsec.RuntimePending{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "apply"}
		f.bgp = true
		m, _ := f.runtimePollFake.IPsecMaterial(context.Background(), f.item.ConnectionID, 2)
		m.OwnershipDigest = "synthetic-owned-delivery"
		m.Secrets = [2]ipsec.RuntimeSecret{{PSK: "synthetic-private-test-value"}}
		f.items = append(f.items, f.item)
		f.materials[f.item.ConnectionID] = m
	}
	return f
}
func (f *observedMaintenancePollFake) MaintainIPsecRuntime(ctx context.Context, mats []ipsec.RuntimeMaterial) ([]ipsec.RuntimeMaintenanceResult, error) {
	out, err := f.maintenancePollFake.MaintainIPsecRuntime(ctx, mats)
	f.elapsed += 11 * time.Second
	f.completed = true
	return out, err
}
func (f *observedMaintenancePollFake) MaintainIPsecRuntimeObserved(ctx context.Context, mats []ipsec.RuntimeMaterial, publish func(context.Context, ipsec.RuntimeDelivery, ipsec.RuntimeStatusReport) error) ([]ipsec.RuntimeMaintenanceResult, error) {
	out, err := f.maintenancePollFake.MaintainIPsecRuntime(ctx, mats)
	if err != nil {
		return out, err
	}
	f.elapsed += time.Second // original native commit; no ACK has escaped
	for i, m := range mats {
		f.elapsed += 2 * time.Second // actual per-owner observation cost
		d, r := m.RuntimeDelivery, out[i].Report
		if f.observationChange != nil {
			f.observationChange(i, &d, &r)
		}
		pubCtx := ctx
		if f.publicationContext != nil {
			pubCtx = f.publicationContext
		}
		if err := publish(pubCtx, d, r); err != nil {
			return nil, err
		}
	}
	f.completed = true
	if f.finalChange != nil {
		out = f.finalChange(out)
	}
	return out, nil
}
func (f *observedMaintenancePollFake) IPsecReportStatus(ctx context.Context, id uuid.UUID, r ipsec.RuntimeStatusReport) error {
	if f.acks != 0 && !f.completed {
		return errors.New("ACK before complete result validation")
	}
	f.arrivals = append(f.arrivals, f.elapsed)
	return f.maintenancePollFake.IPsecReportStatus(ctx, id, r)
}
func (f *observedMaintenancePollFake) IPsecAcknowledge(ctx context.Context, id uuid.UUID, a ipsec.RuntimeAcknowledgement) error {
	if !f.completed {
		return errors.New("ACK before complete result validation")
	}
	return f.maintenancePollFake.IPsecAcknowledge(ctx, id, a)
}
func TestIPsecMaintainedObservationPublicationDoesNotWaitForBatch(t *testing.T) {
	f := newObservedMaintenancePollFake(t)
	valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
	t.Logf("five-owner accepted publication arrivals=%v ACKs=%d", f.arrivals, f.acks)
	if err != nil || !valid || f.acks != 5 || len(f.reports) != 5 || len(f.arrivals) != 5 {
		t.Fatal("missing streamed observations or complete ACKs", err)
	}
	if f.arrivals[0] >= 10*time.Second || f.arrivals[1] >= 10*time.Second {
		t.Fatal("fresh static reports withheld behind three BGP observations")
	}
	for _, r := range f.reports {
		if r.Tunnels[0].Status != "unknown" || r.Tunnels[1].Status != "down" {
			t.Fatal("cached healthy telemetry manufactured")
		}
	}
	assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
}
func TestIPsecMaintainedObservationBindingAndWholeACKValidation(t *testing.T) {
	for _, scenario := range []string{"unknown_delivery", "changed_material", "wrong_revision", "duplicate", "canceled", "final_digest", "changed_final_report"} {
		t.Run(scenario, func(t *testing.T) {
			f := newObservedMaintenancePollFake(t)
			switch scenario {
			case "unknown_delivery":
				f.observationChange = func(i int, d *ipsec.RuntimeDelivery, r *ipsec.RuntimeStatusReport) {
					if i == 0 {
						d.ID = uuid.New()
						r.DeliveryID = d.ID
					}
				}
			case "changed_material":
				f.observationChange = func(i int, d *ipsec.RuntimeDelivery, r *ipsec.RuntimeStatusReport) {
					if i == 0 {
						d.OwnershipDigest = "foreign"
					}
				}
			case "wrong_revision":
				f.observationChange = func(i int, d *ipsec.RuntimeDelivery, r *ipsec.RuntimeStatusReport) {
					if i == 0 {
						r.DesiredRevision++
					}
				}
			case "duplicate":
				var before ipsec.RuntimeDelivery
				var report ipsec.RuntimeStatusReport
				f.observationChange = func(i int, d *ipsec.RuntimeDelivery, r *ipsec.RuntimeStatusReport) {
					if i == 0 {
						before, report = *d, *r
					} else if i == 1 {
						*d, *r = before, report
					}
				}
			case "canceled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				f.publicationContext = ctx
			case "final_digest":
				f.finalChange = func(r []ipsec.RuntimeMaintenanceResult) []ipsec.RuntimeMaintenanceResult {
					r[4].Acknowledgement.OwnershipDigest = "foreign"
					return r
				}
			case "changed_final_report":
				f.finalChange = func(r []ipsec.RuntimeMaintenanceResult) []ipsec.RuntimeMaintenanceResult {
					r[0].Report.Tunnels[0].Status = "up"
					return r
				}
			}
			valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
			if err == nil || valid || f.acks != 0 || f.applyCount != 0 {
				t.Fatal("unvalidated observation/result acknowledged", err, f.acks)
			}
			assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
		})
	}
}
func TestIPsecMaintainedObservationRPCFailureDoesNotWithholdValidACK(t *testing.T) {
	f := newObservedMaintenancePollFake(t)
	f.reportFailure = true
	valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
	if err == nil || valid || f.acks != 5 || f.applyCount != 0 {
		t.Fatal("telemetry failure changed complete Apply ACK", err)
	}
	assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
}

func TestIPsecMaintainedObservationCannotDetachParentCancellation(t *testing.T) {
	f := newObservedMaintenancePollFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.publicationContext = context.Background()
	f.observationChange = func(i int, _ *ipsec.RuntimeDelivery, _ *ipsec.RuntimeStatusReport) {
		if i == 0 {
			cancel()
		}
	}
	valid, err := PollIPsecRuntimeValidated(ctx, f, f)
	if err == nil || valid || f.acks != 0 || len(f.reports) != 0 {
		t.Fatal("observer posted after owning Poll cancellation")
	}
	assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
}

func TestIPsecMaintainedObservationPreservesAzureGCPWire(t *testing.T) {
	for _, profile := range []string{ipsec.AzureActiveActiveBGPProfile, ipsec.AzureActiveStandbyBGPProfile, ipsec.GCPHABGPProfile} {
		for _, mismatch := range []bool{false, true} {
			t.Run(profile+map[bool]string{false: "/valid", true: "/changed-final"}[mismatch], func(t *testing.T) {
				f := newObservedMaintenancePollFake(t)
				id := f.items[0].ConnectionID
				m := f.materials[id]
				m.Manifest.ProfileID = profile
				version := 3
				if profile == ipsec.GCPHABGPProfile {
					version = 2
				}
				m.Manifest.BGPVersion = &version
				m.Manifest.BGP = &ipsec.BGPConfig{MaximumPrefixes: 64}
				for i := range m.Manifest.Tunnels {
					m.Manifest.Tunnels[i].Selected = false
				}
				if ipsec.IsSingleTunnelProfile(profile) {
					v, n := 1, 1
					m.Manifest.TransportVersion = &v
					m.Manifest.TunnelCount = &n
					m.Manifest.Tunnels[1] = ipsec.RuntimeTunnel{}
					m.Secrets[1] = ipsec.RuntimeSecret{}
				}
				f.materials[id] = m
				f.change = func(out []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
					out[0].Report.TransportVersion = m.Manifest.TransportVersion
					out[0].Report.TunnelCount = m.Manifest.TunnelCount
					if ipsec.IsSingleTunnelProfile(profile) {
						out[0].Report.Tunnels[1] = ipsec.RuntimeTunnelStatus{}
					}
					return out, nil
				}
				if mismatch {
					f.finalChange = func(out []ipsec.RuntimeMaintenanceResult) []ipsec.RuntimeMaintenanceResult {
						out[0].Report.Tunnels[0].Status = "down"
						return out
					}
				}
				valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
				if mismatch {
					if err == nil || valid || f.acks != 0 {
						t.Fatal("changed streamed final body acknowledged")
					}
				} else if err != nil || !valid || f.acks != 5 || len(f.reports) != 5 || f.applyCount != 0 {
					t.Fatal("provider wire lost", err, f.acks, len(f.reports))
				}
				assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
			})
		}
	}
}
