package control

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
)

func TestIPsecMaintenanceDeferredEnvelope(t *testing.T) {
	for _, mode := range []string{"pending-only", "mixed", "unknown", "revision", "ownership", "connection", "configuration", "kind", "manifest", "duplicate-deferred", "duplicate-applied-first", "duplicate-deferred-first", "ack", "report", "error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newMaintenancePollFake(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.change = func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
				// Deep copy the fetched page, so tampering cannot mutate its validation basis.
				raw, _ := json.Marshal(f.materials[f.items[1].ConnectionID].RuntimeDelivery)
				var d ipsec.RuntimeDelivery
				if err := json.Unmarshal(raw, &d); err != nil {
					t.Fatal(err)
				}
				out := []ipsec.RuntimeMaintenanceResult{r[0], {Deferred: &d}}
				switch mode {
				case "pending-only":
					first := f.materials[f.items[0].ConnectionID].RuntimeDelivery
					out[0] = ipsec.RuntimeMaintenanceResult{Deferred: &first}
				case "unknown":
					d.ID = uuid.New()
				case "revision":
					d.DesiredRevision++
				case "ownership":
					d.OwnershipDigest = "changed"
				case "connection":
					d.Manifest.ConnectionID = uuid.New()
				case "configuration":
					d.Manifest.ConfigurationRevision++
				case "kind":
					d.Kind = "cleanup"
				case "manifest":
					d.Manifest.RemotePrefixes = []string{"192.0.2.0/24"}
				case "duplicate-deferred":
					out[0] = out[1]
				case "duplicate-applied-first":
					out[0] = r[1]
				case "duplicate-deferred-first":
					out = []ipsec.RuntimeMaintenanceResult{out[1], r[1]}
				case "ack":
					out[1].Acknowledgement = r[1].Acknowledgement
				case "report":
					out[1].Report = r[1].Report
				case "error":
					return out, errors.New("refused")
				case "cancel":
					cancel()
				}
				return out, nil
			}
			valid, err := PollIPsecRuntimeValidated(ctx, f, f)
			switch mode {
			case "pending-only":
				if err != nil || valid || f.acks != 0 || len(f.reports) != 0 || f.applyCount != 0 {
					t.Fatal("deferred-only fabricated completion", valid, err)
				}
			case "mixed":
				if err != nil || !valid || f.acks != 1 || len(f.reports) != 1 || f.applyCount != 0 {
					t.Fatal("independent sibling lost", valid, err)
				}
			default:
				if err == nil || valid || f.acks != 0 || len(f.reports) != 0 || f.applyCount != 0 {
					t.Fatal("invalid envelope escaped whole-batch fence", valid, err)
				}
			}
			assertMaintenanceSecretsCleared(t, f)
		})
	}
}

func TestIPsecMaintenanceDeferredRejectsPublishedObservation(t *testing.T) {
	for _, reportFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "published", true: "observed-rpc-failed"}[reportFailure], func(t *testing.T) {
			f := newObservedMaintenancePollFake(t)
			f.reportFailure = reportFailure
			f.finalChange = func(out []ipsec.RuntimeMaintenanceResult) []ipsec.RuntimeMaintenanceResult {
				d := f.materials[f.items[0].ConnectionID].RuntimeDelivery
				out[0] = ipsec.RuntimeMaintenanceResult{Deferred: &d}
				return out
			}
			valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
			if err == nil || valid || f.acks != 0 || f.applyCount != 0 || len(f.reports) != len(f.items) {
				t.Fatal("deferred after observed result accepted", valid, err)
			}
			assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
		})
	}
}
