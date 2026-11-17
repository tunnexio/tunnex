package control

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

func TestIPsecMaintenanceRetainedEnvelope(t *testing.T) {
	for _, mode := range []string{"all-retained", "mixed-applied", "mixed-pending", "unknown", "revision", "ownership", "connection", "configuration", "kind", "manifest", "duplicate-retained", "duplicate-applied-first", "duplicate-retained-first", "deferred", "ack", "report", "error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newMaintenancePollFake(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.change = func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
				raw, _ := json.Marshal(f.materials[f.items[1].ConnectionID].RuntimeDelivery)
				var d ipsec.RuntimeDelivery
				if err := json.Unmarshal(raw, &d); err != nil {
					t.Fatal(err)
				}
				out := []ipsec.RuntimeMaintenanceResult{r[0], {Retained: &d}}
				first := f.materials[f.items[0].ConnectionID].RuntimeDelivery
				switch mode {
				case "all-retained":
					out[0] = ipsec.RuntimeMaintenanceResult{Retained: &first}
				case "mixed-pending":
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
				case "duplicate-retained":
					out[0] = out[1]
				case "duplicate-applied-first":
					out[0] = r[1]
				case "duplicate-retained-first":
					out = []ipsec.RuntimeMaintenanceResult{out[1], r[1]}
				case "deferred":
					out[1].Deferred = &d
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
			case "all-retained", "mixed-pending":
				if err != nil || !valid || f.acks != 0 || len(f.reports) != 0 || f.applyCount != 0 {
					t.Fatal("validated retained owner fabricated apply or pending acknowledgement", valid, err)
				}
			case "mixed-applied":
				if err != nil || !valid || f.acks != 1 || len(f.reports) != 1 || f.applyCount != 0 {
					t.Fatal("independently applied sibling lost", valid, err)
				}
			default:
				if err == nil || valid || f.acks != 0 || len(f.reports) != 0 || f.applyCount != 0 {
					t.Fatal("malformed retained result escaped whole-page fence", valid, err)
				}
			}
			assertMaintenanceSecretsCleared(t, f)
		})
	}
}

func TestIPsecMaintenanceRetainedRejectsPublishedObservation(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "published", true: "failed-publication"}[failed], func(t *testing.T) {
			f := newObservedMaintenancePollFake(t)
			f.reportFailure = failed
			f.finalChange = func(out []ipsec.RuntimeMaintenanceResult) []ipsec.RuntimeMaintenanceResult {
				d := f.materials[f.items[0].ConnectionID].RuntimeDelivery
				out[0] = ipsec.RuntimeMaintenanceResult{Retained: &d}
				return out
			}
			valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
			if err == nil || valid || f.acks != 0 || f.applyCount != 0 || len(f.reports) != len(f.items) {
				t.Fatal("published observation relabeled as retained", valid, err)
			}
			assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
		})
	}
}
