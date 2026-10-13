package ipsec

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"testing"
)

type testLeaseFailure string

func (e testLeaseFailure) Error() string                  { return "fixed test failure" }
func (e testLeaseFailure) IPsecLeaseFailureStage() string { return string(e) }
func TestMaintenanceLeaseLeafFirstPredicateSafety(t *testing.T) {
	for _, kind := range []string{"http_409", "http_409_ineligible", "http_409_conflict", "delivery", "revision", "policy", "nonce", "ttl", "active"} {
		t.Run(kind, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			base := r.c.client
			calls := 0
			events := []RuntimeDiagnostic{}
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
			r.c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
				calls++
				v, e := base.RenewIPsecLease(ctx, id, q)
				if e != nil {
					return v, e
				}
				switch kind {
				case "http_409", "http_409_ineligible", "http_409_conflict":
					return v, testLeaseFailure(kind)
				case "delivery":
					v.DeliveryID = uuid.New()
					v.DesiredRevision = -1
					v.PolicyHash = "wrong"
					v.Nonce = "wrong"
					v.TTLMS = 0
				case "revision":
					v.DesiredRevision = -1
					v.PolicyHash = "wrong"
					v.Nonce = "wrong"
					v.TTLMS = 0
				case "policy":
					v.PolicyHash = "wrong"
					v.Nonce = "wrong"
					v.TTLMS = 0
				case "nonce":
					v.Nonce = "wrong"
					v.TTLMS = 0
				case "ttl":
					v.TTLMS = 0
				case "active":
					delete(r.c.active, id)
				}
				return v, nil
			})
			result, e := r.c.maintainIPsecRuntime(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true })
			if e != ErrRuntimeController || len(result) != 0 || calls != 1 || len(r.c.active) != 0 {
				t.Fatalf("global refusal changed results=%d calls=%d active=%d err=%v", len(result), calls, len(r.c.active), e)
			}
			stages := []string{}
			for _, d := range events {
				if d.Operation == "maintenance" && d.Refused {
					stages = append(stages, d.Stage)
				}
			}
			if len(stages) != 1 || stages[0] != "maintenance_lease_"+kind {
				t.Fatalf("first refused predicate stages=%v", stages)
			}
		})
	}
}
func TestMaintenanceLeaseUnknownCategoryRefusesClosed(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	events := []RuntimeDiagnostic{}
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
	r.c.client = maintenanceLeaseFunc(func(context.Context, uuid.UUID, RuntimeLeaseRequest) (RuntimeLease, error) {
		return RuntimeLease{}, testLeaseFailure("private-secret-marker")
	})
	_, e := r.c.maintainIPsecRuntime(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true })
	if !errors.Is(e, ErrRuntimeController) || len(r.c.active) != 0 {
		t.Fatal("failure safety changed")
	}
	for _, d := range events {
		if d.Operation == "maintenance" && d.Refused && d.Stage != "maintenance_lease" {
			t.Fatal("unknown category exported", d.Stage)
		}
	}
}
