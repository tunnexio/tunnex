package ipsec

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type observedMaintenanceCore interface {
	maintainIPsecRuntimeObserved(context.Context, []RuntimeMaterial, func() *PermitLeaseAuthority, func() bool, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) ([]RuntimeMaintenanceResult, error)
}

// The fallback is the frozen controller's real whole-result return/publication
// ordering, not a second implementation of native observation or maintenance.
func runObservedMaintenance(r *renewalCycleRig, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error) ([]RuntimeMaintenanceResult, error) {
	if c, ok := any(r.c).(observedMaintenanceCore); ok {
		return c.maintainIPsecRuntimeObserved(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true }, publish)
	}
	results, err := r.c.maintainIPsecRuntime(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true })
	if err != nil {
		return results, err
	}
	for i, out := range results {
		if err := publish(context.Background(), r.materials[i].RuntimeDelivery, out.Report); err != nil {
			return nil, err
		}
	}
	return results, nil
}

func TestMaintainedNativeObservationDoesNotWaitForOtherReports(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	// This starts at the original combined commit: subsequent status IO must not
	// withhold an already completed earlier owner's observation. Native failure
	// stays unknown; the callback never invents an Up or forwarding assertion.
	committed := false
	commitStart := time.Duration(0)
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		out, err := replace(ctx, in)
		committed = err == nil
		commitStart = *r.now
		return out, err
	}
	observed, published := 0, 0
	r.c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
		if !committed {
			t.Fatal("status observed before original combined commit")
		}
		observed++
		r.charge("fresh_status_IO", 2300*time.Millisecond)
		if observed > 1 && published == 0 {
			t.Error("completed first native observation withheld during later owners' status IO")
		}
		return viciMessage{}, nil, errors.New("synthetic native refusal")
	}}
	r.c.config.IPPath = "/usr/bin/true"
	var arrivals []time.Duration
	results, err := runObservedMaintenance(r, func(ctx context.Context, d RuntimeDelivery, out RuntimeStatusReport) error {
		if !committed || out.DeliveryID != d.ID || out.DesiredRevision != d.DesiredRevision || out.Tunnels[0].Status != "unknown" || out.Tunnels[1].Status != "unknown" {
			t.Fatal("cached/mismatched positive telemetry")
		}
		published++
		arrivals = append(arrivals, *r.now-commitStart)
		return nil
	})
	t.Logf("actual native attempts=%d publication arrivals=%v", observed, arrivals)
	if err != nil || len(results) != 5 || observed != 5 || published != 5 {
		t.Fatalf("results=%d attempts=%d publication=%d err=%v", len(results), observed, published, err)
	}
	if arrivals[0] > 10*time.Second {
		t.Error("first fresh observation withheld beyond status age bound")
	}
}

func TestMaintainedObservationCallbackCannotAcknowledgeInvalidAuthority(t *testing.T) {
	for _, scenario := range []string{"canceled", "expired", "qualification", "replaced", "rejected"} {
		t.Run(scenario, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			originals := map[*PermitLeaseAuthority]time.Duration{}
			for _, a := range r.c.active {
				originals[a.Authority] = a.Authority.deadline
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			results, err := r.c.maintainIPsecRuntimeObserved(ctx, r.materials, maintenanceAuthority(r), func() bool { return true }, func(_ context.Context, d RuntimeDelivery, _ RuntimeStatusReport) error {
				calls++
				switch scenario {
				case "canceled":
					cancel()
				case "expired":
					r.charge("slow_HTTP", 61*time.Second)
				case "qualification":
					r.c.qualification.invalid = true
				case "replaced":
					delete(r.c.active, d.Manifest.ConnectionID)
				case "rejected":
					return errors.New("synthetic invalid binding")
				}
				return nil
			})
			if calls != 1 || err == nil || len(results) != 0 || len(r.c.active) != 0 {
				t.Fatal("invalid callback produced Apply results", calls, len(results), err)
			}
			for a, deadline := range originals {
				if a.deadline != deadline {
					t.Fatal("callback extended original authority")
				}
			}
		})
	}
}
func TestMaintainedObservedCompleteSetDeadlineStillGatesResults(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	var authorities []*PermitLeaseAuthority
	ctor := func() *PermitLeaseAuthority {
		a := maintenanceAuthority(r)()
		authorities = append(authorities, a)
		return a
	}
	calls := 0
	results, err := r.c.maintainIPsecRuntimeObserved(context.Background(), r.materials, ctor, func() bool { return true }, func(_ context.Context, d RuntimeDelivery, _ RuntimeStatusReport) error {
		calls++
		if calls == 5 {
			*r.now = authorities[0].deadline + time.Millisecond
		}
		return nil
	})
	if calls != 5 || len(authorities) != 5 || err == nil || len(results) != 0 || len(r.c.active) != 0 {
		t.Fatal("earlier candidate expired during later callback escaped full-set check")
	}
	if reflect.DeepEqual(authorities[0], authorities[4]) {
		t.Fatal("fixture did not exercise distinct candidate authorities")
	}
	if _, err := authorities[4].RemainingForApply(PermitLeaseIdentity{DeliveryID: r.materials[4].ID, Binding: r.entries[4].Engines[0].Binding, PolicyHash: r.materials[4].Policy.Hash}, time.Millisecond); err != nil {
		t.Fatal("last candidate must remain valid", err)
	}
}
