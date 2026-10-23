package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

// Exercise the production maintenance entry after platform qualification using
// normal sealed material, a real journal/native guard, and finite CP leases.
// The local host cannot qualify FRR; kernel/daemon observations are test seams.
func maintainedMissingBGPChild(t *testing.T, selected int) (*renewalCycleRig, uuid.UUID, *recoveryKernelFixture) {
	t.Helper()
	r := newRenewalCycleRigInput(t, true, func(t *testing.T, c *RuntimeController, entries []RuntimeJournalEntry, materials []RuntimeMaterial) ([]RuntimeJournalEntry, []RuntimeMaterial) {
		e := entries[0]
		if e.ContractVersion != 3 {
			t.Fatal("first canonical owner must use BGP")
		}
		e.BGPRoutes.Owned = []RuntimeBGPRouteTuple{routeTupleFixture(e, uint8(selected))}
		e.BGPRoutes.Target = append([]RuntimeBGPRouteTuple(nil), e.BGPRoutes.Owned...)
		entries[0] = e
		a := c.active[e.Allocation.ConnectionID]
		a.Entry = e
		c.active[e.Allocation.ConnectionID] = a
		return entries, materials
	})
	e := r.entries[0]
	target := e.Allocation.ConnectionID
	r.c.bgpProcesses[e.DeliveryID].(*bgpSessionFixture).routes = []bgpengine.LearnedRoute{{Prefix: e.Allocation.Tunnels[0].RemotePrefixes[0], Slot: selected}}
	k := newRecoveryKernelFixture()
	k.p, k.owned = e.Allocation, e.Observed
	for i, tun := range k.p.Tunnels {
		k.routes[i] = map[string]bool{netip.PrefixFrom(tun.BGP.Peer, 32).String(): true}
	}
	for _, route := range e.BGPRoutes.Owned {
		k.routes[int(route.Slot)-1][route.Prefix.String()] = true
	}
	r.c.kernel = k.applier()
	r.c.recoveryObserve = func(_ context.Context, entry RuntimeJournalEntry) [2]string {
		r.charge("native_status", 800*time.Millisecond)
		states := [2]string{"up", "up"}
		if entry.Allocation.ConnectionID == target {
			states[2-selected] = "down"
		}
		return states
	}
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("qualified initial guard", err)
	}
	if err := r.c.kernel.verifyBGPRoutes(context.Background(), e.Allocation, e.Observed, e.BGPRoutes.Owned, true); err != nil {
		t.Fatal("exact initial native routes", err)
	}
	r.c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
		return viciMessage{}, nil, errors.New("status honestly unknown")
	}}
	r.c.config.IPPath = "/usr/bin/true"
	return r, target, k
}

func TestMaintainedMissingBGPChildRestoration(t *testing.T) {
	for _, selected := range []int{1, 2} {
		t.Run(string(rune('0'+selected)), func(t *testing.T) {
			r, target, k := maintainedMissingBGPChild(t, selected)
			old := map[uuid.UUID]runtimeActive{}
			deadlines := map[*PermitLeaseAuthority]time.Duration{}
			for id, a := range r.c.active {
				old[id] = cloneMaintenanceActive(a)
				deadlines[a.Authority] = a.Authority.deadline
			}
			commits, attempts := 0, 0
			published := false
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) { commits++; return replace(ctx, in) }
			r.c.recoveryInitiate = func(ctx context.Context, tun EngineTunnel) error {
				attempts++
				a := r.c.active[target]
				if commits != 1 || !published || tun.TunnelID != a.Entry.Engines[2-selected].TunnelID || a.Authority == old[target].Authority {
					t.Fatal("retry not exact missing child after fresh commit/publication")
				}
				if _, err := a.Authority.RemainingForApply(a.Identity, 2*time.Second); err != nil {
					t.Fatal(err)
				}
				if d, ok := ctx.Deadline(); !ok || time.Until(d) > 2*time.Second {
					t.Fatal("unbounded retry")
				}
				for id, previous := range old {
					current, ok := r.c.active[id]
					if !ok || !reflect.DeepEqual(previous.Entry, current.Entry) {
						t.Fatal("retry replaced existing owner")
					}
					if p := r.c.bgpProcesses[previous.Entry.DeliveryID]; p != nil && !p.Alive() {
						t.Fatal("retry closed healthy process")
					}
				}
				installed := map[string]time.Duration{}
				for key, value := range r.installed {
					installed[key] = value
				}
				deadline := a.Authority.deadline
				r.charge("retry_timeout", 2*time.Second)
				if !reflect.DeepEqual(installed, r.installed) || deadline != a.Authority.deadline {
					t.Fatal("initiation extended native authority")
				}
				return context.DeadlineExceeded
			}
			r.phase = "maintenance"
			results, err := r.c.maintainIPsecRuntimeObserved(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, func(_ context.Context, d RuntimeDelivery, _ RuntimeStatusReport) error {
				if d.Manifest.ConnectionID == target {
					published = true
				}
				return nil
			})
			r.phase = ""
			if err != nil || len(results) != 5 || len(r.c.active) != 5 {
				t.Fatal("maintenance not successful", len(results), err, len(r.c.active))
			}
			if attempts != 1 {
				t.Fatalf("successful maintenance skipped missing BGP child retry: attempts=%d", attempts)
			}
			if k.mutations != 0 {
				t.Fatal("retry mutated routes or interfaces")
			}
			for authority, deadline := range deadlines {
				if authority.deadline != deadline {
					t.Fatal("old deadline extended")
				}
			}
			for _, result := range results {
				if result.Report.DeliveryID == old[target].Entry.DeliveryID && result.Report.Tunnels[2-selected].Status == "up" {
					t.Fatal("attempt fabricated recovered status")
				}
			}
			r.c.retryMissingBGPChild(context.Background(), r.c.active[target].Entry)
			if attempts != 1 {
				t.Fatal("retry bypassed existing per-child pacing")
			}
		})
	}
}

func TestMaintainedMissingBGPChildPriorityRestoration(t *testing.T) {
	r, target, k := maintainedMissingBGPChild(t, 1)
	published, attempts := false, 0
	r.c.recoveryInitiate = func(_ context.Context, tun EngineTunnel) error {
		attempts++
		if !published || tun.TunnelID != r.c.active[target].Entry.Engines[1].TunnelID {
			t.Fatal("priority retry before publication or wrong owner")
		}
		return context.DeadlineExceeded
	}
	r.phase = "maintenance"
	err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, func(_ context.Context, d RuntimeDelivery, _ RuntimeStatusReport) error {
		if d.Manifest.ConnectionID == target {
			published = true
		}
		return nil
	}, nil)
	if err != nil || attempts != 1 || len(r.c.active) != 5 || k.mutations != 0 {
		t.Fatal("priority maintenance did not preserve guarded retry", err, attempts, len(r.c.active), k.mutations)
	}
}

func TestMaintainedMissingBGPChildInvalidInputsCannotInitiate(t *testing.T) {
	for _, scenario := range []string{"unknown", "already_up", "canceled", "qualification", "revoked", "expired", "wrong_owner", "process", "native_ownership", "rejected"} {
		t.Run(scenario, func(t *testing.T) {
			r, target, k := maintainedMissingBGPChild(t, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			attempts := 0
			r.c.recoveryInitiate = func(context.Context, EngineTunnel) error { attempts++; return nil }
			results, err := r.c.maintainIPsecRuntimeObserved(ctx, maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, func(_ context.Context, d RuntimeDelivery, _ RuntimeStatusReport) error {
				if d.Manifest.ConnectionID != target {
					return nil
				}
				switch scenario {
				case "unknown", "already_up":
					oldObserve := r.c.recoveryObserve
					r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
						if e.Allocation.ConnectionID == target {
							if scenario == "unknown" {
								return [2]string{"up", "unknown"}
							}
							return [2]string{"up", "up"}
						}
						return oldObserve(ctx, e)
					}
				case "canceled":
					cancel()
				case "qualification":
					r.c.qualification.invalid = true
				case "revoked":
					r.c.active[target].Authority.Invalidate()
				case "expired":
					r.charge("slow_publish", 61*time.Second)
				case "wrong_owner":
					a := r.c.active[target]
					a.Entry.Allocation.ConnectionID = uuid.New()
					r.c.active[target] = a
				case "process":
					r.c.bgpProcesses[d.ID].(*bgpSessionFixture).closed = true
				case "native_ownership":
					k.owned[1].InterfaceIndex++
				case "rejected":
					return errors.New("publication refused")
				}
				return nil
			})
			if attempts != 0 {
				t.Fatal("invalid/healthy child initiated", scenario, attempts)
			}
			switch scenario {
			case "canceled", "qualification", "revoked", "expired", "wrong_owner", "rejected":
				if err == nil || len(results) != 0 {
					t.Fatal("invalid publication acknowledged", scenario, len(results), err)
				}
			}
		})
	}
}

func TestMaintainedMissingBGPChildRetryCannotAcknowledgeExpiredCandidate(t *testing.T) {
	for _, scenario := range []string{"target_expiry", "earlier_owner_expiry", "canceled_during_retry"} {
		t.Run(scenario, func(t *testing.T) {
			r, target, _ := maintainedMissingBGPChild(t, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			attempts := 0
			r.c.recoveryInitiate = func(context.Context, EngineTunnel) error {
				attempts++
				switch scenario {
				case "target_expiry":
					r.charge("late_retry", 61*time.Second)
				case "earlier_owner_expiry":
					earliest := time.Duration(1<<63 - 1)
					for id, a := range r.c.active {
						if id != target && a.Authority.deadline < earliest {
							earliest = a.Authority.deadline
						}
					}
					*r.now = earliest + time.Millisecond
					a := r.c.active[target]
					if _, err := a.Authority.RemainingForApply(a.Identity, time.Millisecond); err != nil {
						t.Fatal("target must outlive earlier owner", err)
					}
				case "canceled_during_retry":
					cancel()
				}
				return context.DeadlineExceeded
			}
			results, err := r.c.maintainIPsecRuntimeObserved(ctx, maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, nil)
			if attempts != 1 || err == nil || len(results) != 0 || len(r.c.active) != 0 {
				t.Fatal("retry latency escaped final complete-set proof", attempts, len(results), err, len(r.c.active))
			}
		})
	}
}
