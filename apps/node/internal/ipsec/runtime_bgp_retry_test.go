package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestBGPChildRetryPreservesHealthyAuthorityAndPacesUnknownOutcome(t *testing.T) {
	for _, statuses := range [][2]string{{"up", "down"}, {"down", "up"}} {
		t.Run(statuses[0], func(t *testing.T) {
			c, f, p, _ := bgpControllerFixture(t, false)
			entries, _ := c.journal.Entries()
			e := entries[0]
			id := e.Allocation.ConnectionID
			before := c.active[id]
			c.config.Environment = &mtuEnvironmentFixture{env: before.Environment}
			c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return statuses }
			now := time.Second
			c.recoveryClock = func() time.Duration { return now }
			calls := 0
			c.recoveryInitiate = func(ctx context.Context, tunnel EngineTunnel) error {
				calls++
				target := 1
				if statuses[0] == "down" {
					target = 0
				}
				if tunnel.TunnelID != e.Engines[target].TunnelID {
					t.Fatal("wrongslot")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 2*time.Second {
					t.Fatal("unboundedinitiate")
				}
				if !reflect.DeepEqual(c.active[id], before) || p.closed {
					t.Fatal("healthygrantdisarmed")
				}
				return context.DeadlineExceeded
			}
			c.retryMissingBGPChild(context.Background(), e)
			c.retryMissingBGPChild(context.Background(), e)
			if calls != 1 {
				t.Fatal("unknownoutcome repeated", calls)
			}
			now += 29 * time.Second
			c.retryMissingBGPChild(context.Background(), e)
			if calls != 1 {
				t.Fatal("earlyretry")
			}
			now += time.Second
			c.retryMissingBGPChild(context.Background(), e)
			if calls != 2 || f.mutations != 0 || p.closed || !reflect.DeepEqual(c.active[id], before) {
				t.Fatal("retrychangedhealthyresources", calls)
			}
		})
	}
}
func TestBGPChildRetryRefusesAmbiguousOrExpiredEvidence(t *testing.T) {
	for _, scenario := range []string{"unknown", "bothup", "bothdown", "expired", "drift", "ownership", "process", "changed", "slow"} {
		t.Run(scenario, func(t *testing.T) {
			c, f, p, _ := bgpControllerFixture(t, false)
			entries, _ := c.journal.Entries()
			e := entries[0]
			active := c.active[e.Allocation.ConnectionID]
			env := &mtuEnvironmentFixture{env: active.Environment}
			c.config.Environment = env
			states := [2]string{"up", "down"}
			count := 0
			now := time.Second
			c.recoveryClock = func() time.Duration { return now }
			c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
				count++
				if scenario == "changed" && count > 1 {
					return [2]string{"up", "unknown"}
				}
				if scenario == "slow" {
					now += 6 * time.Second
				}
				return states
			}
			calls := 0
			c.recoveryInitiate = func(context.Context, EngineTunnel) error { calls++; return nil }
			switch scenario {
			case "unknown":
				states = [2]string{"up", "unknown"}
			case "bothup":
				states = [2]string{"up", "up"}
			case "bothdown":
				states = [2]string{"down", "down"}
			case "expired":
				active.Authority.elapsed = func() time.Duration { return 61 * time.Second }
			case "drift":
				env.drift = true
			case "ownership":
				f.owned[1].InterfaceIndex++
			case "process":
				p.closed = true
			}
			c.retryMissingBGPChild(context.Background(), e)
			if calls != 0 {
				t.Fatal("unsafeinitiation", scenario)
			}
		})
	}
}
func TestBGPAllDownRetryRequiresProvedDenialAndEmptyRouteDuty(t *testing.T) {
	for _, scenario := range []string{"retry", "denialfail", "expired", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			c, f, _, denied := bgpControllerFixture(t, true)
			entries, _ := c.journal.Entries()
			e := entries[0]
			active := c.active[e.Allocation.ConnectionID]
			c.config.Environment = &mtuEnvironmentFixture{env: active.Environment}
			c.recoveryClock = func() time.Duration { return time.Second }
			// Transport negotiation does not require an absent BGP session to restart.
			delete(c.bgpProcesses, e.DeliveryID)
			states := [2]string{"down", "down"}
			if scenario == "unknown" {
				states = [2]string{"down", "unknown"}
			}
			c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return states }
			if scenario == "denialfail" {
				c.replace = func(context.Context, GuardIntent) (GuardManifest, error) { return GuardManifest{}, ErrGuardReadback }
			}
			if scenario == "expired" {
				active.Authority.elapsed = func() time.Duration { return 61 * time.Second }
			}
			beforeMutations := f.mutations
			slots := []int{}
			c.recoveryInitiate = func(_ context.Context, tunnel EngineTunnel) error {
				if !*denied || len(c.active) != 0 {
					t.Fatal("retrybeforedenial")
				}
				fresh, _ := c.journal.Entries()
				if len(fresh[0].BGPRoutes.Owned) != 0 || len(fresh[0].BGPRoutes.Target) != 0 {
					t.Fatal("routeauthorityretained")
				}
				slot := 1
				if tunnel.TunnelID == e.Engines[1].TunnelID {
					slot = 2
				}
				slots = append(slots, slot)
				return context.DeadlineExceeded
			}
			allDown, err := c.retryAllDownBGPChildren(context.Background(), e, active.Environment, active.Authority, active.Identity, entries)
			if scenario == "retry" {
				if !allDown || err != nil || !reflect.DeepEqual(slots, []int{1}) {
					t.Fatal("allDownretry", allDown, err, slots)
				}
				fresh, _ := c.journal.Entries()
				if _, err := c.retryAllDownBGPChildren(context.Background(), fresh[0], active.Environment, active.Authority, active.Identity, fresh); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(slots, []int{1, 2}) {
					t.Fatal("oneattimepacing", slots)
				}
			} else {
				if len(slots) != 0 {
					t.Fatal("unsafeallDownretry")
				}
				if scenario == "denialfail" && f.mutations != beforeMutations {
					t.Fatal("mutationwithoutdenial")
				}
			}
		})
	}
}

func TestBGPChildRetryFinalObservationDiscontinuitySkipsInitiation(t *testing.T) {
	for _, scenario := range []string{"session", "namespace", "qualification", "daemon"} {
		t.Run(scenario, func(t *testing.T) {
			c, _, p, _ := bgpControllerFixture(t, false)
			entries, _ := c.journal.Entries()
			e := entries[0]
			before := c.active[e.Allocation.ConnectionID]
			c.config.Environment = &mtuEnvironmentFixture{env: before.Environment}
			c.recoveryClock = func() time.Duration { return time.Second }
			alive := true
			c.config.DaemonAlive = func() bool { return alive }
			samples := 0
			c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
				samples++
				if samples == 2 {
					switch scenario {
					case "session":
						p.closed = true
					case "namespace":
						c.namespace = func() (string, error) { return "net:[999999]", nil }
					case "qualification":
						c.qualification.alive = func() bool { return false }
					case "daemon":
						alive = false
					}
				}
				return [2]string{"up", "down"}
			}
			attempts := 0
			c.recoveryInitiate = func(context.Context, EngineTunnel) error { attempts++; return nil }
			c.retryMissingBGPChild(context.Background(), e)
			if samples != 2 || attempts != 0 || !reflect.DeepEqual(before, c.active[e.Allocation.ConnectionID]) {
				t.Fatal("late discontinuity initiated or changedhealthygrant", samples, attempts)
			}
			if history := c.bgpRetries[e.DeliveryID]; history[1].TunnelID == e.Engines[1].TunnelID {
				t.Fatal("unissuedattemptrecorded")
			}
		})
	}
}
