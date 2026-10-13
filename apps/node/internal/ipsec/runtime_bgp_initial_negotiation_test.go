package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// These tests exercise the real VICI initiation wrapper with synthetic lease,
// environment and kernel fixtures; they do not claim native CHILD negotiation.
func TestBGPInitialNegotiationIndependentRequests(t *testing.T) {
	for _, failedSlot := range []int{0, 1} {
		for _, timeout := range []bool{false, true} {
			t.Run(string(rune('1'+failedSlot))+map[bool]string{false: "-rejected", true: "-timeout"}[timeout], func(t *testing.T) {
				c, f, p, _ := bgpControllerFixture(t, false)
				entries, _ := c.journal.Entries()
				before := entries
				e := entries[0]
				a := c.active[e.Allocation.ConnectionID]
				delete(c.active, e.Allocation.ConnectionID)
				e.Phase = RuntimeApplying
				c.bgpStaged = map[uuid.UUID]bool{e.DeliveryID: true}
				c.config.Environment = &mtuEnvironmentFixture{env: a.Environment}
				now := time.Second
				c.recoveryClock = func() time.Duration { return now }
				statuses := [2]string{"down", "down"}
				c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return statuses }
				calls := []string{}
				c.config.Daemon = &DaemonClient{request: func(ctx context.Context, cmd, event string, m viciMessage) (viciMessage, []viciMessage, error) {
					child, _ := viciString(m, "child")
					calls = append(calls, child)
					if cmd != "initiate" {
						t.Fatalf("unexpected mutation %s", cmd)
					}
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > 2*time.Second {
						t.Fatal("unbounded request")
					}
					slot := 0
					if child == engineName(e.Engines[1]) {
						slot = 1
					}
					if c.bgpRetries[e.DeliveryID][slot].TunnelID != e.Engines[slot].TunnelID {
						t.Fatal("unknown outcome not paced before request")
					}
					if slot == failedSlot {
						if timeout {
							return nil, nil, context.DeadlineExceeded
						}
						return viciMessage{"success": viciText("no")}, nil, nil
					}
					return viciMessage{"success": viciText("yes")}, nil, nil
				}}
				invoke := func() {
					t.Helper()
					if err := c.initiateStagedBGPChildren(context.Background(), e, a.Environment, a.Authority, a.Identity); err != nil {
						t.Fatal(err)
					}
				}
				invoke()
				if !reflect.DeepEqual(calls, []string{engineName(e.Engines[0]), engineName(e.Engines[1])}) {
					t.Fatal(calls)
				}
				invoke()
				now += 29 * time.Second
				invoke()
				if len(calls) != 2 {
					t.Fatal("unpaced retry")
				}
				now += time.Second
				invoke()
				if len(calls) != 4 {
					t.Fatal("Applying peers never retried")
				}
				statuses = [2]string{"up", "down"}
				now += 30 * time.Second
				invoke()
				if len(calls) != 5 || calls[4] != engineName(e.Engines[1]) {
					t.Fatal("healthy peer reinitiated")
				}
				after, _ := c.journal.Entries()
				if !reflect.DeepEqual(before, after) || f.mutations != 0 || !c.bgpStaged[e.DeliveryID] || p.closed || len(c.active) != 0 {
					t.Fatal("negotiation changed durable staging/kernel/authority")
				}
			})
		}
	}
}

func TestBGPInitialNegotiationRefusesLostProof(t *testing.T) {
	for _, loss := range []string{"unknown", "context", "lease", "environment", "namespace", "ownership", "qualification", "daemon"} {
		t.Run(loss, func(t *testing.T) {
			c, f, _, _ := bgpControllerFixture(t, false)
			entries, _ := c.journal.Entries()
			e := entries[0]
			before := entries
			a := c.active[e.Allocation.ConnectionID]
			delete(c.active, e.Allocation.ConnectionID)
			e.Phase = RuntimeApplying
			env := &mtuEnvironmentFixture{env: a.Environment}
			c.config.Environment = env
			c.bgpStaged = map[uuid.UUID]bool{e.DeliveryID: true}
			c.recoveryClock = func() time.Duration { return time.Second }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			lost := false
			c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
				if loss == "unknown" {
					return [2]string{"unknown", "down"}
				}
				return [2]string{"down", "down"}
			}
			c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
				calls++
				lost = true
				switch loss {
				case "context":
					cancel()
				case "lease":
					a.Authority.elapsed = func() time.Duration { return 61 * time.Second }
				case "environment":
					env.drift = true
				case "namespace":
					c.namespace = func() (string, error) { return "net:[999999]", nil }
				case "ownership":
					f.owned[1].InterfaceIndex++
				case "qualification":
					c.qualification.alive = func() bool { return false }
				case "daemon":
					c.config.DaemonAlive = func() bool { return !lost }
				}
				return nil, nil, context.DeadlineExceeded
			}}
			if err := c.initiateStagedBGPChildren(ctx, e, a.Environment, a.Authority, a.Identity); err == nil {
				t.Fatal("lost proof accepted")
			}
			expected := 1
			if loss == "unknown" {
				expected = 0
			}
			if calls != expected {
				t.Fatalf("requests %d want %d", calls, expected)
			}
			after, _ := c.journal.Entries()
			if !reflect.DeepEqual(before, after) || f.mutations != 0 || !c.bgpStaged[e.DeliveryID] {
				t.Fatal("refusal mutated staging")
			}
		})
	}
}

func TestBGPInitialNegotiationFinalHealthFreshness(t *testing.T) {
	for _, loss := range []string{"namespace", "qualification", "daemon", "lease", "context"} {
		t.Run(loss, func(t *testing.T) {
			c, _, _, _ := bgpControllerFixture(t, false)
			entries, _ := c.journal.Entries()
			e := entries[0]
			a := c.active[e.Allocation.ConnectionID]
			delete(c.active, e.Allocation.ConnectionID)
			e.Phase = RuntimeApplying
			c.config.Environment = &mtuEnvironmentFixture{env: a.Environment}
			c.bgpStaged = map[uuid.UUID]bool{e.DeliveryID: true}
			c.recoveryClock = func() time.Duration { return time.Second }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			samples, calls := 0, 0
			c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
				samples++
				if samples == 2 {
					switch loss {
					case "namespace":
						c.namespace = func() (string, error) { return "net:[999999]", nil }
					case "qualification":
						c.qualification.alive = func() bool { return false }
					case "daemon":
						c.config.DaemonAlive = func() bool { return false }
					case "lease":
						a.Authority.elapsed = func() time.Duration { return 61 * time.Second }
					case "context":
						cancel()
					}
				}
				return [2]string{"down", "down"}
			}
			c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
				calls++
				return viciMessage{"success": viciText("yes")}, nil, nil
			}}
			if err := c.initiateStagedBGPChildren(ctx, e, a.Environment, a.Authority, a.Identity); err == nil || calls != 1 {
				t.Fatalf("late %s loss: err=%v requests=%d", loss, err, calls)
			}
			if c.bgpRetries[e.DeliveryID][1].TunnelID != uuid.Nil {
				t.Fatal("refused request recorded as attempted")
			}
		})
	}
}
