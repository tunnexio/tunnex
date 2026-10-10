package ipsec

import (
	"context"
	"net/netip"
	"strconv"
	"testing"
)

type mtuEnvironmentFixture struct {
	env   RuntimeEnvironment
	drift bool
}

func (f *mtuEnvironmentFixture) Observe(context.Context, KernelAllocation, [2]EngineTunnel) (RuntimeEnvironment, error) {
	if f.drift {
		return RuntimeEnvironment{}, ErrRuntimeEnvironment
	}
	return f.env, nil
}
func (f *mtuEnvironmentFixture) Drain(context.Context, []RuntimeJournalEntry) error { return nil }
func TestUnderlayMTUControllerDeniesOnlyWhenLowering(t *testing.T) {
	for _, scenario := range []string{"unchanged", "lower", "denialfailed", "drift"} {
		t.Run(scenario, func(t *testing.T) {
			c, f, _, _ := bgpControllerFixture(t, true)
			entries, _ := c.journal.Entries()
			e := entries[0]
			active := c.active[e.Allocation.ConnectionID]
			env := active.Environment
			for i := range env.Underlays {
				env.Underlays[i].OuterMTU = 1500
				env.Underlays[i].LocalAddress = netip.MustParseAddr("192.0.2.1")
			}
			if scenario != "unchanged" {
				env.Underlays[0].OuterMTU = 1300
			}
			observed := &mtuEnvironmentFixture{env: env, drift: scenario == "drift"}
			c.config.Environment = observed
			writes := 0
			denials := 0
			oldrun := c.kernel.run
			c.kernel.run = func(ctx context.Context, args ...string) ([]byte, error) {
				if len(args) == 6 && args[0] == "link" && args[4] == "mtu" {
					writes++
					if denials == 0 {
						t.Fatal("MTU changed before guard denial")
					}
					for i, tun := range f.p.Tunnels {
						if tun.Name == args[3] {
							v, _ := strconv.ParseUint(args[5], 10, 64)
							f.mtu[i] = v
						}
					}
					return nil, nil
				}
				return oldrun(ctx, args...)
			}
			c.replace = func(_ context.Context, g GuardIntent) (GuardManifest, error) {
				denials++
				for _, r := range g.Connections {
					if r.ID == e.Allocation.ConnectionID && len(r.Grants) > 0 {
						t.Fatal("lowering retained own application grants")
					}
				}
				if scenario == "denialfailed" {
					return GuardManifest{}, ErrRuntimeController
				}
				return GuardManifest{}, nil
			}
			lower, err := c.ensureUnderlayMTUs(context.Background(), e, env, entries)
			switch scenario {
			case "unchanged":
				if err != nil || lower || writes != 0 || denials != 0 || len(c.active[e.Allocation.ConnectionID].Grants) == 0 {
					t.Fatal("steady MTU refresh denied grants")
				}
			case "lower":
				if err != nil || !lower || writes != 1 || f.mtu[0] != 1230 {
					t.Fatal("qualified lowering failed", err)
				}
				if _, ok := c.active[e.Allocation.ConnectionID]; ok {
					t.Fatal("lowered connection reauthorized itself")
				}
			default:
				if err == nil || writes != 0 {
					t.Fatal("failed evidence mutated owned MTU")
				}
			}
		})
	}
}

func TestStaticRecoveryApplyLowersOuterMTUBeforeGrant(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	entries, _ := r.c.journal.Entries()
	e := entries[0]
	r.env.Underlays[0].OuterMTU = 1300
	r.c.recoveryPrepared[e.DeliveryID] = r.env
	r.c.config.Environment = &mtuEnvironmentFixture{env: r.env}
	f := newRecoveryKernelFixture()
	f.p, f.owned = e.Allocation, e.Observed
	f.routes = [2]map[string]bool{{}, {}}
	a := f.applier()
	run := a.run
	writes := 0
	a.run = func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) == 6 && args[0] == "link" && args[4] == "mtu" {
			if len(r.events) == 0 || r.events[len(r.events)-1] != "deny" {
				t.Fatal("recovery controller MTU write preceded denial")
			}
			writes++
			for i, tun := range f.p.Tunnels {
				if tun.Name == args[3] {
					v, _ := strconv.ParseUint(args[5], 10, 64)
					f.mtu[i] = v
				}
			}
			return nil, nil
		}
		return run(ctx, args...)
	}
	r.c.kernel = a
	ack, err := r.c.applyRecovery(context.Background(), r.m, entries, 0, r.env, []GuardGrant{{Source: e.Engines[0].LocalPrefixes[0], Destination: e.Engines[0].RemotePrefixes[0], Protocol: GuardTCP, PortLow: 18080, PortHigh: 18080}})
	if err != nil || ack.Result != "applied" || writes != 1 || f.mtu[0] != 1230 {
		t.Fatal("recovery controller failed lower-underlay", err, ack)
	}
	if len(r.events) < 2 || r.events[len(r.events)-1] != "permit" {
		t.Fatal("fresh grant was not restored after exact lowering")
	}
}
