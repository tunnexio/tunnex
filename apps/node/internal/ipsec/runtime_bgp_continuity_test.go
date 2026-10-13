package ipsec

import (
	"context"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBGPApplyGuardRefreshRetainsOnlyUnchangedOldLease(t *testing.T) {
	for _, scenario := range []string{"unchanged", "withdraw", "policy", "expired", "cold", "processlost", "ownership", "routes"} {
		t.Run(scenario, func(t *testing.T) {
			c, f, p, _ := bgpControllerFixture(t, true)
			entries, _ := c.journal.Entries()
			e := entries[0]
			e.BGPProcess = &bgpengine.ProcessIdentity{Stage: "ready", Generation: 1}
			old := c.active[e.Allocation.ConnectionID]
			old.Entry = e
			c.active[e.Allocation.ConnectionID] = old
			env := old.Environment
			identity := old.Identity
			grants := old.Grants
			fresh := NewPermitLeaseAuthority()
			request, err := fresh.Begin(identity)
			if err != nil {
				t.Fatal(err)
			}
			if err = fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 60000}); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "withdraw":
				grants = nil
			case "policy":
				identity.PolicyHash = strings.Repeat("c", 64)
			case "expired":
				old.Authority.elapsed = func() time.Duration { return 61 * time.Second }
			case "cold":
				delete(c.active, e.Allocation.ConnectionID)
			case "processlost":
				p.closed = true
			case "ownership":
				env.Underlays[0].InterfaceIndex++
			case "routes":
				delete(f.routes[0], e.Allocation.Tunnels[0].RemotePrefixes[0].String())
			}
			var guards []GuardIntent
			c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
				guards = append(guards, in)
				return GuardManifest{}, nil
			}
			active, continuous, err := c.prepareBGPApplyActive(context.Background(), e, env, identity, fresh, grants, entries)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "unchanged" {
				if !continuous || active.Authority != old.Authority || !reflect.DeepEqual(active.Grants, old.Grants) || len(guards) != 0 {
					t.Fatal("unchanged refresh replaced old guard or extended authority before RIB")
				}
				p.routes = []bgpengine.LearnedRoute{{Prefix: e.Allocation.Tunnels[0].RemotePrefixes[0], Slot: 1}}
				if err := c.reconcileActiveBGP(context.Background(), entries); err != nil {
					t.Fatal(err)
				}
				if err := c.installActive(context.Background(), entries); err != nil {
					t.Fatal(err)
				}
				for _, g := range guards {
					if len(g.Connections) != 1 || len(g.Connections[0].Grants) == 0 || g.Connections[0].PermitFor <= 0 {
						t.Fatal("unchanged reconcile introduced denial")
					}
				}
			} else {
				if continuous || len(guards) == 0 {
					t.Fatal("changed apply skipped denial")
				}
				for _, g := range guards {
					for _, row := range g.Connections {
						if len(row.Grants) != 0 {
							t.Fatal("changed apply retained permission")
						}
					}
				}
			}
		})
	}
}
