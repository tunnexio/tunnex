package ipsec

import (
	"context"
	"encoding/json"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestBGPApplyThirdAliveLossDeniesBeforeCleanup(t *testing.T) {
	for _, denyFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "denial-proven", true: "denial-failed"}[denyFailure], func(t *testing.T) {
			c, _, p, denied := bgpControllerFixture(t, true)
			e := checkpointControllerProcess(t, c)
			entries, _ := c.journal.Entries()
			old := c.active[e.Allocation.ConnectionID]
			old.Entry = e
			c.active[e.Allocation.ConnectionID] = old
			fresh := NewPermitLeaseAuthority()
			request, err := fresh.Begin(old.Identity)
			if err != nil {
				t.Fatal(err)
			}
			if fresh.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 60000}) != nil {
				t.Fatal("fresh fixture lease")
			}
			aliveCalls := 0
			p.alive = func() bool { aliveCalls++; return aliveCalls < 3 }
			var installCalls, cleanupCalls int
			c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
				installCalls++
				for _, g := range in.Connections {
					if len(g.Grants) > 0 {
						t.Fatal("stale grants survived death")
					}
				}
				if denyFailure {
					return GuardManifest{}, ErrRuntimeController
				}
				*denied = true
				return GuardManifest{}, nil
			}
			c.bgpRecover = func(bgpengine.ProcessIdentity) error {
				cleanupCalls++
				if !*denied {
					t.Fatal("process proof before denial")
				}
				return nil
			}
			active, continuous, err := c.prepareBGPApplyActive(context.Background(), e, old.Environment, old.Identity, fresh, old.Grants, entries)
			if err != nil || !continuous || installCalls != 0 || aliveCalls != 2 {
				t.Fatal("fixture did not reach exact unchanged two-check state", err, aliveCalls)
			}
			if p.Alive() {
				t.Fatal("third liveness loss not injected")
			}
			// Production dead-session branch calls this exact denial seam before the
			// existing known-session cleanup, and cancels continuity before the call.
			continuous = false
			active, err = c.denyBGPApplySessionCleanup(context.Background(), active, old.Identity, fresh, entries)
			if denyFailure {
				if err == nil || p.closed || cleanupCalls != 0 || installCalls != 1 {
					t.Fatal("denial failure cleaned owned process")
				}
				after, _ := c.journal.Entries()
				if !reflect.DeepEqual(after[0].BGPProcess, e.BGPProcess) {
					t.Fatal("denial failure erased obligation")
				}
				return
			}
			if err != nil || continuous || len(active.Grants) != 0 || active.Authority != fresh || installCalls != 1 {
				t.Fatal("dead session retained stale active state")
			}
			if c.finishKnownBGPSession(e) != nil {
				t.Fatal("known cleanup refused")
			}
			if !p.closed || cleanupCalls != 1 || !*denied {
				t.Fatal("cleanup not ordered after proof")
			}
			if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
				t.Fatal("old lease mutated instead of separately denying")
			}
		})
	}
}
func TestGuardMSSCapturedNativeFlagsExpression(t *testing.T) {
	raw, err := os.ReadFile("testdata/nft_mss_native_expression.json")
	if err != nil {
		t.Fatal(err)
	}
	g := guardFixture().Connections[0].Grants[0]
	rule, ok := guardMSSRule(guardAllow(g, 2, 10, false, "lease_test", "oif"), []GuardTunnelMTU{{10, 1422}})
	if !ok {
		t.Fatal("clamp missing")
	}
	encoded, _ := json.Marshal(rule.expr[len(rule.expr)-4:])
	var want, got any
	if json.Unmarshal(raw, &want) != nil || json.Unmarshal(encoded, &got) != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("renderer differs from actual native flag mask grammar")
	}
}
