package policy_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/gatewaymesh"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

func TestCrossGatewayPreservesRulesForHumansAndAgents(t *testing.T) {
	for _, sourceKind := range []string{"human", "agent"} {
		for _, destinationKind := range []string{"human", "agent"} {
			t.Run(sourceKind+"_to_"+destinationKind, func(t *testing.T) {
				a, b, relay := uuid.New(), uuid.New(), uuid.New()
				owner, sourceID, destinationID, resource, rule := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
				graph, err := gatewaymesh.Build(true, []gatewaymesh.Gateway{{ID: a, PublicKey: "a"}, {ID: b, PublicKey: "b"}, {ID: relay, PublicKey: "relay", Endpoint: "relay.example:51820"}}, []gatewaymesh.Client{{NodeID: a, Address: "10.99.0.2", IPv6Address: "fd99::2"}, {NodeID: b, Address: "10.99.0.3", IPv6Address: "fd99::3"}}, nil)
				if err != nil {
					t.Fatal(err)
				}
				snap := policy.Snapshot{Mode: policy.ModeEnforcing, CrossGatewayGraph: graph, Devices: []policy.Device{{ID: sourceID, UserID: owner, NodeID: a, AssignedIP: "10.99.0.2", Kind: sourceKind}, {ID: destinationID, UserID: uuid.New(), NodeID: b, AssignedIP: "10.99.0.3", Kind: destinationKind}}, Resources: []policy.Resource{{ID: resource, CIDR: "10.99.0.3/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}}}
				for _, artifact := range policy.Compile(snap) {
					if artifact.Mesh || len(artifact.Allow) != 0 {
						t.Fatal("transport opt-in invented permission")
					}
				}
				r := policy.Rule{ID: rule, SrcKind: "user", SrcUserID: owner, DstKind: "resource", DstResourceID: resource}
				if sourceKind == "agent" {
					r.SrcKind = "agent"
					r.SrcDeviceID = sourceID
					r.SrcUserID = uuid.Nil
				}
				snap.Rules = []policy.Rule{r}
				out := policy.Compile(snap)
				for _, node := range []uuid.UUID{a, b, relay} {
					allows := out[node].Allow
					if len(allows) != 1 || allows[0].SrcIP != "10.99.0.2" || allows[0].DstCIDR != "10.99.0.3/32" || allows[0].PortLow != 443 || allows[0].PortHigh != 443 || allows[0].RuleID != rule.String() {
						t.Fatalf("scoped grant missing on path: %+v", out[node])
					}
					if hasAllow(allows, "fd99::2", "fd99::3/128") {
						t.Fatalf("IPv4 destination grant widened to IPv6: %+v", allows)
					}
					if out[node].Mesh {
						t.Fatal("opt-in switched enforcing to mesh")
					}
				}
				v6Resource := uuid.New()
				snap.Resources = append(snap.Resources, policy.Resource{ID: v6Resource, CIDR: "fd99::3/128", Protocol: "tcp", PortLow: 443, PortHigh: 443})
				v6Rule := r
				v6Rule.ID = uuid.New()
				v6Rule.DstResourceID = v6Resource
				snap.Rules = append(snap.Rules, v6Rule)
				for _, artifact := range policy.Compile(snap) {
					if !hasAllow(artifact.Allow, "fd99::2", "fd99::3/128") {
						t.Fatalf("explicit IPv6 destination missing: %+v", artifact)
					}
				}
				snap.CrossGatewayGraph = nil
				off := policy.Compile(snap)
				if len(off[b].Allow) != 0 || len(off[relay].Allow) != 0 {
					t.Fatal("disable retained remote authorization")
				}
			})
		}
	}
}
