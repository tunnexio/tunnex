package policy

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/gatewaymesh"
)

func TestCrossGatewayFQDNRetainsGenerationWithoutInventingAnswers(t *testing.T) {
	a, b, relay, site, owner, device, ruleID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	graph, err := gatewaymesh.Build(true, []gatewaymesh.Gateway{{ID: a, PublicKey: "a"}, {ID: b, PublicKey: "b"}, {ID: relay, PublicKey: "r", Endpoint: "relay.example:51820"}}, []gatewaymesh.Client{{NodeID: a, Address: "10.99.0.2", IPv6Address: "fd99::2"}, {NodeID: b, Address: "10.99.0.3", IPv6Address: "fd99::3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resource := fqdnForwardResource("client.internal.example", "internal.example", "10.20.0.53", site, relay)
	resource.Active.Answers = []string{"10.99.0.3"}
	snapshot := Snapshot{Mode: ModeEnforcing, CrossGatewayGraph: graph, FQDNResourcesLicensed: true, FQDNResourcesEnabled: true, Devices: []Device{{ID: device, UserID: owner, NodeID: a, AssignedIP: "10.99.0.2"}}, SiteNodes: []SiteNode{{SiteID: site, NodeID: relay}}, Rules: []Rule{{ID: ruleID, SrcKind: "user", SrcUserID: owner, DstKind: "fqdn_resource"}}, FQDNResources: []FQDNResource{resource}, FQDNRuleReferences: []FQDNRuleReference{{PolicyRuleID: ruleID, FQDNResourceID: resource.ID}}}
	out := Compile(snapshot)
	for _, id := range []uuid.UUID{a, b, relay} {
		got := out[id]
		if len(got.FQDNGenerations) != 1 {
			t.Fatalf("gateway %s lost FQDN withdrawal provenance: %+v", id, got)
		}
		if len(got.Allow) != 1 || got.Allow[0].DstCIDR != "10.99.0.3/32" || !got.Allow[0].FQDNManaged {
			t.Fatalf("DNS answer scope changed: %+v", got.Allow)
		}
	}
	snapshot.FQDNResources[0].Active = nil
	for _, got := range Compile(snapshot) {
		if len(got.Allow) != 0 || len(got.FQDNGenerations) != 0 {
			t.Fatalf("withdrawal retained grant: %+v", got)
		}
	}
}
