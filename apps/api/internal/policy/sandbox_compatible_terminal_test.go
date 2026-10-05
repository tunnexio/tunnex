package policy_test

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/gatewaymesh"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

func TestSandboxCompatibleTerminalKeepsLegacyGrantsOffRuntime(t *testing.T) {
	f := newScopedTerminalFixture(t)
	scoped := f.snapshot.CrossGatewayGraph
	f.gateways = append(f.gateways, gatewaymesh.Gateway{ID: f.otherSiteNode, PublicKey: "other-site", Endpoint: "other-site.example:51820"})
	clients := []gatewaymesh.Client{}
	for _, device := range f.snapshot.Devices {
		if device.Kind != "sandbox" {
			clients = append(clients, gatewaymesh.Client{NodeID: device.NodeID, Address: device.AssignedIP})
		}
	}
	legacyGateways := []gatewaymesh.Gateway{}
	for _, gateway := range f.gateways {
		if gateway.ID != f.runtime {
			legacyGateways = append(legacyGateways, gateway)
		}
	}
	legacy, err := gatewaymesh.Build(true, legacyGateways, clients, nil)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := gatewaymesh.BuildSandboxCompatibleGraph(f.gateways, clients, nil, []uuid.UUID{f.runtime}, scoped)
	if err != nil {
		t.Fatal(err)
	}
	// Both existing owner grants and an unrelated user's broad CIDR grant must
	// retain their old placement. Carriage of a sandbox /32 is not permission
	// for its dedicated runtime to accept those unrelated sources or ports.
	resource := uuid.New()
	f.snapshot.Resources = append(f.snapshot.Resources, policy.Resource{ID: resource, CIDR: "10.99.0.0/24", Protocol: "any"})
	for _, owner := range []uuid.UUID{f.snapshot.Devices[0].UserID, f.snapshot.Devices[4].UserID} {
		f.snapshot.Rules = append(f.snapshot.Rules, policy.Rule{ID: uuid.New(), SrcKind: "user", SrcUserID: owner, DstKind: "resource", DstResourceID: resource})
	}
	before := f.snapshot
	before.Sandboxes = nil
	before.CrossGatewayGraph = legacy
	old := policy.Compile(before)
	f.snapshot.CrossGatewayGraph = combined
	current := policy.Compile(f.snapshot)
	for node, artifact := range old {
		if node != f.terminal && node != f.runtime && !reflect.DeepEqual(current[node], artifact) {
			t.Fatalf("ordinary policy changed on %s", node)
		}
	}
	for _, retained := range old[f.terminal].Allow {
		found := false
		for _, current := range current[f.terminal].Allow {
			found = found || reflect.DeepEqual(current, retained)
		}
		if !found {
			t.Fatal("terminal lost an ordinary pre-existing grant")
		}
	}
	runtime := current[f.runtime]
	if runtime.Mesh || len(runtime.Allow) != 1 || runtime.Allow[0].SrcIP != "10.99.0.11" || runtime.Allow[0].DstCIDR != "10.99.0.12/32" || runtime.Allow[0].Protocol != "tcp" || runtime.Allow[0].PortLow != 22 || runtime.Allow[0].PortHigh != 22 {
		t.Fatalf("runtime inherited legacy/unrelated permission: %+v", runtime)
	}
	for _, artifact := range current {
		for _, grant := range artifact.Allow {
			if grant.SrcIP == "10.99.0.12" {
				t.Fatal("sandbox inherited creator outbound scope")
			}
		}
	}
	f.snapshot.Sandboxes = nil
	if withdrawn := policy.Compile(f.snapshot)[f.runtime]; len(withdrawn.Allow) != 0 {
		t.Fatal("stale corridor supplied authorization after projection withdrawal")
	}
}
