package policy_test

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/gatewaymesh"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxscope"
)

type scopedTerminalFixture struct {
	snapshot                    policy.Snapshot
	gateways                    []gatewaymesh.Gateway
	route                       gatewaymesh.SandboxTerminalRoute
	terminal, runtime, hub      uuid.UUID
	otherSiteNode, otherGateway uuid.UUID
	terminalDevice, sandboxID   uuid.UUID
}

func newScopedTerminalFixture(t *testing.T) scopedTerminalFixture {
	t.Helper()
	f := scopedTerminalFixture{
		terminal: uuid.New(), runtime: uuid.New(), hub: uuid.New(), otherSiteNode: uuid.New(), otherGateway: uuid.New(),
		terminalDevice: uuid.New(), sandboxID: uuid.New(),
	}
	creator, peer, site, hubSite := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	f.gateways = []gatewaymesh.Gateway{
		{ID: f.terminal, PublicKey: "terminal", Endpoint: "terminal.example:51820"},
		{ID: f.runtime, PublicKey: "runtime", Endpoint: "runner.example:51821"},
		{ID: f.otherGateway, PublicKey: "unrelated", Endpoint: "unrelated.example:51820"},
	}
	f.route = gatewaymesh.SandboxTerminalRoute{
		TerminalGatewayID: f.terminal, RuntimeGatewayID: f.runtime,
		TerminalAddress: "10.99.0.11", SandboxAddress: "10.99.0.12",
		TerminalGatewayEndpoint: "172.31.18.43:51820", RuntimeGatewayEndpoint: "172.31.18.44:51821",
	}
	graph, err := gatewaymesh.BuildSandboxTerminalGraph(f.gateways, []gatewaymesh.SandboxTerminalRoute{f.route})
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot = policy.Snapshot{
		Mode: policy.ModeEnforcing, CrossGatewayGraph: graph, ActiveHub: f.hub,
		Devices: []policy.Device{
			{ID: peer, Kind: "sandbox", UserID: creator, NodeID: f.runtime, AssignedIP: "10.99.0.12"},
			{ID: f.terminalDevice, Kind: "human", UserID: creator, NodeID: f.terminal, AssignedIP: "10.99.0.11"},
			{ID: uuid.New(), Kind: "human", UserID: creator, NodeID: f.terminal, AssignedIP: "10.99.0.13"},
			{ID: uuid.New(), Kind: "agent", UserID: creator, NodeID: f.terminal, AssignedIP: "10.99.0.14"},
			{ID: uuid.New(), Kind: "human", UserID: uuid.New(), NodeID: f.otherSiteNode, AssignedIP: "10.99.0.21"},
		},
		// The unrelated site's approved subnet deliberately includes the sandbox
		// address. Generic resource placement would add both this site and hub.
		SiteSubnets: []policy.SiteSubnet{{SiteID: site, CIDR: "10.99.0.0/24"}, {SiteID: hubSite, CIDR: "10.20.0.0/16"}},
		SiteNodes:   []policy.SiteNode{{SiteID: site, NodeID: f.otherSiteNode}, {SiteID: hubSite, NodeID: f.hub}},
		Sandboxes: []policy.SandboxProjection{{
			SandboxID: f.sandboxID, DeviceID: peer, CreatorID: creator, TerminalDeviceID: f.terminalDevice,
			RemoteTerminalGatewayID: f.terminal, RemoteRuntimeGatewayID: f.runtime,
		}},
	}
	return f
}

func assertScopedTerminalNoGrants(t *testing.T, snapshot policy.Snapshot) {
	t.Helper()
	for node, artifact := range policy.Compile(snapshot) {
		if artifact.Mesh || len(artifact.Allow) != 0 {
			t.Fatalf("withdrawn scoped terminal retained grant on %s: %+v", node, artifact)
		}
	}
}

func TestScopedSandboxTerminalSSHPlacementExcludesSitesAndHub(t *testing.T) {
	f := newScopedTerminalFixture(t)
	compiled := policy.Compile(f.snapshot)
	want := []policyspec.AllowEntry{{
		SrcIP: "10.99.0.11", DstCIDR: "10.99.0.12/32", Protocol: "tcp", PortLow: 22, PortHigh: 22,
		RuleID: uuid.NewSHA1(f.sandboxID, []byte("terminal/"+f.terminalDevice.String())).String(), SrcDeviceID: f.terminalDevice.String(),
	}}
	for _, node := range []uuid.UUID{f.terminal, f.runtime} {
		artifact, exists := compiled[node]
		if !exists || artifact.Mesh || !reflect.DeepEqual(artifact.Allow, want) {
			t.Fatalf("pinned gateway %s must get exactly creator SSH scope: %+v", node, artifact)
		}
	}
	for _, node := range []uuid.UUID{f.hub, f.otherSiteNode} {
		artifact, exists := compiled[node]
		if !exists || artifact.Mesh || len(artifact.Allow) != 0 {
			t.Fatalf("unrelated existing enforcement context received scoped SSH: %s %+v", node, artifact)
		}
	}
	if _, exists := compiled[f.otherGateway]; exists {
		t.Fatal("unrelated gateway was introduced by scoped transport")
	}
	for node, artifact := range compiled {
		if node != f.terminal && node != f.runtime && len(artifact.Allow) != 0 {
			t.Fatalf("terminal rule leaked outside pinned gateway pair: %s %+v", node, artifact)
		}
	}
}

func TestScopedSandboxTerminalWithdrawalHasNoLegacyFallback(t *testing.T) {
	for _, state := range []string{"expired", "stopped"} {
		t.Run(state+" projection absent", func(t *testing.T) {
			f := newScopedTerminalFixture(t)
			// The compiler is clockless. Authoritative snapshot loading omits
			// expired/stopped records; a stale route alone must grant nothing.
			f.snapshot.Sandboxes = nil
			assertScopedTerminalNoGrants(t, f.snapshot)
		})
		t.Run(state+" route absent", func(t *testing.T) {
			f := newScopedTerminalFixture(t)
			// Even if the projection remains, withdrawal of its eligible route
			// must not fall back to legacy terminal or site/hub placement.
			graph, err := gatewaymesh.BuildSandboxTerminalGraph(f.gateways, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.snapshot.CrossGatewayGraph = graph
			assertScopedTerminalNoGrants(t, f.snapshot)
		})
	}
}

func TestScopedSandboxTerminalRejectsInvalidAssociation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*testing.T, *scopedTerminalFixture)
	}{
		{"missing graph", func(_ *testing.T, f *scopedTerminalFixture) { f.snapshot.CrossGatewayGraph = nil }},
		{"ordinary graph is insufficient", func(t *testing.T, f *scopedTerminalFixture) {
			graph, err := gatewaymesh.Build(true, f.gateways[:2], []gatewaymesh.Client{
				{NodeID: f.terminal, Address: "10.99.0.11"}, {NodeID: f.runtime, Address: "10.99.0.12"},
			}, []uuid.UUID{f.terminal})
			if err != nil {
				t.Fatal(err)
			}
			f.snapshot.CrossGatewayGraph = graph
		}},
		{"missing runtime pin", func(_ *testing.T, f *scopedTerminalFixture) {
			f.snapshot.Sandboxes[0].RemoteRuntimeGatewayID = uuid.Nil
		}},
		{"wrong runtime pin", func(_ *testing.T, f *scopedTerminalFixture) {
			f.snapshot.Sandboxes[0].RemoteRuntimeGatewayID = f.otherGateway
		}},
		{"wrong terminal pin", func(_ *testing.T, f *scopedTerminalFixture) {
			f.snapshot.Sandboxes[0].RemoteTerminalGatewayID = f.otherGateway
		}},
		{"wrong pinned device", func(_ *testing.T, f *scopedTerminalFixture) { f.snapshot.Sandboxes[0].TerminalDeviceID = uuid.New() }},
		{"terminal moved gateway", func(_ *testing.T, f *scopedTerminalFixture) { f.snapshot.Devices[1].NodeID = f.otherSiteNode }},
		{"runtime moved gateway", func(_ *testing.T, f *scopedTerminalFixture) { f.snapshot.Devices[0].NodeID = f.otherSiteNode }},
		{"terminal address changed", func(_ *testing.T, f *scopedTerminalFixture) { f.snapshot.Devices[1].AssignedIP = "10.99.0.31" }},
		{"sandbox address changed", func(_ *testing.T, f *scopedTerminalFixture) { f.snapshot.Devices[0].AssignedIP = "10.99.0.32" }},
		{"terminal ownership transferred", func(_ *testing.T, f *scopedTerminalFixture) { f.snapshot.Devices[1].UserID = uuid.New() }},
		{"agent cannot replace human terminal", func(_ *testing.T, f *scopedTerminalFixture) { f.snapshot.Devices[1].Kind = "agent" }},
		{"local and remote pins conflict", func(_ *testing.T, f *scopedTerminalFixture) {
			f.snapshot.Sandboxes[0].LocalTerminalGatewayID = f.terminal
		}},
		{"remote terminal cannot request outbound scope", func(_ *testing.T, f *scopedTerminalFixture) {
			f.snapshot.Sandboxes[0].Requested = []sandboxscope.Scope{{CIDR: "10.20.0.1/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}}
		}},
		{"unrecorded selected address pair", func(t *testing.T, f *scopedTerminalFixture) {
			// Both addresses and owners exist in the routing graph, but not as
			// the projected terminal/sandbox association.
			first, second := f.route, f.route
			first.SandboxAddress = "10.99.0.32"
			second.TerminalAddress = "10.99.0.31"
			graph, err := gatewaymesh.BuildSandboxTerminalGraph(f.gateways, []gatewaymesh.SandboxTerminalRoute{first, second})
			if err != nil {
				t.Fatal(err)
			}
			f.snapshot.CrossGatewayGraph = graph
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newScopedTerminalFixture(t)
			tt.edit(t, &f)
			assertScopedTerminalNoGrants(t, f.snapshot)
		})
	}
}
