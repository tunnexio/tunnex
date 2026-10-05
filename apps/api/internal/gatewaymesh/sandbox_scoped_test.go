package gatewaymesh

import (
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func sandboxScopedFixture() ([]Gateway, []SandboxTerminalRoute) {
	terminal, runtime, unrelated := uuid.New(), uuid.New(), uuid.New()
	return []Gateway{
		{ID: terminal, PublicKey: "terminal-key", Endpoint: "terminal.example:51820"},
		{ID: runtime, PublicKey: "runtime-key", Endpoint: "198.51.100.20:51821"},
		{ID: unrelated, PublicKey: "unrelated-key", Endpoint: "unrelated.example:51820"},
	}, []SandboxTerminalRoute{{
		TerminalGatewayID: terminal, RuntimeGatewayID: runtime,
		TerminalAddress: "10.99.0.11", SandboxAddress: "10.99.0.12",
	}}
}

func TestSandboxTerminalGraphScopesBothDirections(t *testing.T) {
	gateways, routes := sandboxScopedFixture()
	// Even a conflicting key on an unrelated gateway must not add a peer or
	// interfere with the independently selected corridor.
	gateways[2].PublicKey = gateways[0].PublicKey
	gateways[2].Endpoint = "invalid"
	graph, err := BuildSandboxTerminalGraph(gateways, routes)
	if err != nil {
		t.Fatal(err)
	}
	terminal, runtime := routes[0].TerminalGatewayID, routes[0].RuntimeGatewayID
	if graph.Relay != terminal || graph.Unavailable != "" || !graph.SandboxScoped() {
		t.Fatalf("terminal relay changed: %+v", graph)
	}
	if got := graph.Peers(terminal); !reflect.DeepEqual(got, []Peer{{
		NodeID: runtime, PublicKey: "runtime-key", Endpoint: "198.51.100.20:51821", Prefixes: []string{"10.99.0.12/32"},
	}}) {
		t.Fatalf("terminal forward routing: %+v", got)
	}
	if got := graph.Peers(runtime); !reflect.DeepEqual(got, []Peer{{
		NodeID: terminal, PublicKey: "terminal-key", Endpoint: "terminal.example:51820", Prefixes: []string{"10.99.0.11/32"},
	}}) {
		t.Fatalf("sandbox reverse routing: %+v", got)
	}
	if len(graph.Peers(gateways[2].ID)) != 0 || len(graph.Peers(uuid.New())) != 0 || len(graph.gateways) != 2 || len(graph.owners) != 2 {
		t.Fatal("unselected gateways or clients included")
	}
	for address, owner := range map[string]uuid.UUID{"10.99.0.11": terminal, "10.99.0.12": runtime, "10.99.0.13": uuid.Nil, "fd99::11": uuid.Nil} {
		if graph.Owner(address) != owner {
			t.Fatalf("unexpected owner for %s", address)
		}
	}
	// A routing graph only identifies enforcement placement. It has no grants
	// or transport-port policy, and unknown endpoints have no placement.
	if !reflect.DeepEqual(graph.EnforcementNodes("10.99.0.11", "10.99.0.12/32"), sortedIDs(terminal, runtime)) {
		t.Fatal("pinned path enforcement placement missing")
	}
	if len(graph.EnforcementNodes("10.99.0.13", "10.99.0.12/32")) != 0 || len(graph.EnforcementNodes("10.99.0.11", "10.99.0.13/32")) != 0 || len(graph.IPv6Tuples("10.99.0.11", "10.99.0.12/32")) != 0 {
		t.Fatal("graph invented an unrelated identity or IPv6 route")
	}
}

func TestSandboxTerminalGraphMultipleSandboxesAndPrivatePeering(t *testing.T) {
	gateways, routes := sandboxScopedFixture()
	routes[0].TerminalGatewayEndpoint = "172.31.18.43:51820"
	routes[0].RuntimeGatewayEndpoint = "10.0.1.9:51821"
	second := routes[0]
	second.SandboxAddress = "10.99.0.13"
	routes = append(routes, second, routes[0])
	// An omitted override on another row uses the one exact selected override.
	routes[1].TerminalGatewayEndpoint = ""
	gateways = append(gateways, gateways[0])
	before := append([]Gateway(nil), gateways...)
	graph, err := BuildSandboxTerminalGraph(gateways, routes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gateways, before) {
		t.Fatal("changed trusted gateway inputs")
	}
	if got := graph.Peers(routes[0].TerminalGatewayID); len(got) != 1 || got[0].Endpoint != "10.0.1.9:51821" || !reflect.DeepEqual(got[0].Prefixes, []string{"10.99.0.12/32", "10.99.0.13/32"}) {
		t.Fatalf("sandbox routes duplicated or widened: %+v", got)
	}
	if got := graph.Peers(routes[0].RuntimeGatewayID); len(got) != 1 || got[0].Endpoint != "172.31.18.43:51820" || !reflect.DeepEqual(got[0].Prefixes, []string{"10.99.0.11/32"}) {
		t.Fatalf("terminal route duplicated or private endpoint lost: %+v", got)
	}
	// Route ordering cannot select a different relay or transport endpoint.
	routes[0], routes[1] = routes[1], routes[0]
	reordered, err := BuildSandboxTerminalGraph(gateways, routes)
	if err != nil || !reflect.DeepEqual(graph.Peers(routes[0].TerminalGatewayID), reordered.Peers(routes[0].TerminalGatewayID)) || !reflect.DeepEqual(graph.Peers(routes[0].RuntimeGatewayID), reordered.Peers(routes[0].RuntimeGatewayID)) {
		t.Fatal("route ordering changed the corridor")
	}
}

func TestSandboxTerminalGraphEmptyAndNATRuntime(t *testing.T) {
	gateways, routes := sandboxScopedFixture()
	empty, err := BuildSandboxTerminalGraph(gateways, nil)
	if err != nil || empty.Relay != uuid.Nil || empty.SandboxScoped() || len(empty.gateways) != 0 || len(empty.owners) != 0 || len(empty.Peers(gateways[0].ID)) != 0 {
		t.Fatalf("empty selection retained routing: %+v %v", empty, err)
	}
	gateways[1].Endpoint = ""
	graph, err := BuildSandboxTerminalGraph(gateways, routes)
	if err != nil || graph.Relay != routes[0].TerminalGatewayID {
		t.Fatalf("NAT runtime changed relay: %+v %v", graph, err)
	}
	if got := graph.Peers(routes[0].TerminalGatewayID); len(got) != 1 || got[0].Endpoint != "" || !reflect.DeepEqual(got[0].Prefixes, []string{"10.99.0.12/32"}) {
		t.Fatalf("NAT runtime host route lost: %+v", got)
	}
}

func TestSandboxTerminalGraphExactAssociation(t *testing.T) {
	gateways, routes := sandboxScopedFixture()
	second := routes[0]
	second.TerminalAddress = "10.99.0.21"
	second.SandboxAddress = "10.99.0.22"
	routes = append(routes, second)
	graph, err := BuildSandboxTerminalGraph(gateways, routes)
	if err != nil {
		t.Fatal(err)
	}
	terminal, runtime := routes[0].TerminalGatewayID, routes[0].RuntimeGatewayID
	for _, route := range routes {
		if !graph.AllowsSandboxTerminal(terminal, runtime, route.TerminalAddress, route.SandboxAddress) {
			t.Fatal("explicit routing association missing")
		}
	}
	for _, addresses := range [][2]string{
		{"10.99.0.11", "10.99.0.22"}, // Selected owners are insufficient without the exact row.
		{"10.99.0.21", "10.99.0.12"},
		{"10.99.0.13", "10.99.0.12"},
		{"10.99.0.11", "10.99.0.13"},
		{"10.99.0.11/32", "10.99.0.12"},
		{"10.99.0.11", "10.99.0.12/32"},
		{"::ffff:10.99.0.11", "10.99.0.12"},
	} {
		if graph.AllowsSandboxTerminal(terminal, runtime, addresses[0], addresses[1]) {
			t.Fatalf("unrecorded association accepted: %+v", addresses)
		}
	}
	for _, ids := range [][2]uuid.UUID{{runtime, terminal}, {terminal, uuid.New()}, {uuid.New(), runtime}, {terminal, terminal}, {uuid.Nil, runtime}, {terminal, uuid.Nil}} {
		if graph.AllowsSandboxTerminal(ids[0], ids[1], "10.99.0.11", "10.99.0.12") {
			t.Fatalf("unrecorded gateway ownership accepted: %+v", ids)
		}
	}
	ordinary, err := Build(true, gateways[:2], []Client{{NodeID: terminal, Address: "10.99.0.11"}, {NodeID: runtime, Address: "10.99.0.12"}}, []uuid.UUID{terminal})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := BuildSandboxTerminalGraph(gateways, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, notScoped := range []*Graph{nil, ordinary, empty} {
		if notScoped.SandboxScoped() || notScoped.AllowsSandboxTerminal(terminal, runtime, "10.99.0.11", "10.99.0.12") {
			t.Fatal("unscoped graph accepted a sandbox terminal association")
		}
	}
}

func TestSandboxTerminalGraphRejectsAmbiguity(t *testing.T) {
	tests := []struct {
		name string
		edit func(*[]Gateway, *[]SandboxTerminalRoute)
		want string
	}{
		{"nil terminal", func(_ *[]Gateway, r *[]SandboxTerminalRoute) { (*r)[0].TerminalGatewayID = uuid.Nil }, "distinct pinned gateways"},
		{"nil runtime", func(_ *[]Gateway, r *[]SandboxTerminalRoute) { (*r)[0].RuntimeGatewayID = uuid.Nil }, "distinct pinned gateways"},
		{"same gateway", func(_ *[]Gateway, r *[]SandboxTerminalRoute) { (*r)[0].RuntimeGatewayID = (*r)[0].TerminalGatewayID }, "distinct pinned gateways"},
		{"unknown terminal", func(_ *[]Gateway, r *[]SandboxTerminalRoute) { (*r)[0].TerminalGatewayID = uuid.New() }, "gateway is unavailable"},
		{"unknown runtime", func(_ *[]Gateway, r *[]SandboxTerminalRoute) { (*r)[0].RuntimeGatewayID = uuid.New() }, "gateway is unavailable"},
		{"empty key", func(g *[]Gateway, _ *[]SandboxTerminalRoute) { (*g)[1].PublicKey = "" }, "gateway is unavailable"},
		{"whitespace key", func(g *[]Gateway, _ *[]SandboxTerminalRoute) { (*g)[0].PublicKey = "terminal\nkey" }, "gateway is unavailable"},
		{"shared selected key", func(g *[]Gateway, _ *[]SandboxTerminalRoute) { (*g)[1].PublicKey = (*g)[0].PublicKey }, "ambiguous gateway public key"},
		{"conflicting gateway key", func(g *[]Gateway, _ *[]SandboxTerminalRoute) {
			duplicate := (*g)[0]
			duplicate.PublicKey = "different"
			*g = append(*g, duplicate)
		}, "ambiguous sandbox gateway definition"},
		{"conflicting gateway endpoint", func(g *[]Gateway, _ *[]SandboxTerminalRoute) {
			duplicate := (*g)[1]
			duplicate.Endpoint = "different.example:51821"
			*g = append(*g, duplicate)
		}, "ambiguous sandbox gateway definition"},
		{"mixed pairs", func(g *[]Gateway, r *[]SandboxTerminalRoute) {
			second := (*r)[0]
			second.RuntimeGatewayID = (*g)[2].ID
			*r = append(*r, second)
		}, "mixed sandbox terminal gateway pairs"},
		{"reversed pair", func(_ *[]Gateway, r *[]SandboxTerminalRoute) {
			second := (*r)[0]
			second.TerminalGatewayID, second.RuntimeGatewayID = second.RuntimeGatewayID, second.TerminalGatewayID
			*r = append(*r, second)
		}, "mixed sandbox terminal gateway pairs"},
		{"same address", func(_ *[]Gateway, r *[]SandboxTerminalRoute) { (*r)[0].SandboxAddress = (*r)[0].TerminalAddress }, "ambiguous sandbox terminal address ownership"},
		{"cross row ownership", func(_ *[]Gateway, r *[]SandboxTerminalRoute) {
			second := (*r)[0]
			second.TerminalAddress = (*r)[0].SandboxAddress
			second.SandboxAddress = "10.99.0.13"
			*r = append(*r, second)
		}, "ambiguous sandbox terminal address ownership"},
		{"conflicting terminal override", func(_ *[]Gateway, r *[]SandboxTerminalRoute) {
			(*r)[0].TerminalGatewayEndpoint = "172.31.18.43:51820"
			second := (*r)[0]
			second.TerminalGatewayEndpoint = "172.31.18.44:51820"
			*r = append(*r, second)
		}, "conflicting sandbox gateway endpoint overrides"},
		{"conflicting runtime override", func(_ *[]Gateway, r *[]SandboxTerminalRoute) {
			(*r)[0].RuntimeGatewayEndpoint = "10.0.1.9:51821"
			second := (*r)[0]
			second.RuntimeGatewayEndpoint = "10.0.1.9:51822"
			*r = append(*r, second)
		}, "conflicting sandbox gateway endpoint overrides"},
		{"missing terminal carrier", func(g *[]Gateway, _ *[]SandboxTerminalRoute) { (*g)[0].Endpoint = "" }, "invalid gateway endpoint"},
		{"invalid terminal carrier", func(g *[]Gateway, _ *[]SandboxTerminalRoute) { (*g)[0].Endpoint = "terminal.example:0" }, "invalid gateway endpoint"},
		{"invalid runtime carrier", func(g *[]Gateway, _ *[]SandboxTerminalRoute) { (*g)[1].Endpoint = "runtime.example:65536" }, "invalid gateway endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateways, routes := sandboxScopedFixture()
			tt.edit(&gateways, &routes)
			if graph, err := BuildSandboxTerminalGraph(gateways, routes); err == nil || graph != nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q rejection, got graph=%+v err=%v", tt.want, graph, err)
			}
		})
	}
}

func TestSandboxTerminalGraphRejectsInvalidHostAddresses(t *testing.T) {
	for _, address := range []string{"", "10.99.0.0/24", "10.99.0.12/32", "fd99::12", "::ffff:10.99.0.12", "0.0.0.0", "127.0.0.1", "169.254.0.1", "224.0.0.1", "10.99.0.12\n"} {
		for _, terminal := range []bool{true, false} {
			t.Run(address+"/terminal="+map[bool]string{true: "true", false: "false"}[terminal], func(t *testing.T) {
				gateways, routes := sandboxScopedFixture()
				if terminal {
					routes[0].TerminalAddress = address
				} else {
					routes[0].SandboxAddress = address
				}
				if graph, err := BuildSandboxTerminalGraph(gateways, routes); err == nil || graph != nil {
					t.Fatalf("non-host IPv4 accepted: %q", address)
				}
			})
		}
	}
}

func TestSandboxTerminalGraphRestrictsOverrideEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"198.51.100.20:51821", "gateway.example:51821", "127.0.0.1:51821", "169.254.0.1:51821",
		"0.0.0.0:51821", "224.0.0.1:51821", "[fd99::1]:51821", "[::ffff:10.0.1.9]:51821",
		"10.0.1.9", "10.0.1.9:0", "10.0.1.9:65536", "10.0.1.9:-1", "10.0.1.9:51821\n",
	} {
		for _, terminal := range []bool{true, false} {
			t.Run(endpoint+"/terminal="+map[bool]string{true: "true", false: "false"}[terminal], func(t *testing.T) {
				gateways, routes := sandboxScopedFixture()
				if terminal {
					routes[0].TerminalGatewayEndpoint = endpoint
				} else {
					routes[0].RuntimeGatewayEndpoint = endpoint
				}
				if graph, err := BuildSandboxTerminalGraph(gateways, routes); err == nil || graph != nil {
					t.Fatalf("non-private IPv4 override accepted: %q", endpoint)
				}
			})
		}
	}
	for _, endpoint := range []string{"10.0.1.9:51821", "172.31.18.43:51821", "192.168.1.2:51821"} {
		t.Run("valid/"+endpoint, func(t *testing.T) {
			gateways, routes := sandboxScopedFixture()
			routes[0].RuntimeGatewayEndpoint = endpoint
			if _, err := BuildSandboxTerminalGraph(gateways, routes); err != nil {
				t.Fatal(err)
			}
		})
	}
}
