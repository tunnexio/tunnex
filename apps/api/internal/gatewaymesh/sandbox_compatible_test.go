package gatewaymesh

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func compatibleSandboxFixture(t *testing.T) ([]Gateway, []Client, []uuid.UUID, *Graph, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	terminal, other, runtime := uuid.New(), uuid.New(), uuid.New()
	gateways := []Gateway{{terminal, "terminal", "terminal.example:51820"}, {other, "other", "other.example:51820"}, {runtime, "runtime", "runtime.example:51821"}}
	clients := []Client{{terminal, "10.99.0.11", "fd00::11"}, {other, "10.99.0.21", "fd00::21"}, {terminal, "10.99.0.13", "fd00::13"}}
	scoped, err := BuildSandboxTerminalGraph(gateways, []SandboxTerminalRoute{{TerminalGatewayID: terminal, RuntimeGatewayID: runtime, TerminalAddress: "10.99.0.11", SandboxAddress: "10.99.0.12", TerminalGatewayEndpoint: "172.31.18.43:51820", RuntimeGatewayEndpoint: "172.31.7.56:51821"}})
	if err != nil {
		t.Fatal(err)
	}
	return gateways, clients, []uuid.UUID{terminal}, scoped, terminal, other, runtime
}

func TestSandboxCompatibleGraphPreservesLegacyIPv6AndExactCorridor(t *testing.T) {
	gateways, clients, members, scoped, terminal, other, runtime := compatibleSandboxFixture(t)
	legacy, err := Build(true, gateways[:2], clients, members)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := BuildSandboxCompatibleGraph(gateways, clients, members, []uuid.UUID{runtime}, scoped)
	if err != nil {
		t.Fatal(err)
	}
	if combined.SandboxScoped() || !combined.AllowsSandboxTerminal(terminal, runtime, "10.99.0.11", "10.99.0.12") || combined.AllowsSandboxTerminal(terminal, runtime, "10.99.0.13", "10.99.0.12") {
		t.Fatal("ordinary graph confused with exact sandbox authorization association")
	}
	if combined.Relay != legacy.Relay || combined.Owner("10.99.0.11") != legacy.Owner("10.99.0.11") || combined.Owner("10.99.0.12") != uuid.Nil || combined.IPv6Source("10.99.0.11") != legacy.IPv6Source("10.99.0.11") || !reflect.DeepEqual(combined.IPv6Tuples("10.99.0.11", "10.99.0.21/32"), legacy.IPv6Tuples("10.99.0.11", "10.99.0.21/32")) {
		t.Fatal("scoped corridor changed ordinary ownership, relay or IPv6")
	}
	if !reflect.DeepEqual(combined.Peers(other), legacy.Peers(other)) || !reflect.DeepEqual(combined.EnforcementNodes("10.99.0.11", "10.99.0.21/32"), legacy.EnforcementNodes("10.99.0.11", "10.99.0.21/32")) {
		t.Fatal("unrelated ordinary carriage/enforcement changed")
	}
	if peers := combined.Peers(runtime); !reflect.DeepEqual(peers, scoped.Peers(runtime)) || len(peers) != 1 || !reflect.DeepEqual(peers[0].Prefixes, []string{"10.99.0.11/32"}) {
		t.Fatal("runtime received unrelated clients", peers)
	}
	for _, peer := range combined.Peers(terminal) {
		if peer.NodeID == runtime {
			if !reflect.DeepEqual(peer.Prefixes, []string{"10.99.0.12/32"}) || peer.Endpoint != "172.31.7.56:51821" {
				t.Fatal("terminal exported broader runtime prefix", peer)
			}
		}
	}
	withdrawn, err := BuildSandboxCompatibleGraph(gateways, clients, members, []uuid.UUID{runtime}, nil)
	if err != nil || len(withdrawn.Peers(runtime)) != 0 || !reflect.DeepEqual(withdrawn.Peers(other), legacy.Peers(other)) || withdrawn.AllowsSandboxTerminal(terminal, runtime, "10.99.0.11", "10.99.0.12") {
		t.Fatal("withdrawal widened runtime carriage or changed existing clients", err)
	}
}

func TestSandboxCompatibleGraphRejectsSharedRuntimeAndAmbiguousOwnership(t *testing.T) {
	for _, scenario := range []string{"runtime client", "runtime HA", "terminal HA owner", "address overlap", "public key collision", "runtime key mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			gateways, clients, members, scoped, terminal, other, runtime := compatibleSandboxFixture(t)
			switch scenario {
			case "runtime client":
				clients = append(clients, Client{NodeID: runtime, Address: "10.99.0.31"})
			case "runtime HA":
				members = append(members, runtime)
			case "terminal HA owner":
				members = []uuid.UUID{other, terminal}
			case "address overlap":
				clients = append(clients, Client{NodeID: other, Address: "10.99.0.12"})
			case "public key collision":
				gateways[1].PublicKey = gateways[2].PublicKey
			case "runtime key mismatch":
				gateways[2].PublicKey = "changed-runtime"
			}
			if _, err := BuildSandboxCompatibleGraph(gateways, clients, members, []uuid.UUID{runtime}, scoped); err == nil {
				t.Fatal("ambiguous/shared topology admitted")
			}
		})
	}
}
