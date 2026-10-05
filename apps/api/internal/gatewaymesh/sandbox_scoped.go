package gatewaymesh

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// SandboxTerminalRoute pins one terminal and sandbox to their actual gateways.
// Optional transport overrides are operator-selected private IPv4 endpoints,
// not addresses or endpoints supplied by a sandbox creator.
type SandboxTerminalRoute struct {
	TerminalGatewayID       uuid.UUID
	RuntimeGatewayID        uuid.UUID
	TerminalAddress         string
	SandboxAddress          string
	TerminalGatewayEndpoint string
	RuntimeGatewayEndpoint  string
}

type sandboxTerminalPair struct {
	terminal netip.Addr
	sandbox  netip.Addr
}

// SandboxScoped identifies a graph built solely from pinned sandbox terminal
// routes. An empty selection does not opt into scoped routing.
func (g *Graph) SandboxScoped() bool {
	return g != nil && g.sandboxScoped && g.Relay != uuid.Nil
}

// AllowsSandboxTerminal proves this exact routing association was supplied to
// BuildSandboxTerminalGraph. It does not authorize the connection; policy must
// independently grant its protocol and port scope.
func (g *Graph) AllowsSandboxTerminal(terminalGateway, runtimeGateway uuid.UUID, terminalAddress, sandboxAddress string) bool {
	if g != nil && g.sandboxTerminalGraph != nil {
		return g.sandboxTerminalGraph.AllowsSandboxTerminal(terminalGateway, runtimeGateway, terminalAddress, sandboxAddress)
	}
	if !g.SandboxScoped() || g.Relay != terminalGateway || terminalGateway == runtimeGateway {
		return false
	}
	terminal, err := netip.ParseAddr(terminalAddress)
	if err != nil || !terminal.Is4() {
		return false
	}
	sandbox, err := netip.ParseAddr(sandboxAddress)
	if err != nil || !sandbox.Is4() {
		return false
	}
	return g.owners[terminal] == terminalGateway && g.owners[sandbox] == runtimeGateway &&
		g.sandboxTerminalPairs[sandboxTerminalPair{terminal: terminal, sandbox: sandbox}]
}

// BuildSandboxTerminalGraph supplies reachability for a single explicitly
// selected terminal/runtime gateway pair. It never grants access: callers must
// still compile the terminal-to-sandbox policy independently. The existing
// terminal gateway is the relay, preserving the terminal's enrollment.
//
// More than one sandbox or terminal address may use that pair. Other gateway
// pairs must be built separately; combining them here would introduce transit
// routes through Graph's organization-wide relay model.
func BuildSandboxTerminalGraph(gateways []Gateway, terminals []SandboxTerminalRoute) (*Graph, error) {
	if len(terminals) == 0 {
		return Build(false, nil, nil, nil)
	}
	terminalID, runtimeID := terminals[0].TerminalGatewayID, terminals[0].RuntimeGatewayID
	if terminalID == uuid.Nil || runtimeID == uuid.Nil || terminalID == runtimeID {
		return nil, fmt.Errorf("sandbox terminal route requires distinct pinned gateways")
	}
	selected := map[uuid.UUID]Gateway{}
	for _, gateway := range gateways {
		if gateway.ID != terminalID && gateway.ID != runtimeID {
			continue
		}
		if old, exists := selected[gateway.ID]; exists && old != gateway {
			return nil, fmt.Errorf("ambiguous sandbox gateway definition")
		}
		selected[gateway.ID] = gateway
	}
	for _, id := range []uuid.UUID{terminalID, runtimeID} {
		gateway, exists := selected[id]
		if !exists || gateway.PublicKey == "" || strings.ContainsAny(gateway.PublicKey, " \t\r\n") {
			return nil, fmt.Errorf("sandbox terminal route gateway is unavailable")
		}
	}
	owners := map[netip.Addr]uuid.UUID{}
	overrides := map[uuid.UUID]string{}
	pairs := map[sandboxTerminalPair]bool{}
	for _, terminal := range terminals {
		if terminal.TerminalGatewayID != terminalID || terminal.RuntimeGatewayID != runtimeID {
			return nil, fmt.Errorf("mixed sandbox terminal gateway pairs")
		}
		for _, endpoint := range []struct {
			id    uuid.UUID
			value string
		}{{terminalID, terminal.TerminalGatewayEndpoint}, {runtimeID, terminal.RuntimeGatewayEndpoint}} {
			if endpoint.value == "" {
				continue
			}
			address, err := netip.ParseAddrPort(endpoint.value)
			if err != nil || !address.Addr().Is4() || !address.Addr().IsPrivate() || address.Port() == 0 {
				return nil, fmt.Errorf("sandbox gateway override requires a private IPv4 endpoint")
			}
			canonical := address.String()
			if old, exists := overrides[endpoint.id]; exists && old != canonical {
				return nil, fmt.Errorf("conflicting sandbox gateway endpoint overrides")
			}
			overrides[endpoint.id] = canonical
		}
		for _, client := range []struct {
			id      uuid.UUID
			address string
		}{{terminalID, terminal.TerminalAddress}, {runtimeID, terminal.SandboxAddress}} {
			address, err := netip.ParseAddr(client.address)
			if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
				return nil, fmt.Errorf("sandbox terminal route requires IPv4 host addresses")
			}
			if old, exists := owners[address]; exists && old != client.id {
				return nil, fmt.Errorf("ambiguous sandbox terminal address ownership")
			}
			owners[address] = client.id
		}
		// Both addresses have already been parsed and validated above.
		terminalAddress, _ := netip.ParseAddr(terminal.TerminalAddress)
		sandboxAddress, _ := netip.ParseAddr(terminal.SandboxAddress)
		pairs[sandboxTerminalPair{terminal: terminalAddress, sandbox: sandboxAddress}] = true
	}
	selectedGateways := make([]Gateway, 0, 2)
	for _, id := range []uuid.UUID{terminalID, runtimeID} {
		gateway := selected[id]
		if endpoint, exists := overrides[id]; exists {
			gateway.Endpoint = endpoint
		}
		// The selected terminal must remain the relay. Do not fall back to a
		// runtime or unrelated gateway when its endpoint is unavailable.
		if (id == terminalID || gateway.Endpoint != "") && !validEndpoint(gateway.Endpoint) {
			return nil, fmt.Errorf("sandbox terminal route has an invalid gateway endpoint")
		}
		selectedGateways = append(selectedGateways, gateway)
	}
	addresses := make([]netip.Addr, 0, len(owners))
	for address := range owners {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	clients := make([]Client, 0, len(addresses))
	for _, address := range addresses {
		clients = append(clients, Client{NodeID: owners[address], Address: address.String()})
	}
	graph, err := Build(true, selectedGateways, clients, []uuid.UUID{terminalID})
	if err != nil {
		return nil, err
	}
	graph.sandboxScoped = true
	graph.sandboxTerminalPairs = pairs
	return graph, nil
}
