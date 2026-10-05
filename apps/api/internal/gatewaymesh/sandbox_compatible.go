package gatewaymesh

import (
	"fmt"

	"github.com/google/uuid"
)

// BuildSandboxCompatibleGraph retains ordinary client ownership, IPv6 and HA
// for existing carriers, while dedicated runtime gateways carry only their
// independently selected sandbox corridor. Historical remote records reserve
// those runtimes even after stop/delete; withdrawing a corridor must not opt
// its runtime into carrying unrelated clients.
func BuildSandboxCompatibleGraph(gateways []Gateway, clients []Client, activeMembers, reservedRuntimes []uuid.UUID, scoped *Graph) (*Graph, error) {
	reserved := map[uuid.UUID]bool{}
	for _, id := range reservedRuntimes {
		if id == uuid.Nil {
			return nil, fmt.Errorf("invalid dedicated sandbox gateway")
		}
		reserved[id] = true
	}
	for _, client := range clients {
		if reserved[client.NodeID] {
			return nil, fmt.Errorf("sandbox runtime gateway hosts ordinary clients")
		}
	}
	for _, id := range activeMembers {
		if reserved[id] {
			return nil, fmt.Errorf("sandbox runtime gateway participates in HA hosting")
		}
	}
	ordinary := make([]Gateway, 0, len(gateways))
	runtimeGateways := map[uuid.UUID]Gateway{}
	for _, gateway := range gateways {
		if reserved[gateway.ID] {
			runtimeGateways[gateway.ID] = gateway
		} else {
			ordinary = append(ordinary, gateway)
		}
	}
	graph, err := Build(true, ordinary, clients, activeMembers)
	if err != nil || scoped == nil {
		return graph, err
	}
	if !scoped.SandboxScoped() {
		return nil, fmt.Errorf("exact sandbox terminal graph required")
	}
	terminal, exists := graph.gateways[scoped.Relay]
	if !exists || terminal.PublicKey != scoped.gateways[scoped.Relay].PublicKey {
		return nil, fmt.Errorf("sandbox terminal conflicts with ordinary gateway identity")
	}
	for address, owner := range scoped.owners {
		if owner == scoped.Relay {
			// Preserve the terminal's actual ordinary owner; do not move a
			// pinned Mac through a different HA owner to supply this corridor.
			if graph.owners[address] != owner {
				return nil, fmt.Errorf("sandbox terminal conflicts with ordinary client ownership")
			}
			continue
		}
		if !reserved[owner] || graph.owners[address] != uuid.Nil {
			return nil, fmt.Errorf("sandbox runtime or address is not exclusive")
		}
	}
	for id, gateway := range scoped.gateways {
		if id == scoped.Relay {
			continue
		}
		if observed, exists := runtimeGateways[id]; !exists || observed.PublicKey != gateway.PublicKey {
			return nil, fmt.Errorf("sandbox runtime conflicts with current gateway identity")
		}
		for _, existing := range graph.gateways {
			if existing.PublicKey == gateway.PublicKey {
				return nil, fmt.Errorf("sandbox gateway public key conflicts with ordinary carrier")
			}
		}
	}
	graph.sandboxTerminalGraph = scoped
	return graph, nil
}
