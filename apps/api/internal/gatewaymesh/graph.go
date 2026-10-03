// Package gatewaymesh projects organization-scoped client ownership into a
// gateway relay graph. It supplies reachability and enforcement placement,
// never authorization: the policy compiler still resolves the actual grants.
package gatewaymesh

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type Gateway struct {
	ID                  uuid.UUID
	PublicKey, Endpoint string
}
type Client struct {
	NodeID      uuid.UUID
	Address     string
	IPv6Address string
}
type Peer struct {
	NodeID              uuid.UUID
	PublicKey, Endpoint string
	Prefixes            []string
}
type Graph struct {
	Relay       uuid.UUID
	Unavailable string
	gateways    map[uuid.UUID]Gateway
	owners      map[netip.Addr]uuid.UUID
	aliases     map[netip.Addr]netip.Addr
}

// ActiveOrder is the existing hub-set derivation: demoted members remain warm
// candidates at the back. Both site topology and client ownership use it.
func ActiveOrder(configured, demoted []uuid.UUID) []uuid.UUID {
	dead := map[uuid.UUID]bool{}
	for _, id := range demoted {
		dead[id] = true
	}
	live, back := []uuid.UUID{}, []uuid.UUID{}
	for _, id := range configured {
		if dead[id] {
			back = append(back, id)
		} else {
			live = append(live, id)
		}
	}
	return append(live, back...)
}

func validEndpoint(value string) bool {
	if strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && number > 0 && number <= 65535
}

func Build(enabled bool, gateways []Gateway, clients []Client, activeMembers []uuid.UUID) (*Graph, error) {
	graph := &Graph{gateways: map[uuid.UUID]Gateway{}, owners: map[netip.Addr]uuid.UUID{}, aliases: map[netip.Addr]netip.Addr{}}
	if !enabled {
		return graph, nil
	}
	keys := map[string]uuid.UUID{}
	for _, g := range gateways {
		if g.ID == uuid.Nil || g.PublicKey == "" {
			continue
		}
		if id, ok := keys[g.PublicKey]; ok && id != g.ID {
			return nil, fmt.Errorf("ambiguous gateway public key")
		}
		keys[g.PublicKey] = g.ID
		graph.gateways[g.ID] = g
	}
	members := map[uuid.UUID]bool{}
	primary := uuid.Nil
	for _, id := range activeMembers {
		if _, ok := graph.gateways[id]; ok {
			members[id] = true
			if primary == uuid.Nil {
				primary = id
			}
		}
	}
	if g, ok := graph.gateways[primary]; ok && validEndpoint(g.Endpoint) {
		graph.Relay = primary
	}
	if graph.Relay == uuid.Nil {
		candidates := []uuid.UUID{}
		for id, g := range graph.gateways {
			if validEndpoint(g.Endpoint) {
				candidates = append(candidates, id)
			}
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].String() < candidates[j].String() })
		if len(candidates) > 0 {
			graph.Relay = candidates[0]
		}
	}
	for _, client := range clients {
		owner := client.NodeID
		if members[owner] {
			owner = primary
		}
		if _, ok := graph.gateways[owner]; !ok {
			continue
		}
		address, err := netip.ParseAddr(client.Address)
		if err != nil || !address.IsGlobalUnicast() {
			return nil, fmt.Errorf("invalid client address")
		}
		address = address.Unmap()
		if _, ok := graph.owners[address]; ok {
			return nil, fmt.Errorf("ambiguous client address ownership")
		}
		graph.owners[address] = owner
		if client.IPv6Address != "" {
			v6, err := netip.ParseAddr(client.IPv6Address)
			if err != nil || !address.Is4() || !v6.Is6() || v6.Is4In6() || !v6.IsGlobalUnicast() {
				return nil, fmt.Errorf("invalid dual-stack client binding")
			}
			if _, ok := graph.owners[v6]; ok {
				return nil, fmt.Errorf("ambiguous IPv6 client ownership")
			}
			graph.owners[v6] = owner
			graph.aliases[address] = v6
		}
	}
	if graph.Relay == uuid.Nil && len(graph.owners) > 0 {
		graph.Unavailable = "A gateway with a reachable WireGuard endpoint is required."
	}
	return graph, nil
}

type IPv6Tuple struct{ Source, Destination string }

// IPv6Tuples expands a resolved identity grant onto those identities' allocated
// IPv6 hosts. Address-scoped resource/FQDN grants must not use this expansion.
func (g *Graph) IPv6Tuples(source, destination string) []IPv6Tuple {
	if g == nil || g.Relay == uuid.Nil {
		return nil
	}
	src, err := netip.ParseAddr(source)
	if err != nil {
		return nil
	}
	v6, ok := g.aliases[src]
	if !ok {
		return nil
	}
	prefix, err := netip.ParsePrefix(destination)
	if err != nil || !prefix.Addr().Is4() {
		return nil
	}
	out := []IPv6Tuple{}
	for address, target := range g.aliases {
		if prefix.Contains(address) && address != src {
			out = append(out, IPv6Tuple{Source: v6.String(), Destination: netip.PrefixFrom(target, 128).String()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Destination < out[j].Destination })
	return out
}

// IPv6Source resolves an active device's alias without changing the requested destination.
func (g *Graph) IPv6Source(source string) string {
	if g == nil || g.Relay == uuid.Nil {
		return ""
	}
	address, err := netip.ParseAddr(source)
	if err != nil {
		return ""
	}
	if v6, ok := g.aliases[address.Unmap()]; ok {
		return v6.String()
	}
	return ""
}

func (g *Graph) Owner(value string) uuid.UUID {
	if g == nil {
		return uuid.Nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return uuid.Nil
	}
	return g.owners[address.Unmap()]
}

// Peers carries exact client hosts, never the pool prefix. On the relay each
// host routes to its owning gateway; on a spoke remote hosts route to the relay.
// Local hosts are excluded, including HA clients hosted by the active primary.
func (g *Graph) Peers(nodeID uuid.UUID) []Peer {
	if g == nil || g.Relay == uuid.Nil {
		return nil
	}
	if _, ok := g.gateways[nodeID]; !ok {
		return nil
	}
	byPeer := map[uuid.UUID][]string{}
	// Keep carrier handshakes warm even when a gateway temporarily has no
	// clients. Empty AllowedIPs authorize no packets. Removing that peer would
	// strand a NAT spoke's existing session when its next client arrives.
	if nodeID == g.Relay {
		for id := range g.gateways {
			if id != nodeID {
				byPeer[id] = nil
			}
		}
	} else {
		byPeer[g.Relay] = nil
	}

	for address, owner := range g.owners {
		if owner == nodeID {
			continue
		}
		next := owner
		if nodeID != g.Relay {
			next = g.Relay
		}
		byPeer[next] = append(byPeer[next], netip.PrefixFrom(address, address.BitLen()).String())
	}
	out := []Peer{}
	for id, prefixes := range byPeer {
		sort.Strings(prefixes)
		peer := g.gateways[id]
		endpoint := peer.Endpoint
		if !validEndpoint(endpoint) {
			endpoint = ""
		}
		out = append(out, Peer{NodeID: id, PublicKey: peer.PublicKey, Endpoint: endpoint, Prefixes: prefixes})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out
}

func sortedIDs(ids ...uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	out := []uuid.UUID{}
	for _, id := range ids {
		if id != uuid.Nil && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// EnforcementNodes places a resolved grant on every gateway on its client
// path. CIDR grants may cover several destination clients; L4 scope is retained
// by the caller. No rule is invented, and absent/revoked clients are absent here.
func (g *Graph) EnforcementNodes(source, destination string) []uuid.UUID {
	if g == nil || g.Relay == uuid.Nil {
		return nil
	}
	owner := g.Owner(source)
	if owner == uuid.Nil {
		return nil
	}
	prefix, err := netip.ParsePrefix(destination)
	if err != nil {
		return nil
	}
	targets := []uuid.UUID{}
	for address, dstOwner := range g.owners {
		if prefix.Contains(address) && address.String() != source {
			targets = append(targets, owner, dstOwner)
			if owner != dstOwner {
				targets = append(targets, g.Relay)
			}
		}
	}
	return sortedIDs(targets...)
}
