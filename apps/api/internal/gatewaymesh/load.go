package gatewaymesh

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
)

// Load shares the same active subject and HA ownership projection between
// routing and policy. Without organization-wide routing, only explicit sandbox
// terminal bindings can supply a transport graph.
func Load(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, enabled bool, sandboxEnabled ...bool) (*Graph, error) {
	var scoped *Graph
	if len(sandboxEnabled) == 1 && sandboxEnabled[0] {
		var err error
		scoped, err = loadScopedSandboxTerminals(ctx, q, orgID)
		if err != nil {
			return nil, err
		}
	}
	if !enabled {
		return scoped, nil
	}
	reserved, err := q.ListReservedSandboxRuntimeGateways(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if len(reserved) > 32 {
		return nil, errors.New("dedicated sandbox gateway capacity exceeded")
	}
	reservedIDs := make([]uuid.UUID, 0, len(reserved))
	for _, row := range reserved {
		if row.SiteID.Valid {
			return nil, errors.New("sandbox runtime gateway has site placement")
		}
		reservedIDs = append(reservedIDs, row.RuntimeGatewayID)
	}
	rows, err := q.ListCrossGatewayGateways(ctx, orgID)
	if err != nil {
		return nil, err
	}
	gateways := make([]Gateway, 0, len(rows))
	for _, row := range rows {
		gateways = append(gateways, Gateway{ID: row.ID, PublicKey: row.WgPublicKey, Endpoint: row.Endpoint})
	}
	subjects, err := q.ListCrossGatewayClients(ctx, orgID)
	if err != nil {
		return nil, err
	}
	pools, err := q.ListCrossGatewayIPv6Pool(ctx, orgID)
	if err != nil {
		return nil, err
	}
	clients := make([]Client, 0, len(subjects))
	for _, row := range subjects {
		if row.AssignedIp != nil {
			client := Client{NodeID: row.NodeID, Address: *row.AssignedIp}
			if len(pools) > 0 && row.Transport == "wireguard" {
				address, e := ipalloc.IPv6DeviceAddr(pools[0], orgID, client.Address)
				if e != nil {
					return nil, e
				}
				client.IPv6Address = address.String()
			}
			clients = append(clients, client)
		}
	}
	hs, err := q.GetOrgHubSet(ctx, orgID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var members []uuid.UUID
	if err == nil {
		// Match the site topology's derive-then-filter boundary: only current
		// site gateway members participate in the existing HA hosting contract.
		siteRows, e := q.ListSiteGatewaysForOrg(ctx, orgID)
		if e != nil {
			return nil, e
		}
		eligible := map[uuid.UUID]bool{}
		for _, row := range siteRows {
			eligible[row.ID] = true
		}
		for _, id := range ActiveOrder(hs.Configured, hs.Demoted) {
			if eligible[id] {
				members = append(members, id)
			}
		}
	}
	return BuildSandboxCompatibleGraph(gateways, clients, members, reservedIDs, scoped)
}

func loadScopedSandboxTerminals(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID) (*Graph, error) {
	rows, err := q.ListScopedSandboxTerminalRoutes(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if len(rows) > 32 {
		return nil, errors.New("scoped sandbox transport capacity exceeded")
	}
	gateways := []Gateway{}
	routes := []SandboxTerminalRoute{}
	for _, row := range rows {
		gateways = append(gateways, Gateway{ID: row.TerminalGatewayID, PublicKey: row.TerminalPublicKey, Endpoint: row.TerminalGatewayEndpoint}, Gateway{ID: row.RuntimeGatewayID, PublicKey: row.RuntimePublicKey, Endpoint: row.RuntimeGatewayEndpoint})
		routes = append(routes, SandboxTerminalRoute{TerminalGatewayID: row.TerminalGatewayID, RuntimeGatewayID: row.RuntimeGatewayID, TerminalAddress: row.TerminalAddress, SandboxAddress: row.SandboxAddress, TerminalGatewayEndpoint: row.TerminalGatewayEndpoint, RuntimeGatewayEndpoint: row.RuntimeGatewayEndpoint})
	}
	return BuildSandboxTerminalGraph(gateways, routes)
}

// HasScopedSandboxTerminals uses the same bounded authority projection as Load.
// It lets site-less gateways include the explicit corridor without opting the
// organization into the ordinary cross-gateway client graph.
func HasScopedSandboxTerminals(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID) (bool, error) {
	rows, err := q.ListScopedSandboxTerminalRoutes(ctx, orgID)
	return len(rows) > 0, err
}

func (g *Graph) NodeIDs() []uuid.UUID {
	if g == nil {
		return nil
	}
	ids := []uuid.UUID{}
	if g.Relay != uuid.Nil {
		ids = append(ids, g.Relay)
		for id := range g.gateways {
			ids = append(ids, id)
		}
	}
	if g.sandboxTerminalGraph != nil {
		ids = append(ids, g.sandboxTerminalGraph.NodeIDs()...)
	}
	return sortedIDs(ids...)
}
