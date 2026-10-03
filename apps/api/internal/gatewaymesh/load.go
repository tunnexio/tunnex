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
// routing and policy. Disabled reads need no later-schema tables.
func Load(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, enabled bool) (*Graph, error) {
	if !enabled {
		return nil, nil
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
	return Build(true, gateways, clients, members)
}

func (g *Graph) NodeIDs() []uuid.UUID {
	if g == nil || g.Relay == uuid.Nil {
		return nil
	}
	ids := []uuid.UUID{g.Relay}
	for id := range g.gateways {
		ids = append(ids, id)
	}
	return sortedIDs(ids...)
}
