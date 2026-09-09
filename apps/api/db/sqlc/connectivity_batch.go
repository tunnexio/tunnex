package sqlc

// Handwritten composition of generated queries; SQL remains in db/queries.

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ShareConnectivityTopologyLocks retains the existing lock order in one batch.
// The caller must bind Queries to its transaction. Close drains every result and
// propagates errors before the caller may inspect topology or commit.
func (q *Queries) ShareConnectivityTopologyLocks(ctx context.Context, orgID uuid.UUID) error {
	batch := topologyLockBatch(orgID)
	return q.db.SendBatch(ctx, batch).Close()
}

func topologyLockBatch(orgID uuid.UUID) *pgx.Batch {
	batch := &pgx.Batch{}
	batch.Queue(shareConnectivityHubSet, orgID)
	batch.Queue(shareConnectivityTopologyNodes, orgID)
	batch.Queue(shareConnectivityTopologySites, orgID)
	return batch
}

type ConnectivityTopologySnapshot struct {
	Now      time.Time
	Gateways []ListSiteGatewaysForOrgRow
	HubSet   *GetOrgHubSetRow
}

// ReadLockedConnectivityTopology preserves the serial statement order but sends
// the independent reads with their prerequisite locks. Only call on a transaction.
func (q *Queries) ReadLockedConnectivityTopology(ctx context.Context, orgID uuid.UUID) (out ConnectivityTopologySnapshot, err error) {
	batch := topologyLockBatch(orgID)
	batch.Queue(connectivityWallClock)
	batch.Queue(listSiteGatewaysForOrg, orgID)
	batch.Queue(getOrgHubSet, orgID)
	results := q.db.SendBatch(ctx, batch)
	defer func() {
		if closeErr := results.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			out = ConnectivityTopologySnapshot{}
		}
	}()
	for i := 0; i < 3; i++ {
		if _, err = results.Exec(); err != nil {
			return out, err
		}
	}
	if err = results.QueryRow().Scan(&out.Now); err != nil {
		return out, err
	}
	rows, err := results.Query()
	if err != nil {
		return out, err
	}
	out.Gateways, err = pgx.CollectRows(rows, pgx.RowToStructByPos[ListSiteGatewaysForOrgRow])
	if err != nil {
		return out, err
	}
	rows, err = results.Query()
	if err != nil {
		return out, err
	}
	hub, err := pgx.CollectOneRow(rows, pgx.RowToStructByPos[GetOrgHubSetRow])
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.HubSet = &hub
	return out, nil
}
