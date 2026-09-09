package sqlc

// Handwritten composition of generated queries; SQL remains in db/queries.

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ShareConnectivityTopologyLocks retains the existing lock order in one batch.
// The caller must bind Queries to its transaction. Close drains every result and
// propagates errors before the caller may inspect topology or commit.
func (q *Queries) ShareConnectivityTopologyLocks(ctx context.Context, orgID uuid.UUID) error {
	batch := &pgx.Batch{}
	batch.Queue(shareConnectivityHubSet, orgID)
	batch.Queue(shareConnectivityTopologyNodes, orgID)
	batch.Queue(shareConnectivityTopologySites, orgID)
	return q.db.SendBatch(ctx, batch).Close()
}
