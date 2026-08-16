package agentaccessguard

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func LockDestination(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, kind string, id uuid.UUID) (bool, error) {
	var err error
	switch kind {
	case "resource":
		_, err = q.LockAgentAccessResourceDestination(ctx, sqlc.LockAgentAccessResourceDestinationParams{ID: id, OrgID: orgID})
	case "group":
		_, err = q.LockAgentAccessGroupDestination(ctx, sqlc.LockAgentAccessGroupDestinationParams{ID: id, OrgID: orgID})
	case "site":
		_, err = q.LockAgentAccessSiteDestination(ctx, sqlc.LockAgentAccessSiteDestinationParams{ID: id, OrgID: orgID})
	case "k8s_service":
		_, err = q.LockAgentAccessK8sServiceDestination(ctx, sqlc.LockAgentAccessK8sServiceDestinationParams{ID: id, OrgID: orgID})
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// LiveDestinationRequests is the shared destructive-action guard. Terminal
// workflow history intentionally does not retain a hard destination FK.
func LiveDestinationRequests(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, kind string, id uuid.UUID) (int64, error) {
	var resource, group, site, service pgtype.UUID
	value := pgtype.UUID{Bytes: id, Valid: true}
	switch kind {
	case "resource":
		resource = value
	case "group":
		group = value
	case "site":
		site = value
	case "k8s_service":
		service = value
	}
	return q.CountLiveAgentAccessRequestsByDestination(ctx, sqlc.CountLiveAgentAccessRequestsByDestinationParams{
		OrgID: orgID, DstResourceID: resource, DstGroupID: group,
		DstSiteID: site, DstK8sServiceID: service,
	})
}

func LiveK8sClusterRequests(ctx context.Context, q *sqlc.Queries, orgID, clusterID uuid.UUID) (int64, error) {
	return q.CountLiveAgentAccessRequestsByK8sCluster(ctx, sqlc.CountLiveAgentAccessRequestsByK8sClusterParams{OrgID: orgID, ClusterID: clusterID})
}

func LockK8sClusterDestinations(ctx context.Context, q *sqlc.Queries, orgID, clusterID uuid.UUID) error {
	_, err := q.LockAgentAccessK8sClusterDestinations(ctx, sqlc.LockAgentAccessK8sClusterDestinationsParams{OrgID: orgID, ClusterID: clusterID})
	return err
}
