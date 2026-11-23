// Package k8sapiaccess reads the cluster API endpoints of K8N-3 (docs/K8N-3-kubectl-access.md) for the
// shared paths that must treat a cluster's API address like an exposed Service's: the policy snapshot,
// the gateway topology, address allocation and the client resolver push.
//
// Every read here first asks whether the database has the 0239 table. The control plane also runs
// against a schema that has not been migrated that far (this repository tests today's code at earlier
// schema versions on purpose); there the feature has no data, and naming the table would fail the whole
// read. So "no table" is "no API endpoints", never an error.
package k8sapiaccess

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// EnabledEndpoints returns the organization's cluster API endpoints whose API access is on.
func EnabledEndpoints(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID) ([]sqlc.ListEnabledK8sAPIEndpointsForOrgRow, error) {
	present, err := q.K8sAPIAccessSchemaPresent(ctx)
	if err != nil || !present {
		return nil, err
	}
	return q.ListEnabledK8sAPIEndpointsForOrg(ctx, orgID)
}

// EndpointVIPs returns the address of the cluster's API while API access is on (zero or one address).
// Every address allocation in the cluster works around it.
func EndpointVIPs(ctx context.Context, q *sqlc.Queries, orgID, clusterID uuid.UUID) ([]string, error) {
	present, err := q.K8sAPIAccessSchemaPresent(ctx)
	if err != nil || !present {
		return nil, err
	}
	return q.ListK8sAPIEndpointVIPsInCluster(ctx, sqlc.ListK8sAPIEndpointVIPsInClusterParams{OrgID: orgID, ClusterID: clusterID})
}

// ServedZones returns the zones of clusters whose API access is on and whose gateway is resolved.
func ServedZones(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID) ([]sqlc.ListK8sAPIServedZonesForOrgRow, error) {
	present, err := q.K8sAPIAccessSchemaPresent(ctx)
	if err != nil || !present {
		return nil, err
	}
	return q.ListK8sAPIServedZonesForOrg(ctx, orgID)
}

// Enabled reports whether API access is on for one cluster.
func Enabled(ctx context.Context, q *sqlc.Queries, orgID, clusterID uuid.UUID) (bool, error) {
	present, err := q.K8sAPIAccessSchemaPresent(ctx)
	if err != nil || !present {
		return false, err
	}
	endpoint, err := q.GetK8sAPIEndpointForCluster(ctx, sqlc.GetK8sAPIEndpointForClusterParams{OrgID: orgID, ClusterID: clusterID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return endpoint.Enabled, nil
}

// RuleCount returns how many rules name the cluster's API, whatever their state.
func RuleCount(ctx context.Context, q *sqlc.Queries, orgID, clusterID uuid.UUID) (int64, error) {
	present, err := q.K8sAPIAccessSchemaPresent(ctx)
	if err != nil || !present {
		return 0, err
	}
	return q.CountK8sAPIPolicyRulesForCluster(ctx, sqlc.CountK8sAPIPolicyRulesForClusterParams{OrgID: orgID, ClusterID: clusterID})
}
