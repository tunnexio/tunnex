package nodes

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	k8sServiceInventoryFreshFor                      = 90 * time.Second
	k8sServiceInventoryMaxAge                        = 90 * time.Second
	k8sServiceInventoryRetainedUnreferencedSnapshots = 20
)

var _ K8sServiceInventoryStore = (*PostgresK8sServiceInventoryStore)(nil)

type PostgresK8sServiceInventoryStore struct{ pool *pgxpool.Pool }

func NewPostgresK8sServiceInventoryStore(pool *pgxpool.Pool) *PostgresK8sServiceInventoryStore {
	return &PostgresK8sServiceInventoryStore{pool: pool}
}

// WriteK8sServiceInventory atomically advances the existing UID replay ledger
// and writes one immutable inventory snapshot. Thus every public inventory row
// is tied to the exact current reporter incarnation and replay sequence.
func (s *PostgresK8sServiceInventoryStore) WriteK8sServiceInventory(ctx context.Context, agent K8sServiceUIDObservationAgent, report K8sServiceInventoryReport, receivedAt time.Time) (K8sServiceInventoryWriteResult, error) {
	if s == nil || s.pool == nil || agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil || receivedAt.IsZero() || report.Sequence > math.MaxInt64 {
		return K8sServiceInventoryWriteResult{}, ErrK8sServiceInventoryInvalid
	}
	canonical, err := ValidateK8sServiceInventoryReport(report)
	if err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	receivedAt = receivedAt.UTC()
	if canonical.ObservedAt.After(receivedAt.Add(5 * time.Second)) {
		return K8sServiceInventoryWriteResult{}, ErrK8sServiceInventoryInvalid
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	scope, err := resolveSelectedK8sServiceUIDObservationScope(ctx, tx, agent)
	if err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	scopeIdentity := k8sServiceUIDObservationScopeIdentity(scope)
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_uid_observation_replay_states
		(org_id,site_id,cluster_id,connector_node_id,scope_identity) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (org_id,site_id,cluster_id,connector_node_id) DO NOTHING`, scope.OrgID, scope.SiteID, scope.ClusterID, scope.ConnectorNodeID, scopeIdentity); err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	replayStateID, state, err := loadK8sServiceUIDObservationReplayState(ctx, tx, scope, scopeIdentity)
	if err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	ledgerID, current, retired, err := loadK8sServiceUIDObservationLedger(ctx, tx, scope)
	if err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	state.Current, state.Retired = current, retired
	if _, seen := state.Seen[canonical.Sequence]; seen {
		var reportID uuid.UUID
		var digest string
		err := tx.QueryRow(ctx, `SELECT id,digest FROM k8s_service_inventory_reports WHERE replay_state_id=$1 AND replay_sequence=$2`, replayStateID, int64(canonical.Sequence)).Scan(&reportID, &digest)
		if err != nil || digest != canonical.Digest {
			return K8sServiceInventoryWriteResult{}, ErrK8sServiceInventoryInvalid
		}
		if err := tx.Commit(ctx); err != nil {
			return K8sServiceInventoryWriteResult{}, err
		}
		return K8sServiceInventoryWriteResult{Duplicate: true, ReportID: reportID}, nil
	}
	if canonical.Sequence <= state.Sequence {
		return K8sServiceInventoryWriteResult{}, ErrK8sServiceUIDObservationStale
	}
	if receivedAt.Sub(canonical.ObservedAt) > k8sServiceInventoryMaxAge {
		return K8sServiceInventoryWriteResult{}, ErrK8sServiceInventoryInvalid
	}
	uidReport := inventoryUIDObservationReport(canonical)
	validation, err := validateCanonicalK8sServiceUIDObservations(receivedAt, agent, scope, uidReport, state)
	if err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	if validation.Duplicate {
		return K8sServiceInventoryWriteResult{}, ErrK8sServiceInventoryInvalid
	}
	if err := validK8sServiceUIDObservationStoreTransition(scopeIdentity, uidReport, state, validation); err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	if err := persistK8sServiceUIDObservationState(ctx, tx, replayStateID, ledgerID, scope.OrgID, uidReport, validation.NextState); err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	generation, err := currentK8sServiceInventoryGeneration(ctx, tx, scope)
	if err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	reportID := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_inventory_reports
		(id,org_id,site_id,cluster_id,connector_node_id,replay_state_id,replay_sequence,promotion_generation,digest,service_count,observed_at,received_at,fresh_until)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, reportID, scope.OrgID, scope.SiteID, scope.ClusterID, scope.ConnectorNodeID, replayStateID, int64(canonical.Sequence), generation, canonical.Digest, len(canonical.Services), canonical.ObservedAt, receivedAt, receivedAt.Add(k8sServiceInventoryFreshFor)); err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	for _, service := range canonical.Services {
		inventoryRef := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_inventory_items
			(report_id,org_id,cluster_id,inventory_ref,namespace,service,service_uid,port_count)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, reportID, scope.OrgID, scope.ClusterID, inventoryRef, service.Namespace, service.Service, service.UID, len(service.Ports)); err != nil {
			return K8sServiceInventoryWriteResult{}, err
		}
		for _, port := range service.Ports {
			var name any
			if port.Name != "" {
				name = port.Name
			}
			if _, err := tx.Exec(ctx, `INSERT INTO k8s_service_inventory_ports
				(report_id,inventory_ref,port_ref,name,protocol,service_port)
				VALUES ($1,$2,$3,$4,$5,$6)`, reportID, inventoryRef, uuid.New(), name, port.Protocol, port.Port); err != nil {
				return K8sServiceInventoryWriteResult{}, err
			}
		}
	}
	var prunedSnapshots int64
	if err := tx.QueryRow(ctx, `SELECT k8s_service_inventory_prune($1,$2,$3)`,
		scope.OrgID, scope.ClusterID, k8sServiceInventoryRetainedUnreferencedSnapshots).Scan(&prunedSnapshots); err != nil {
		return K8sServiceInventoryWriteResult{}, fmt.Errorf("%w: %v", ErrK8sServiceInventoryRetention, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return K8sServiceInventoryWriteResult{}, err
	}
	return K8sServiceInventoryWriteResult{ReportID: reportID, PrunedSnapshots: prunedSnapshots}, nil
}

func inventoryUIDObservationReport(report K8sServiceInventoryReport) K8sServiceUIDObservationReport {
	// Absence from this supported-port inventory is not a deletion claim: a
	// Service may still exist with only unsupported/no ports. The exact UID
	// observation channel remains the authority for explicit deletes, while a
	// replacement UID reported here still retires the prior incarnation.
	observations := make([]K8sServiceUIDObservation, 0, len(report.Services))
	for _, service := range report.Services {
		observations = append(observations, K8sServiceUIDObservation{Namespace: service.Namespace, Service: service.Service, UID: service.UID, State: "live"})
	}
	sort.Slice(observations, func(i, j int) bool {
		a, b := observations[i], observations[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.UID != b.UID {
			return a.UID < b.UID
		}
		return a.State < b.State
	})
	return K8sServiceUIDObservationReport{Version: K8sServiceUIDObservationVersion, Sequence: report.Sequence, Digest: K8sServiceUIDObservationDigest(report.Sequence, observations), Observations: observations}
}

func currentK8sServiceInventoryGeneration(ctx context.Context, tx pgx.Tx, scope K8sServiceUIDObservationScope) (int64, error) {
	var generation int64
	err := tx.QueryRow(ctx, `SELECT CASE WHEN c.connector_pool_id IS NULL THEN 0 ELSE p.generation END
		FROM k8s_clusters c LEFT JOIN k8s_connector_pools p ON p.id=c.connector_pool_id AND p.org_id=c.org_id AND p.site_id=c.site_id
		WHERE c.id=$1 AND c.org_id=$2 AND c.site_id=$3
		  AND ((c.connector_pool_id IS NULL AND c.connector_node_id=$4)
		    OR (c.connector_node_id IS NULL AND p.active_node_id=$4 AND p.generation>0))
		`, scope.ClusterID, scope.OrgID, scope.SiteID, scope.ConnectorNodeID).Scan(&generation)
	if err != nil || generation < 0 {
		return 0, fmt.Errorf("current Kubernetes inventory reporter generation unavailable")
	}
	return generation, nil
}
