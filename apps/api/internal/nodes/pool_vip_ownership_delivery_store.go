package nodes

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresPoolVIPOwnershipDeliveryStore is the only durable owner of issued
// ownership deliveries and their acknowledgement fences. It intentionally has
// no background work: callers issue envelopes and invoke cleanup explicitly.
type PostgresPoolVIPOwnershipDeliveryStore struct {
	pool                    *pgxpool.Pool
	leaderBoundPreWriteHook func(context.Context, *pgxpool.Conn) error // test seam; never configured in production
}

var _ PoolVIPOwnershipDeliveryStore = (*PostgresPoolVIPOwnershipDeliveryStore)(nil)
var _ PoolVIPOwnershipDeliveryProjectionReader = (*PostgresPoolVIPOwnershipDeliveryStore)(nil)

func NewPostgresPoolVIPOwnershipDeliveryStore(pool *pgxpool.Pool) *PostgresPoolVIPOwnershipDeliveryStore {
	return &PostgresPoolVIPOwnershipDeliveryStore{pool: pool}
}

// IssuePoolVIPOwnershipDelivery persists one exact v1 envelope until expiresAt.
// It creates the durable scope fence before the delivery row, so concurrent ACKs
// for sibling deliveries serialize even after an API restart.
func (s *PostgresPoolVIPOwnershipDeliveryStore) IssuePoolVIPOwnershipDelivery(ctx context.Context, envelope PoolVIPOwnershipDeliveryEnvelope, expiresAt time.Time) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("ownership delivery store is not configured")
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelope(envelope); err != nil {
		return err
	}
	expiresAt = canonicalPoolVIPOwnershipDeliveryExpiry(expiresAt)
	if expiresAt.IsZero() || !expiresAt.After(time.Now()) {
		return fmt.Errorf("ownership delivery expiry must be in the future")
	}
	scopeIdentity, err := PoolVIPOwnershipDeliveryScopeIdentity(envelope)
	if err != nil {
		return err
	}
	ids, err := parsePoolVIPOwnershipDeliveryIDs(envelope)
	if err != nil {
		return err
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requirePoolVIPOwnershipScope(ctx, tx, ids); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO pool_vip_ownership_delivery_states
			(org_id, site_id, cluster_id, pool_id, connector_node_id, scope_identity)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (org_id, site_id, cluster_id, pool_id, connector_node_id) DO NOTHING`,
		ids.orgID, ids.siteID, ids.clusterID, ids.poolID, ids.connectorNodeID, scopeIdentity); err != nil {
		return err
	}
	ct, err := tx.Exec(ctx, `
		INSERT INTO pool_vip_ownership_deliveries
			(org_id, site_id, cluster_id, pool_id, connector_node_id, target_node_id,
			 operation_id, wire_version, manifest_identity, role, promotion_generation,
			 manifest_revision, lease_epoch, delivery_phase, delivery_id, delivery_nonce, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (org_id, delivery_id) DO NOTHING`,
		ids.orgID, ids.siteID, ids.clusterID, ids.poolID, ids.connectorNodeID, ids.targetNodeID,
		ids.operationID, envelope.Version, envelope.ManifestIdentity, envelope.Role, envelope.PromotionGeneration,
		envelope.ManifestRevision, envelope.LeaseEpoch, envelope.DeliveryPhase, ids.deliveryID, envelope.DeliveryNonce, expiresAt.UTC())
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 1 {
		return tx.Commit(ctx)
	}
	_, stored, storedExpiry, err := scanPoolVIPOwnershipDelivery(tx.QueryRow(ctx, `
		SELECT id, wire_version, org_id::text, site_id::text, cluster_id::text, pool_id::text,
		       connector_node_id::text, target_node_id::text, operation_id::text, manifest_identity,
		       role, promotion_generation, manifest_revision, lease_epoch, delivery_phase,
		       delivery_id::text, delivery_nonce, expires_at
		FROM pool_vip_ownership_deliveries
		WHERE org_id=$1 AND delivery_id=$2
		FOR UPDATE`, ids.orgID, ids.deliveryID))
	if err != nil {
		return fmt.Errorf("load conflicting ownership delivery: %w", err)
	}
	if !samePoolVIPOwnershipDelivery(stored, storedExpiry, envelope, expiresAt) {
		return fmt.Errorf("ownership delivery ID replayed with different immutable envelope or expiry")
	}
	return tx.Commit(ctx)
}

// LoadPoolVIPOwnershipDeliveryProjection reads one exact operation/artifact
// delivery in its full org/site/pool scope. Receipt presence means only that
// the agent echoed the envelope; it is not applied readiness or serving proof.
func (s *PostgresPoolVIPOwnershipDeliveryStore) LoadPoolVIPOwnershipDeliveryProjection(ctx context.Context, scope PoolVIPOwnershipDeliveryReadScope) (PoolVIPOwnershipDeliveryProjection, bool, error) {
	if s == nil || s.pool == nil {
		return PoolVIPOwnershipDeliveryProjection{}, false, fmt.Errorf("ownership delivery store is not configured")
	}
	ids, err := parsePoolVIPOwnershipDeliveryReadScope(scope)
	if err != nil {
		return PoolVIPOwnershipDeliveryProjection{}, false, err
	}
	_, envelope, expiresAt, receiptTime, err := scanPoolVIPOwnershipDeliveryProjection(s.pool.QueryRow(ctx, `
		SELECT d.id, d.wire_version, d.org_id::text, d.site_id::text, d.cluster_id::text, d.pool_id::text,
		       d.connector_node_id::text, d.target_node_id::text, d.operation_id::text, d.manifest_identity,
		       d.role, d.promotion_generation, d.manifest_revision, d.lease_epoch, d.delivery_phase,
		       d.delivery_id::text, d.delivery_nonce, d.expires_at, r.receipt_time
		FROM pool_vip_ownership_deliveries d
		LEFT JOIN pool_vip_ownership_delivery_ack_receipts r
		  ON r.delivery_row_id=d.id AND r.org_id=d.org_id
		WHERE d.org_id=$1 AND d.site_id=$2 AND d.pool_id=$3 AND d.operation_id=$4
		  AND d.manifest_identity=$5 AND d.delivery_id=$6`,
		ids.orgID, ids.siteID, ids.poolID, ids.operationID, scope.ManifestIdentity, ids.deliveryID))
	if err == pgx.ErrNoRows {
		return PoolVIPOwnershipDeliveryProjection{}, false, nil
	}
	if err != nil {
		return PoolVIPOwnershipDeliveryProjection{}, false, err
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelope(envelope); err != nil {
		return PoolVIPOwnershipDeliveryProjection{}, false, fmt.Errorf("stored ownership delivery is invalid: %w", err)
	}
	projection := PoolVIPOwnershipDeliveryProjection{Envelope: envelope, ExpiresAt: expiresAt.UTC()}
	if receiptTime != nil {
		projection.Receipt = &PoolVIPOwnershipDeliveryReceiptProjection{ReceiptTime: receiptTime.UTC()}
	}
	return projection, true, nil
}

func (s *PostgresPoolVIPOwnershipDeliveryStore) LoadIssuedPoolVIPOwnershipDelivery(ctx context.Context, agent PoolVIPOwnershipAgentIdentity) (PoolVIPOwnershipDeliveryEnvelope, bool, error) {
	if s == nil || s.pool == nil {
		return PoolVIPOwnershipDeliveryEnvelope{}, false, fmt.Errorf("ownership delivery store is not configured")
	}
	if agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil {
		return PoolVIPOwnershipDeliveryEnvelope{}, false, nil
	}
	_, envelope, _, err := scanPoolVIPOwnershipDelivery(s.pool.QueryRow(ctx, `
		WITH pending AS (
			SELECT d.*, row_number() OVER (
				PARTITION BY d.org_id, d.site_id, d.cluster_id, d.pool_id, d.connector_node_id
				ORDER BY d.manifest_revision DESC, d.created_at DESC, d.id DESC
			) AS scope_rank
			FROM pool_vip_ownership_deliveries d
			WHERE d.wire_version=1 AND d.org_id=$1 AND d.target_node_id=$2 AND d.expires_at > clock_timestamp()
			  AND NOT EXISTS (
				SELECT 1 FROM pool_vip_ownership_delivery_ack_receipts r
				WHERE r.delivery_row_id=d.id
			  )
		)
		SELECT id, wire_version, org_id::text, site_id::text, cluster_id::text, pool_id::text,
		       connector_node_id::text, target_node_id::text, operation_id::text, manifest_identity,
		       role, promotion_generation, manifest_revision, lease_epoch, delivery_phase,
		       delivery_id::text, delivery_nonce, expires_at
		FROM pending
		WHERE scope_rank=1
		ORDER BY site_id, cluster_id, pool_id, connector_node_id, manifest_revision DESC, created_at DESC, id DESC
		LIMIT 1`, agent.OrgID, agent.NodeID))
	if err == pgx.ErrNoRows {
		return PoolVIPOwnershipDeliveryEnvelope{}, false, nil
	}
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelope{}, false, err
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelope(envelope); err != nil {
		return PoolVIPOwnershipDeliveryEnvelope{}, false, fmt.Errorf("stored ownership delivery is invalid: %w", err)
	}
	return envelope, true, nil
}

// UpdatePoolVIPOwnershipAck atomically loads the exact issued delivery, locks
// its scope fence, invokes validate, and persists the accepted state/receipt.
// There is no process-local replay state: a second API replica sees the same
// receipt and returns the pure validator's original receipt time.
func (s *PostgresPoolVIPOwnershipDeliveryStore) UpdatePoolVIPOwnershipAck(ctx context.Context, agent PoolVIPOwnershipAgentIdentity, ack PoolVIPOwnershipDeliveryAck, receiptTime time.Time, validate func(PoolVIPOwnershipDeliveryEnvelope, PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error)) (PoolVIPOwnershipAckValidation, error) {
	if s == nil || s.pool == nil || validate == nil {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("ownership delivery store is not configured")
	}
	if agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil || receiptTime.IsZero() {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("invalid acknowledgement principal or receipt time")
	}
	deliveryID, err := uuid.Parse(ack.DeliveryID)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("invalid acknowledgement delivery ID")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	deliveryRowID, envelope, _, err := scanPoolVIPOwnershipDelivery(tx.QueryRow(ctx, `
		SELECT id, wire_version, org_id::text, site_id::text, cluster_id::text, pool_id::text,
		       connector_node_id::text, target_node_id::text, operation_id::text, manifest_identity,
		       role, promotion_generation, manifest_revision, lease_epoch, delivery_phase,
		       delivery_id::text, delivery_nonce, expires_at
		FROM pool_vip_ownership_deliveries
		WHERE wire_version=1 AND org_id=$1 AND target_node_id=$2 AND delivery_id=$3 AND expires_at > clock_timestamp()
		FOR UPDATE`, agent.OrgID, agent.NodeID, deliveryID))
	if err == pgx.ErrNoRows {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("issued ownership delivery is absent, expired, or belongs to another agent")
	}
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelope(envelope); err != nil {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("stored ownership delivery is invalid: %w", err)
	}
	ids, err := parsePoolVIPOwnershipDeliveryIDs(envelope)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	stateID, state, err := loadPoolVIPOwnershipAckState(ctx, tx, ids)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	expectedScope, err := PoolVIPOwnershipDeliveryScopeIdentity(envelope)
	if err != nil || state.ScopeIdentity != expectedScope {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("stored ownership delivery scope is invalid")
	}
	var fingerprint string
	var originalReceipt time.Time
	err = tx.QueryRow(ctx, `
		SELECT fingerprint, receipt_time
		FROM pool_vip_ownership_delivery_ack_receipts
		WHERE delivery_row_id=$1`, deliveryRowID).Scan(&fingerprint, &originalReceipt)
	if err == nil {
		state.Seen = map[string]PoolVIPOwnershipAckReceipt{ack.DeliveryID: {Fingerprint: fingerprint, ReceiptTime: originalReceipt}}
	} else if err != pgx.ErrNoRows {
		return PoolVIPOwnershipAckValidation{}, err
	}
	result, err := validate(envelope, state)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if result.NextState.ScopeIdentity != state.ScopeIdentity || result.NextState.PromotionGeneration > math.MaxInt64 || result.NextState.ManifestRevision > math.MaxInt64 || result.NextState.LeaseEpoch > math.MaxInt64 {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("invalid acknowledgement state transition")
	}
	if result.Duplicate {
		if err := tx.Commit(ctx); err != nil {
			return PoolVIPOwnershipAckValidation{}, err
		}
		return result, nil
	}
	receipt, ok := result.NextState.Seen[ack.DeliveryID]
	if !ok || receipt.Fingerprint == "" || receipt.ReceiptTime.IsZero() {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("validator returned no acknowledgement receipt")
	}
	if _, err := tx.Exec(ctx, `
		UPDATE pool_vip_ownership_delivery_states
		SET promotion_generation=$2, manifest_revision=$3, lease_epoch=$4
		WHERE id=$1`, stateID, int64(result.NextState.PromotionGeneration), int64(result.NextState.ManifestRevision), int64(result.NextState.LeaseEpoch)); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO pool_vip_ownership_delivery_ack_receipts
			(org_id, delivery_row_id, state_id, fingerprint, receipt_time)
		VALUES ($1, $2, $3, $4, $5)`, ids.orgID, deliveryRowID, stateID, receipt.Fingerprint, receipt.ReceiptTime.UTC()); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	return result, nil
}

// CleanupExpiredPoolVIPOwnershipDeliveries deletes expired issued envelopes and
// their receipt rows. It intentionally retains delivery_states: that monotonic
// fence is what prevents an old generation from becoming acceptable after TTL
// cleanup or a server restart.
func (s *PostgresPoolVIPOwnershipDeliveryStore) CleanupExpiredPoolVIPOwnershipDeliveries(ctx context.Context, before time.Time) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, fmt.Errorf("ownership delivery store is not configured")
	}
	ct, err := s.pool.Exec(ctx, `DELETE FROM pool_vip_ownership_deliveries WHERE expires_at <= $1`, before.UTC())
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

func canonicalPoolVIPOwnershipDeliveryExpiry(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func samePoolVIPOwnershipDelivery(stored PoolVIPOwnershipDeliveryEnvelope, storedExpiry time.Time, want PoolVIPOwnershipDeliveryEnvelope, wantExpiry time.Time) bool {
	return stored == want && storedExpiry.Equal(wantExpiry)
}

type poolVIPOwnershipDeliveryIDs struct {
	orgID, siteID, clusterID, poolID, connectorNodeID, targetNodeID, operationID, deliveryID uuid.UUID
}

type poolVIPOwnershipDeliveryReadIDs struct {
	orgID, siteID, poolID, operationID, deliveryID uuid.UUID
}

func parsePoolVIPOwnershipDeliveryReadScope(scope PoolVIPOwnershipDeliveryReadScope) (poolVIPOwnershipDeliveryReadIDs, error) {
	values := []string{scope.OrgID, scope.SiteID, scope.PoolID, scope.OperationID, scope.DeliveryID}
	parsed := make([]uuid.UUID, len(values))
	for i, value := range values {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return poolVIPOwnershipDeliveryReadIDs{}, fmt.Errorf("invalid ownership delivery read scope")
		}
		parsed[i] = id
	}
	if !poolVIPOwnershipIdentityHexRE.MatchString(scope.ManifestIdentity) {
		return poolVIPOwnershipDeliveryReadIDs{}, fmt.Errorf("invalid ownership delivery read scope")
	}
	return poolVIPOwnershipDeliveryReadIDs{parsed[0], parsed[1], parsed[2], parsed[3], parsed[4]}, nil
}

func parsePoolVIPOwnershipDeliveryIDs(envelope PoolVIPOwnershipDeliveryEnvelope) (poolVIPOwnershipDeliveryIDs, error) {
	values := []string{envelope.OrgID, envelope.SiteID, envelope.ClusterID, envelope.PoolID, envelope.ConnectorNodeID, envelope.TargetNodeID, envelope.OperationID, envelope.DeliveryID}
	parsed := make([]uuid.UUID, len(values))
	for i, value := range values {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return poolVIPOwnershipDeliveryIDs{}, fmt.Errorf("invalid ownership delivery identifier")
		}
		parsed[i] = id
	}
	return poolVIPOwnershipDeliveryIDs{parsed[0], parsed[1], parsed[2], parsed[3], parsed[4], parsed[5], parsed[6], parsed[7]}, nil
}

func requirePoolVIPOwnershipScope(ctx context.Context, tx pgx.Tx, ids poolVIPOwnershipDeliveryIDs) error {
	nodes := []uuid.UUID{ids.connectorNodeID}
	if ids.targetNodeID != ids.connectorNodeID {
		nodes = append(nodes, ids.targetNodeID)
	}
	var count int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM k8s_connector_pool_members
		WHERE pool_id=$1 AND org_id=$2 AND site_id=$3 AND node_id = ANY($4)`,
		ids.poolID, ids.orgID, ids.siteID, nodes).Scan(&count); err != nil {
		return err
	}
	if count != len(nodes) {
		return fmt.Errorf("ownership delivery connector or target node is outside the exact pool scope")
	}
	return nil
}

func loadPoolVIPOwnershipAckState(ctx context.Context, tx pgx.Tx, ids poolVIPOwnershipDeliveryIDs) (uuid.UUID, PoolVIPOwnershipAckState, error) {
	var stateID uuid.UUID
	var promotionGeneration, manifestRevision, leaseEpoch int64
	var scopeIdentity string
	err := tx.QueryRow(ctx, `
		SELECT id, scope_identity, promotion_generation, manifest_revision, lease_epoch
		FROM pool_vip_ownership_delivery_states
		WHERE org_id=$1 AND site_id=$2 AND cluster_id=$3 AND pool_id=$4 AND connector_node_id=$5
		FOR UPDATE`, ids.orgID, ids.siteID, ids.clusterID, ids.poolID, ids.connectorNodeID).Scan(&stateID, &scopeIdentity, &promotionGeneration, &manifestRevision, &leaseEpoch)
	if err != nil {
		return uuid.Nil, PoolVIPOwnershipAckState{}, err
	}
	if promotionGeneration < 0 || manifestRevision < 0 || leaseEpoch < 0 {
		return uuid.Nil, PoolVIPOwnershipAckState{}, fmt.Errorf("stored ownership delivery state is invalid")
	}
	return stateID, PoolVIPOwnershipAckState{
		ScopeIdentity: scopeIdentity, PromotionGeneration: uint64(promotionGeneration),
		ManifestRevision: uint64(manifestRevision), LeaseEpoch: uint64(leaseEpoch),
	}, nil
}

func scanPoolVIPOwnershipDelivery(row pgx.Row) (uuid.UUID, PoolVIPOwnershipDeliveryEnvelope, time.Time, error) {
	var rowID uuid.UUID
	var envelope PoolVIPOwnershipDeliveryEnvelope
	var promotionGeneration, manifestRevision, leaseEpoch int64
	var expiresAt time.Time
	err := row.Scan(&rowID, &envelope.Version, &envelope.OrgID, &envelope.SiteID, &envelope.ClusterID, &envelope.PoolID,
		&envelope.ConnectorNodeID, &envelope.TargetNodeID, &envelope.OperationID, &envelope.ManifestIdentity,
		&envelope.Role, &promotionGeneration, &manifestRevision, &leaseEpoch, &envelope.DeliveryPhase,
		&envelope.DeliveryID, &envelope.DeliveryNonce, &expiresAt)
	if err != nil {
		return uuid.Nil, PoolVIPOwnershipDeliveryEnvelope{}, time.Time{}, err
	}
	if promotionGeneration < 0 || manifestRevision < 0 || leaseEpoch < 0 {
		return uuid.Nil, PoolVIPOwnershipDeliveryEnvelope{}, time.Time{}, fmt.Errorf("stored ownership delivery counters are invalid")
	}
	envelope.PromotionGeneration = uint64(promotionGeneration)
	envelope.ManifestRevision = uint64(manifestRevision)
	envelope.LeaseEpoch = uint64(leaseEpoch)
	return rowID, envelope, expiresAt, nil
}

func scanPoolVIPOwnershipDeliveryProjection(row pgx.Row) (uuid.UUID, PoolVIPOwnershipDeliveryEnvelope, time.Time, *time.Time, error) {
	var rowID uuid.UUID
	var envelope PoolVIPOwnershipDeliveryEnvelope
	var promotionGeneration, manifestRevision, leaseEpoch int64
	var expiresAt time.Time
	var receiptTime *time.Time
	err := row.Scan(&rowID, &envelope.Version, &envelope.OrgID, &envelope.SiteID, &envelope.ClusterID, &envelope.PoolID,
		&envelope.ConnectorNodeID, &envelope.TargetNodeID, &envelope.OperationID, &envelope.ManifestIdentity,
		&envelope.Role, &promotionGeneration, &manifestRevision, &leaseEpoch, &envelope.DeliveryPhase,
		&envelope.DeliveryID, &envelope.DeliveryNonce, &expiresAt, &receiptTime)
	if err != nil {
		return uuid.Nil, PoolVIPOwnershipDeliveryEnvelope{}, time.Time{}, nil, err
	}
	if promotionGeneration < 0 || manifestRevision < 0 || leaseEpoch < 0 {
		return uuid.Nil, PoolVIPOwnershipDeliveryEnvelope{}, time.Time{}, nil, fmt.Errorf("stored ownership delivery counters are invalid")
	}
	envelope.PromotionGeneration = uint64(promotionGeneration)
	envelope.ManifestRevision = uint64(manifestRevision)
	envelope.LeaseEpoch = uint64(leaseEpoch)
	return rowID, envelope, expiresAt, receiptTime, nil
}
