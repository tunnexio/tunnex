package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrPoolVIPOwnershipDeliveryImmutableConflict means one delivery ID is
	// already durable with a different immutable v2 artifact or expiry.
	ErrPoolVIPOwnershipDeliveryImmutableConflict = errors.New("ownership delivery immutable conflict")
	// ErrPoolVIPOwnershipDeliveryStaleGeneration means a new artifact regresses
	// the durable scope generation. An exact older delivery retry remains valid.
	ErrPoolVIPOwnershipDeliveryStaleGeneration = errors.New("ownership delivery stale promotion generation")
)

var _ PoolVIPOwnershipDeliveryAttestationStore = (*PostgresPoolVIPOwnershipDeliveryStore)(nil)
var _ PoolVIPOwnershipAppliedAttestationReader = (*PostgresPoolVIPOwnershipDeliveryStore)(nil)
var _ PoolVIPOwnershipHandoffDeliveryStore = (*PostgresPoolVIPOwnershipDeliveryStore)(nil)

// IssuePoolVIPOwnershipDeliveryV2 persists one exact capability-2 envelope.
// It shares the scope fence with v1 for monotonic replay safety, but its route
// and applied evidence remain inaccessible to receipt-only v1 callers.
func (s *PostgresPoolVIPOwnershipDeliveryStore) issuePoolVIPOwnershipDeliveryV2(ctx context.Context, envelope PoolVIPOwnershipDeliveryEnvelopeV2, expiresAt time.Time, fenceGeneration bool) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("ownership delivery store is not configured")
	}
	input, err := preparePoolVIPOwnershipDeliveryV2Issue(envelope, expiresAt)
	if err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	return issuePoolVIPOwnershipDeliveryV2Tx(ctx, tx, input, fenceGeneration)
}

// IssuePoolVIPOwnershipDeliveryV2 remains the unbound low-level writer for
// non-handoff callers. Handoff issuance is deliberately available only through
// the leader-session-bound method in pool_vip_ownership_leader_session.go.
func (s *PostgresPoolVIPOwnershipDeliveryStore) IssuePoolVIPOwnershipDeliveryV2(ctx context.Context, envelope PoolVIPOwnershipDeliveryEnvelopeV2, expiresAt time.Time) error {
	return s.issuePoolVIPOwnershipDeliveryV2(ctx, envelope, expiresAt, false)
}

type poolVIPOwnershipDeliveryV2IssueInput struct {
	envelope      PoolVIPOwnershipDeliveryEnvelopeV2
	expiresAt     time.Time
	scopeIdentity string
	ids           poolVIPOwnershipDeliveryIDs
	routes        string
}

func preparePoolVIPOwnershipDeliveryV2Issue(envelope PoolVIPOwnershipDeliveryEnvelopeV2, expiresAt time.Time) (poolVIPOwnershipDeliveryV2IssueInput, error) {
	// A non-serving v2 envelope has zero routes. Persist that as a JSON array,
	// never JSON null, so the durable artifact has one canonical empty shape.
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope); err != nil {
		return poolVIPOwnershipDeliveryV2IssueInput{}, err
	}
	// The validator caps route cardinality and element length before this copy.
	// Do not allocate from an untrusted/invalid issue input.
	envelope.OwnedRoutes = append([]string{}, envelope.OwnedRoutes...)
	expiresAt = canonicalPoolVIPOwnershipDeliveryExpiry(expiresAt)
	if expiresAt.IsZero() || !expiresAt.After(time.Now()) {
		return poolVIPOwnershipDeliveryV2IssueInput{}, fmt.Errorf("ownership delivery expiry must be in the future")
	}
	scopeIdentity, err := poolVIPOwnershipDeliveryScopeIdentityV2(envelope)
	if err != nil {
		return poolVIPOwnershipDeliveryV2IssueInput{}, err
	}
	ids, err := parsePoolVIPOwnershipDeliveryIDs(envelope.PoolVIPOwnershipDeliveryEnvelope)
	if err != nil {
		return poolVIPOwnershipDeliveryV2IssueInput{}, err
	}
	routes, err := json.Marshal(envelope.OwnedRoutes)
	if err != nil {
		return poolVIPOwnershipDeliveryV2IssueInput{}, err
	}
	return poolVIPOwnershipDeliveryV2IssueInput{envelope: envelope, expiresAt: expiresAt, scopeIdentity: scopeIdentity, ids: ids, routes: string(routes)}, nil
}

func issuePoolVIPOwnershipDeliveryV2Tx(ctx context.Context, tx pgx.Tx, input poolVIPOwnershipDeliveryV2IssueInput, fenceGeneration bool) error {
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requirePoolVIPOwnershipScope(ctx, tx, input.ids); err != nil {
		return err
	}
	if fenceGeneration {
		_, stored, storedExpiry, err := scanPoolVIPOwnershipDeliveryV2(tx.QueryRow(ctx, poolVIPOwnershipDeliveryV2Select+`
			WHERE org_id=$1 AND delivery_id=$2 FOR UPDATE`, input.ids.orgID, input.ids.deliveryID))
		if err == nil {
			if !samePoolVIPOwnershipDeliveryV2(stored, storedExpiry, input.envelope, input.expiresAt) {
				return fmt.Errorf("%w: delivery ID replayed with different immutable envelope or expiry", ErrPoolVIPOwnershipDeliveryImmutableConflict)
			}
			return tx.Commit(ctx)
		}
		if err != pgx.ErrNoRows {
			return fmt.Errorf("load conflicting ownership v2 delivery: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO pool_vip_ownership_delivery_states
			(org_id, site_id, cluster_id, pool_id, connector_node_id, scope_identity)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (org_id, site_id, cluster_id, pool_id, connector_node_id) DO NOTHING`,
		input.ids.orgID, input.ids.siteID, input.ids.clusterID, input.ids.poolID, input.ids.connectorNodeID, input.scopeIdentity); err != nil {
		return err
	}
	if fenceGeneration {
		_, state, err := loadPoolVIPOwnershipAckState(ctx, tx, input.ids)
		if err != nil {
			return err
		}
		if state.ScopeIdentity != input.scopeIdentity {
			return fmt.Errorf("stored ownership v2 delivery scope is invalid")
		}
		if input.envelope.PromotionGeneration < state.PromotionGeneration {
			return fmt.Errorf("%w: requested=%d durable=%d", ErrPoolVIPOwnershipDeliveryStaleGeneration, input.envelope.PromotionGeneration, state.PromotionGeneration)
		}
	}
	ct, err := tx.Exec(ctx, `
		INSERT INTO pool_vip_ownership_deliveries
			(org_id, site_id, cluster_id, pool_id, connector_node_id, target_node_id,
			 operation_id, wire_version, manifest_identity, role, promotion_generation,
			 manifest_revision, lease_epoch, delivery_phase, delivery_id, delivery_nonce,
			 owned_routes, expected_route_digest, expected_vip_map_digest, prior_lease_epoch, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
		        $17::jsonb, $18, $19, $20, $21)
		ON CONFLICT (org_id, delivery_id) DO NOTHING`,
		input.ids.orgID, input.ids.siteID, input.ids.clusterID, input.ids.poolID, input.ids.connectorNodeID, input.ids.targetNodeID,
		input.ids.operationID, input.envelope.Version, input.envelope.ManifestIdentity, input.envelope.Role, input.envelope.PromotionGeneration,
		input.envelope.ManifestRevision, input.envelope.LeaseEpoch, input.envelope.DeliveryPhase, input.ids.deliveryID, input.envelope.DeliveryNonce,
		input.routes, input.envelope.ExpectedRouteDigest, input.envelope.ExpectedVIPMapDigest, input.envelope.PriorLeaseEpoch, input.expiresAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 1 {
		return tx.Commit(ctx)
	}
	_, stored, storedExpiry, err := scanPoolVIPOwnershipDeliveryV2(tx.QueryRow(ctx, poolVIPOwnershipDeliveryV2Select+`
		WHERE org_id=$1 AND delivery_id=$2 FOR UPDATE`, input.ids.orgID, input.ids.deliveryID))
	if err != nil {
		return fmt.Errorf("load conflicting ownership v2 delivery: %w", err)
	}
	if !samePoolVIPOwnershipDeliveryV2(stored, storedExpiry, input.envelope, input.expiresAt) {
		return fmt.Errorf("%w: delivery ID replayed with different immutable envelope or expiry", ErrPoolVIPOwnershipDeliveryImmutableConflict)
	}
	return tx.Commit(ctx)
}

// LoadIssuedPoolVIPOwnershipDeliveryV2 selects only unacknowledged,
// unexpired capability-2 work for this exact mTLS principal.
func (s *PostgresPoolVIPOwnershipDeliveryStore) LoadIssuedPoolVIPOwnershipDeliveryV2(ctx context.Context, agent PoolVIPOwnershipAgentIdentity) (PoolVIPOwnershipDeliveryEnvelopeV2, bool, error) {
	if s == nil || s.pool == nil {
		return PoolVIPOwnershipDeliveryEnvelopeV2{}, false, fmt.Errorf("ownership delivery store is not configured")
	}
	if agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil {
		return PoolVIPOwnershipDeliveryEnvelopeV2{}, false, nil
	}
	_, envelope, _, err := scanPoolVIPOwnershipDeliveryV2(s.pool.QueryRow(ctx, `
		WITH pending AS (
			SELECT d.*, row_number() OVER (
				PARTITION BY d.org_id, d.site_id, d.cluster_id, d.pool_id, d.connector_node_id
				ORDER BY d.manifest_revision DESC, d.created_at DESC, d.id DESC
			) AS scope_rank
			FROM pool_vip_ownership_deliveries d
			WHERE d.wire_version=2 AND d.org_id=$1 AND d.target_node_id=$2 AND d.expires_at > clock_timestamp()
			  AND NOT EXISTS (SELECT 1 FROM pool_vip_ownership_delivery_ack_receipts r WHERE r.delivery_row_id=d.id)
		)
		SELECT id, wire_version, org_id::text, site_id::text, cluster_id::text, pool_id::text,
	       connector_node_id::text, target_node_id::text, operation_id::text, manifest_identity,
	       role, promotion_generation, manifest_revision, lease_epoch, delivery_phase,
	       delivery_id::text, delivery_nonce, owned_routes, expected_route_digest,
	       expected_vip_map_digest, prior_lease_epoch, expires_at
		FROM pending WHERE scope_rank=1
		ORDER BY site_id, cluster_id, pool_id, connector_node_id, manifest_revision DESC, created_at DESC, id DESC
		LIMIT 1`, agent.OrgID, agent.NodeID))
	if err == pgx.ErrNoRows {
		return PoolVIPOwnershipDeliveryEnvelopeV2{}, false, nil
	}
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV2{}, false, err
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope); err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV2{}, false, fmt.Errorf("stored ownership v2 delivery is invalid: %w", err)
	}
	return envelope, true, nil
}

// UpdatePoolVIPOwnershipAckV2 atomically binds a validated applied-state ACK
// to its exact v2 delivery and durable replay fence. Duplicate retries retain
// the original control-plane receipt timestamp.
func (s *PostgresPoolVIPOwnershipDeliveryStore) UpdatePoolVIPOwnershipAckV2(ctx context.Context, agent PoolVIPOwnershipAgentIdentity, ack PoolVIPOwnershipDeliveryAckV2, receiptTime time.Time, validate func(PoolVIPOwnershipDeliveryEnvelopeV2, PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error)) (PoolVIPOwnershipAckValidation, error) {
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
	deliveryRowID, envelope, _, err := scanPoolVIPOwnershipDeliveryV2(tx.QueryRow(ctx, poolVIPOwnershipDeliveryV2Select+`
		WHERE wire_version=2 AND org_id=$1 AND target_node_id=$2 AND delivery_id=$3
		  AND expires_at > clock_timestamp() FOR UPDATE`, agent.OrgID, agent.NodeID, deliveryID))
	if err == pgx.ErrNoRows {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("issued ownership v2 delivery is absent, expired, or belongs to another agent")
	}
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope); err != nil {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("stored ownership v2 delivery is invalid: %w", err)
	}
	ids, err := parsePoolVIPOwnershipDeliveryIDs(envelope.PoolVIPOwnershipDeliveryEnvelope)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	stateID, state, err := loadPoolVIPOwnershipAckState(ctx, tx, ids)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	expectedScope, err := poolVIPOwnershipDeliveryScopeIdentityV2(envelope)
	if err != nil || state.ScopeIdentity != expectedScope {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("stored ownership v2 delivery scope is invalid")
	}
	var fingerprint string
	var originalReceipt time.Time
	err = tx.QueryRow(ctx, `SELECT fingerprint, receipt_time FROM pool_vip_ownership_delivery_ack_receipts WHERE delivery_row_id=$1`, deliveryRowID).Scan(&fingerprint, &originalReceipt)
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
	if _, err := tx.Exec(ctx, `UPDATE pool_vip_ownership_delivery_states SET promotion_generation=$2, manifest_revision=$3, lease_epoch=$4 WHERE id=$1`, stateID, int64(result.NextState.PromotionGeneration), int64(result.NextState.ManifestRevision), int64(result.NextState.LeaseEpoch)); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO pool_vip_ownership_delivery_ack_receipts
			(org_id, delivery_row_id, state_id, fingerprint, receipt_time, applied_role,
			 applied_manifest_identity, applied_promotion_generation, applied_manifest_revision,
			 applied_lease_epoch, owned_route_digest, vip_map_digest)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		ids.orgID, deliveryRowID, stateID, receipt.Fingerprint, receipt.ReceiptTime.UTC(), ack.AppliedRole,
		ack.AppliedManifestIdentity, int64(ack.AppliedPromotionGeneration), int64(ack.AppliedManifestRevision),
		int64(ack.AppliedLeaseEpoch), ack.OwnedRouteDigest, ack.VIPMapDigest); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	return result, nil
}

// LoadPoolVIPOwnershipAppliedAttestation returns one exact, unexpired v2
// artifact with validated applied evidence. v1 receipt rows cannot match.
func (s *PostgresPoolVIPOwnershipDeliveryStore) LoadPoolVIPOwnershipAppliedAttestation(ctx context.Context, scope PoolVIPOwnershipAppliedAttestationScope) (PoolVIPOwnershipAppliedAttestation, bool, error) {
	if s == nil || s.pool == nil {
		return PoolVIPOwnershipAppliedAttestation{}, false, fmt.Errorf("ownership delivery store is not configured")
	}
	if err := validPoolVIPOwnershipAppliedAttestationScope(scope); err != nil {
		return PoolVIPOwnershipAppliedAttestation{}, false, err
	}
	var rowID uuid.UUID
	var envelope PoolVIPOwnershipDeliveryEnvelopeV2
	var routes []byte
	var promotionGeneration, manifestRevision, leaseEpoch, priorLeaseEpoch int64
	var appliedPromotionGeneration, appliedManifestRevision, appliedLeaseEpoch int64
	var receiptTime, expiresAt time.Time
	var ack PoolVIPOwnershipDeliveryAckV2
	err := s.pool.QueryRow(ctx, `
		SELECT d.id, d.wire_version, d.org_id::text, d.site_id::text, d.cluster_id::text, d.pool_id::text,
		       d.connector_node_id::text, d.target_node_id::text, d.operation_id::text, d.manifest_identity,
		       d.role, d.promotion_generation, d.manifest_revision, d.lease_epoch, d.delivery_phase,
		       d.delivery_id::text, d.delivery_nonce, d.owned_routes, d.expected_route_digest,
		       d.expected_vip_map_digest, d.prior_lease_epoch, d.expires_at, r.receipt_time, r.applied_role,
		       r.applied_manifest_identity, r.applied_promotion_generation, r.applied_manifest_revision,
		       r.applied_lease_epoch, r.owned_route_digest, r.vip_map_digest
		FROM pool_vip_ownership_deliveries d
		JOIN pool_vip_ownership_delivery_ack_receipts r ON r.delivery_row_id=d.id AND r.org_id=d.org_id
		WHERE d.wire_version=2 AND d.expires_at > clock_timestamp()
		  AND d.org_id=$1 AND d.site_id=$2 AND d.cluster_id=$3 AND d.pool_id=$4
		  AND d.connector_node_id=$5 AND d.target_node_id=$6 AND d.operation_id=$7
		  AND d.manifest_identity=$8 AND d.role=$9 AND d.delivery_phase=$10
		  AND d.promotion_generation=$11 AND d.manifest_revision=$12 AND d.lease_epoch=$13 AND d.delivery_id=$14`,
		scope.OrgID, scope.SiteID, scope.ClusterID, scope.PoolID, scope.ConnectorNodeID, scope.TargetNodeID,
		scope.OperationID, scope.ManifestIdentity, scope.Role, scope.DeliveryPhase, int64(scope.PromotionGeneration),
		int64(scope.ManifestRevision), int64(scope.LeaseEpoch), scope.DeliveryID).Scan(
		&rowID, &envelope.Version, &envelope.OrgID, &envelope.SiteID, &envelope.ClusterID, &envelope.PoolID,
		&envelope.ConnectorNodeID, &envelope.TargetNodeID, &envelope.OperationID, &envelope.ManifestIdentity,
		&envelope.Role, &promotionGeneration, &manifestRevision, &leaseEpoch, &envelope.DeliveryPhase,
		&envelope.DeliveryID, &envelope.DeliveryNonce, &routes, &envelope.ExpectedRouteDigest,
		&envelope.ExpectedVIPMapDigest, &priorLeaseEpoch, &expiresAt, &receiptTime, &ack.AppliedRole,
		&ack.AppliedManifestIdentity, &appliedPromotionGeneration, &appliedManifestRevision,
		&appliedLeaseEpoch, &ack.OwnedRouteDigest, &ack.VIPMapDigest)
	if err == pgx.ErrNoRows {
		return PoolVIPOwnershipAppliedAttestation{}, false, nil
	}
	if err != nil {
		return PoolVIPOwnershipAppliedAttestation{}, false, err
	}
	if err := json.Unmarshal(routes, &envelope.OwnedRoutes); err != nil {
		return PoolVIPOwnershipAppliedAttestation{}, false, fmt.Errorf("stored ownership v2 routes are invalid: %w", err)
	}
	if promotionGeneration < 0 || manifestRevision < 0 || leaseEpoch < 0 || priorLeaseEpoch < 0 || appliedPromotionGeneration < 0 || appliedManifestRevision < 0 || appliedLeaseEpoch < 0 {
		return PoolVIPOwnershipAppliedAttestation{}, false, fmt.Errorf("stored ownership v2 counters are invalid")
	}
	envelope.PromotionGeneration, envelope.ManifestRevision, envelope.LeaseEpoch, envelope.PriorLeaseEpoch = uint64(promotionGeneration), uint64(manifestRevision), uint64(leaseEpoch), uint64(priorLeaseEpoch)
	ack.PoolVIPOwnershipDeliveryAck = PoolVIPOwnershipDeliveryAck{Version: envelope.Version, OrgID: envelope.OrgID, SiteID: envelope.SiteID, ClusterID: envelope.ClusterID, PoolID: envelope.PoolID, ConnectorNodeID: envelope.ConnectorNodeID, TargetNodeID: envelope.TargetNodeID, OperationID: envelope.OperationID, ManifestIdentity: envelope.ManifestIdentity, Role: envelope.Role, PromotionGeneration: envelope.PromotionGeneration, ManifestRevision: envelope.ManifestRevision, LeaseEpoch: envelope.LeaseEpoch, DeliveryPhase: envelope.DeliveryPhase, DeliveryID: envelope.DeliveryID, DeliveryNonce: envelope.DeliveryNonce}
	ack.AppliedPromotionGeneration, ack.AppliedManifestRevision, ack.AppliedLeaseEpoch = uint64(appliedPromotionGeneration), uint64(appliedManifestRevision), uint64(appliedLeaseEpoch)
	agent := PoolVIPOwnershipAgentIdentity{NodeID: uuid.MustParse(envelope.TargetNodeID), OrgID: uuid.MustParse(envelope.OrgID)}
	if _, err := ValidatePoolVIPOwnershipDeliveryAckV2(receiptTime, agent, envelope, ack, PoolVIPOwnershipAckState{}); err != nil {
		return PoolVIPOwnershipAppliedAttestation{}, false, fmt.Errorf("stored ownership v2 attestation is invalid: %w", err)
	}
	return PoolVIPOwnershipAppliedAttestation{Envelope: envelope, Ack: ack, ReceiptTime: receiptTime.UTC(), ExpiresAt: expiresAt.UTC()}, true, nil
}

const poolVIPOwnershipDeliveryV2Select = `
	SELECT id, wire_version, org_id::text, site_id::text, cluster_id::text, pool_id::text,
	       connector_node_id::text, target_node_id::text, operation_id::text, manifest_identity,
	       role, promotion_generation, manifest_revision, lease_epoch, delivery_phase,
	       delivery_id::text, delivery_nonce, owned_routes, expected_route_digest,
	       expected_vip_map_digest, prior_lease_epoch, expires_at
	FROM pool_vip_ownership_deliveries `

func scanPoolVIPOwnershipDeliveryV2(row pgx.Row) (uuid.UUID, PoolVIPOwnershipDeliveryEnvelopeV2, time.Time, error) {
	var rowID uuid.UUID
	var envelope PoolVIPOwnershipDeliveryEnvelopeV2
	var routes []byte
	var promotionGeneration, manifestRevision, leaseEpoch, priorLeaseEpoch int64
	var expiresAt time.Time
	err := row.Scan(&rowID, &envelope.Version, &envelope.OrgID, &envelope.SiteID, &envelope.ClusterID, &envelope.PoolID,
		&envelope.ConnectorNodeID, &envelope.TargetNodeID, &envelope.OperationID, &envelope.ManifestIdentity,
		&envelope.Role, &promotionGeneration, &manifestRevision, &leaseEpoch, &envelope.DeliveryPhase,
		&envelope.DeliveryID, &envelope.DeliveryNonce, &routes, &envelope.ExpectedRouteDigest,
		&envelope.ExpectedVIPMapDigest, &priorLeaseEpoch, &expiresAt)
	if err != nil {
		return uuid.Nil, PoolVIPOwnershipDeliveryEnvelopeV2{}, time.Time{}, err
	}
	if err := json.Unmarshal(routes, &envelope.OwnedRoutes); err != nil {
		return uuid.Nil, PoolVIPOwnershipDeliveryEnvelopeV2{}, time.Time{}, err
	}
	if promotionGeneration < 0 || manifestRevision < 0 || leaseEpoch < 0 || priorLeaseEpoch < 0 {
		return uuid.Nil, PoolVIPOwnershipDeliveryEnvelopeV2{}, time.Time{}, fmt.Errorf("stored ownership v2 counters are invalid")
	}
	envelope.PromotionGeneration, envelope.ManifestRevision, envelope.LeaseEpoch, envelope.PriorLeaseEpoch = uint64(promotionGeneration), uint64(manifestRevision), uint64(leaseEpoch), uint64(priorLeaseEpoch)
	return rowID, envelope, expiresAt, nil
}

func samePoolVIPOwnershipDeliveryV2(stored PoolVIPOwnershipDeliveryEnvelopeV2, storedExpiry time.Time, want PoolVIPOwnershipDeliveryEnvelopeV2, wantExpiry time.Time) bool {
	return stored.PoolVIPOwnershipDeliveryEnvelope == want.PoolVIPOwnershipDeliveryEnvelope && reflect.DeepEqual(stored.OwnedRoutes, want.OwnedRoutes) && stored.ExpectedRouteDigest == want.ExpectedRouteDigest && stored.ExpectedVIPMapDigest == want.ExpectedVIPMapDigest && stored.PriorLeaseEpoch == want.PriorLeaseEpoch && storedExpiry.Equal(wantExpiry)
}

func validPoolVIPOwnershipAppliedAttestationScope(scope PoolVIPOwnershipAppliedAttestationScope) error {
	base := PoolVIPOwnershipDeliveryEnvelope{Version: PoolVIPOwnershipDeliveryVersion, OrgID: scope.OrgID, SiteID: scope.SiteID, ClusterID: scope.ClusterID, PoolID: scope.PoolID, ConnectorNodeID: scope.ConnectorNodeID, TargetNodeID: scope.TargetNodeID, OperationID: scope.OperationID, ManifestIdentity: scope.ManifestIdentity, Role: scope.Role, PromotionGeneration: scope.PromotionGeneration, ManifestRevision: scope.ManifestRevision, LeaseEpoch: scope.LeaseEpoch, DeliveryPhase: scope.DeliveryPhase, DeliveryID: scope.DeliveryID, DeliveryNonce: strings.Repeat("a", 64)}
	return ValidatePoolVIPOwnershipDeliveryEnvelope(base)
}
