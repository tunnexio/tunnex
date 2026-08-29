package nodes

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var _ PoolVIPOwnershipDeliveryHandoffStore = (*PostgresPoolVIPOwnershipDeliveryStore)(nil)

type poolVIPOwnershipDeliveryV3IssueInput struct {
	envelope      PoolVIPOwnershipDeliveryEnvelopeV3
	ids           poolVIPOwnershipDeliveryIDs
	scopeIdentity string
	routes        []byte
	manifest      []byte
}

func preparePoolVIPOwnershipDeliveryV3Issue(envelope PoolVIPOwnershipDeliveryEnvelopeV3) (poolVIPOwnershipDeliveryV3IssueInput, error) {
	if !envelope.ExpiresAt.Equal(canonicalPoolVIPOwnershipDeliveryExpiry(envelope.ExpiresAt)) || !envelope.Manifest.LeaseExpiresAt.Equal(envelope.ExpiresAt) {
		return poolVIPOwnershipDeliveryV3IssueInput{}, fmt.Errorf("ownership handoff expiry must be canonical CP time")
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		return poolVIPOwnershipDeliveryV3IssueInput{}, err
	}
	if !envelope.ExpiresAt.After(time.Now()) {
		return poolVIPOwnershipDeliveryV3IssueInput{}, fmt.Errorf("ownership handoff expiry must be in the future")
	}
	ids, err := parsePoolVIPOwnershipDeliveryIDs(envelope.PoolVIPOwnershipDeliveryEnvelope)
	if err != nil {
		return poolVIPOwnershipDeliveryV3IssueInput{}, err
	}
	scope, err := poolVIPOwnershipDeliveryScopeIdentityV3(envelope)
	if err != nil {
		return poolVIPOwnershipDeliveryV3IssueInput{}, err
	}
	manifest, err := json.Marshal(envelope.Manifest)
	if err != nil {
		return poolVIPOwnershipDeliveryV3IssueInput{}, err
	}
	// v3's complete manifest is the source of dataplane truth. Keep the legacy
	// v2 owned_routes column at its canonical empty JSON shape rather than
	// projecting selected fields out of an evolving v3 manifest.
	return poolVIPOwnershipDeliveryV3IssueInput{envelope: envelope, ids: ids, scopeIdentity: scope, routes: []byte("[]"), manifest: manifest}, nil
}

func issuePoolVIPOwnershipDeliveryV3Tx(ctx context.Context, tx pgx.Tx, input poolVIPOwnershipDeliveryV3IssueInput) error {
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requirePoolVIPOwnershipScope(ctx, tx, input.ids); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pool_vip_ownership_delivery_states
		(org_id,site_id,cluster_id,pool_id,connector_node_id,scope_identity) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (org_id,site_id,cluster_id,pool_id,connector_node_id) DO NOTHING`, input.ids.orgID, input.ids.siteID, input.ids.clusterID, input.ids.poolID, input.ids.connectorNodeID, input.scopeIdentity); err != nil {
		return err
	}
	_, state, err := loadPoolVIPOwnershipAckState(ctx, tx, input.ids)
	if err != nil {
		return err
	}
	if state.ScopeIdentity != input.scopeIdentity {
		return fmt.Errorf("stored ownership handoff scope is invalid")
	}
	if input.envelope.PromotionGeneration < state.PromotionGeneration {
		return ErrPoolVIPOwnershipDeliveryStaleGeneration
	}
	ct, err := tx.Exec(ctx, `INSERT INTO pool_vip_ownership_deliveries
		(org_id,site_id,cluster_id,pool_id,connector_node_id,target_node_id,operation_id,wire_version,manifest_identity,role,promotion_generation,manifest_revision,lease_epoch,delivery_phase,delivery_id,delivery_nonce,owned_routes,expected_route_digest,expected_vip_map_digest,prior_lease_epoch,expires_at,ownership_manifest)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb,$18,$19,$20,$21,$22::jsonb)
		ON CONFLICT (org_id,delivery_id) DO NOTHING`, input.ids.orgID, input.ids.siteID, input.ids.clusterID, input.ids.poolID, input.ids.connectorNodeID, input.ids.targetNodeID, input.ids.operationID,
		input.envelope.Version, input.envelope.ManifestIdentity, input.envelope.Role, input.envelope.PromotionGeneration, input.envelope.ManifestRevision, input.envelope.LeaseEpoch,
		input.envelope.DeliveryPhase, input.ids.deliveryID, input.envelope.DeliveryNonce, input.routes, input.envelope.ExpectedRouteDigest, input.envelope.ExpectedVIPMapDigest,
		input.envelope.PriorLeaseEpoch, input.envelope.ExpiresAt, input.manifest)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		_, stored, err := scanPoolVIPOwnershipDeliveryV3(tx.QueryRow(ctx, poolVIPOwnershipDeliveryV3Select+` WHERE org_id=$1 AND delivery_id=$2 FOR UPDATE`, input.ids.orgID, input.ids.deliveryID))
		if err != nil || !reflect.DeepEqual(stored, input.envelope) {
			return fmt.Errorf("%w: delivery ID replay", ErrPoolVIPOwnershipDeliveryImmutableConflict)
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresPoolVIPOwnershipDeliveryStore) LoadIssuedPoolVIPOwnershipDeliveryV3(ctx context.Context, agent PoolVIPOwnershipAgentIdentity) (PoolVIPOwnershipDeliveryEnvelopeV3, bool, error) {
	if s == nil || s.pool == nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, false, fmt.Errorf("ownership delivery store is not configured")
	}
	if agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, false, nil
	}
	_, envelope, err := scanPoolVIPOwnershipDeliveryV3(s.pool.QueryRow(ctx, poolVIPOwnershipDeliveryV3Select+` WHERE wire_version=3 AND org_id=$1 AND target_node_id=$2 AND expires_at>clock_timestamp() AND NOT EXISTS (SELECT 1 FROM pool_vip_ownership_delivery_ack_receipts r WHERE r.delivery_row_id=pool_vip_ownership_deliveries.id) ORDER BY manifest_revision DESC,created_at DESC LIMIT 1`, agent.OrgID, agent.NodeID))
	if err == pgx.ErrNoRows {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, false, nil
	}
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, false, err
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, false, err
	}
	return envelope, true, nil
}

func (s *PostgresPoolVIPOwnershipDeliveryStore) UpdatePoolVIPOwnershipAckV3(ctx context.Context, agent PoolVIPOwnershipAgentIdentity, ack PoolVIPOwnershipDeliveryAckV3, receipt time.Time, validate func(PoolVIPOwnershipDeliveryEnvelopeV3, PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error)) (PoolVIPOwnershipAckValidation, error) {
	if s == nil || s.pool == nil || validate == nil || receipt.IsZero() {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("ownership handoff store is not configured")
	}
	deliveryID, err := uuid.Parse(ack.DeliveryID)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	rowID, envelope, err := scanPoolVIPOwnershipDeliveryV3(tx.QueryRow(ctx, poolVIPOwnershipDeliveryV3Select+` WHERE wire_version=3 AND org_id=$1 AND target_node_id=$2 AND delivery_id=$3 AND expires_at>clock_timestamp() FOR UPDATE`, agent.OrgID, agent.NodeID, deliveryID))
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("issued ownership v3 delivery absent or expired: %w", err)
	}
	ids, err := parsePoolVIPOwnershipDeliveryIDs(envelope.PoolVIPOwnershipDeliveryEnvelope)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	stateID, state, err := loadPoolVIPOwnershipAckState(ctx, tx, ids)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	var fingerprint string
	var original time.Time
	if err := tx.QueryRow(ctx, `SELECT fingerprint,receipt_time FROM pool_vip_ownership_delivery_ack_receipts WHERE delivery_row_id=$1`, rowID).Scan(&fingerprint, &original); err == nil {
		state.Seen = map[string]PoolVIPOwnershipAckReceipt{ack.DeliveryID: {Fingerprint: fingerprint, ReceiptTime: original}}
	} else if err != pgx.ErrNoRows {
		return PoolVIPOwnershipAckValidation{}, err
	}
	result, err := validate(envelope, state)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if result.NextState.ScopeIdentity != state.ScopeIdentity || result.NextState.PromotionGeneration > math.MaxInt64 || result.NextState.ManifestRevision > math.MaxInt64 || result.NextState.LeaseEpoch > math.MaxInt64 {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("invalid acknowledgement state")
	}
	if result.Duplicate {
		if err := tx.Commit(ctx); err != nil {
			return PoolVIPOwnershipAckValidation{}, err
		}
		return result, nil
	}
	rec, ok := result.NextState.Seen[ack.DeliveryID]
	if !ok || rec.Fingerprint == "" || rec.ReceiptTime.IsZero() {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("validator returned no receipt")
	}
	if _, err = tx.Exec(ctx, `UPDATE pool_vip_ownership_delivery_states SET promotion_generation=$2,manifest_revision=$3,lease_epoch=$4 WHERE id=$1`, stateID, int64(result.NextState.PromotionGeneration), int64(result.NextState.ManifestRevision), int64(result.NextState.LeaseEpoch)); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	applied, err := json.Marshal(ack.AppliedManifest)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO pool_vip_ownership_delivery_ack_receipts (org_id,delivery_row_id,state_id,fingerprint,receipt_time,applied_role,applied_manifest_identity,applied_promotion_generation,applied_manifest_revision,applied_lease_epoch,owned_route_digest,vip_map_digest,applied_manifest) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)`, ids.orgID, rowID, stateID, rec.Fingerprint, rec.ReceiptTime.UTC(), envelope.Role, envelope.ManifestIdentity, int64(envelope.PromotionGeneration), int64(envelope.ManifestRevision), int64(ack.AppliedLeaseEpoch), envelope.ExpectedRouteDigest, envelope.ExpectedVIPMapDigest, applied); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	return result, nil
}

const poolVIPOwnershipDeliveryV3Select = `SELECT id,wire_version,org_id::text,site_id::text,cluster_id::text,pool_id::text,connector_node_id::text,target_node_id::text,operation_id::text,manifest_identity,role,promotion_generation,manifest_revision,lease_epoch,delivery_phase,delivery_id::text,delivery_nonce,expected_route_digest,expected_vip_map_digest,prior_lease_epoch,expires_at,ownership_manifest FROM pool_vip_ownership_deliveries`

func scanPoolVIPOwnershipDeliveryV3(row pgx.Row) (uuid.UUID, PoolVIPOwnershipDeliveryEnvelopeV3, error) {
	var id uuid.UUID
	var e PoolVIPOwnershipDeliveryEnvelopeV3
	var promotion, revision, lease, prior int64
	var raw []byte
	err := row.Scan(&id, &e.Version, &e.OrgID, &e.SiteID, &e.ClusterID, &e.PoolID, &e.ConnectorNodeID, &e.TargetNodeID, &e.OperationID, &e.ManifestIdentity, &e.Role, &promotion, &revision, &lease, &e.DeliveryPhase, &e.DeliveryID, &e.DeliveryNonce, &e.ExpectedRouteDigest, &e.ExpectedVIPMapDigest, &prior, &e.ExpiresAt, &raw)
	if err != nil {
		return uuid.Nil, e, err
	}
	if promotion < 0 || revision < 0 || lease < 0 || prior < 0 {
		return uuid.Nil, e, fmt.Errorf("stored v3 counters invalid")
	}
	e.PromotionGeneration, e.ManifestRevision, e.LeaseEpoch, e.PriorLeaseEpoch = uint64(promotion), uint64(revision), uint64(lease), uint64(prior)
	if err = json.Unmarshal(raw, &e.Manifest); err != nil {
		return uuid.Nil, e, err
	}
	e.ExpiresAt = e.ExpiresAt.UTC()
	return id, e, nil
}
