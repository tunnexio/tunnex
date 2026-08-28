package nodes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// ReadPoolVIPOwnershipHandoffAppliedAttestationV3 projects one coherent v3
// delivery/receipt pair. It validates both persisted manifests before exposing
// applied evidence; v1/v2 rows cannot match the exact wire-version predicate.
func (s *PostgresPoolVIPOwnershipDeliveryStore) ReadPoolVIPOwnershipHandoffAppliedAttestationV3(ctx context.Context, artifact PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipHandoffAppliedAttestationRead, bool, error) {
	if s == nil || s.pool == nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, fmt.Errorf("ownership delivery store is not configured")
	}
	return readPoolVIPOwnershipHandoffAppliedAttestationV3(ctx, s.pool, artifact)
}

// ReadPoolVIPOwnershipHandoffAppliedAttestationV3LeaderBound is the bootstrap
// reader: it verifies and reads through the exact caller-held advisory-lock
// session rather than reacquiring an arbitrary pool connection.
func (s *PostgresPoolVIPOwnershipDeliveryStore) ReadPoolVIPOwnershipHandoffAppliedAttestationV3LeaderBound(ctx context.Context, session PoolVIPOwnershipHandoffLeaderSession, artifact PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipHandoffAppliedAttestationRead, bool, error) {
	if s == nil || s.pool == nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, fmt.Errorf("ownership delivery store is not configured")
	}
	if err := validPoolVIPOwnershipHandoffLeaderSession(ctx, session); err != nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, err
	}
	return readPoolVIPOwnershipHandoffAppliedAttestationV3(ctx, session.Conn, artifact)
}

type poolVIPOwnershipHandoffV3Querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readPoolVIPOwnershipHandoffAppliedAttestationV3(ctx context.Context, q poolVIPOwnershipHandoffV3Querier, artifact PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipHandoffAppliedAttestationRead, bool, error) {
	if q == nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, fmt.Errorf("ownership delivery reader is not configured")
	}
	if err := validPoolVIPOwnershipHandoffArtifact(artifact); err != nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, err
	}
	var envelope PoolVIPOwnershipDeliveryEnvelopeV3
	var ack PoolVIPOwnershipDeliveryAckV3
	var promotion, revision, lease, prior int64
	var appliedPromotion, appliedRevision, appliedLease int64
	var manifestJSON, appliedJSON []byte
	var receipt, expires time.Time
	var storedAppliedRole, storedAppliedIdentity string
	var storedRouteDigest, storedVIPDigest string
	err := q.QueryRow(ctx, `
		SELECT d.wire_version,d.org_id::text,d.site_id::text,d.cluster_id::text,d.pool_id::text,
		       d.connector_node_id::text,d.target_node_id::text,d.operation_id::text,d.manifest_identity,d.role,
		       d.promotion_generation,d.manifest_revision,d.lease_epoch,d.delivery_phase,d.delivery_id::text,d.delivery_nonce,
		       d.expected_route_digest,d.expected_vip_map_digest,d.prior_lease_epoch,d.expires_at,d.ownership_manifest,
		       r.receipt_time,r.applied_role,r.applied_manifest_identity,r.applied_promotion_generation,
		       r.applied_manifest_revision,r.applied_lease_epoch,r.owned_route_digest,r.vip_map_digest,r.applied_manifest
		FROM pool_vip_ownership_deliveries d
		JOIN pool_vip_ownership_delivery_ack_receipts r ON r.delivery_row_id=d.id AND r.org_id=d.org_id
		WHERE d.wire_version=3 AND d.expires_at>clock_timestamp()
		  AND d.org_id=$1 AND d.site_id=$2 AND d.cluster_id=$3 AND d.pool_id=$4
		  AND d.connector_node_id=$5 AND d.target_node_id=$6 AND d.operation_id=$7
		  AND d.manifest_identity=$8 AND d.role=$9 AND d.delivery_phase=$10
		  AND d.promotion_generation=$11 AND d.manifest_revision=$12 AND d.lease_epoch=$13 AND d.delivery_id=$14
		  AND d.expected_route_digest=$15 AND d.expected_vip_map_digest=$16 AND d.prior_lease_epoch=$17`,
		artifact.OrgID, artifact.SiteID, artifact.ClusterID, artifact.PoolID, artifact.ConnectorNodeID, artifact.TargetNodeID,
		artifact.OperationID, artifact.ManifestIdentity, artifact.Role, artifact.DeliveryPhase, int64(artifact.PromotionGeneration),
		int64(artifact.ManifestRevision), int64(artifact.LeaseEpoch), artifact.DeliveryID, artifact.ExpectedRouteDigest,
		artifact.ExpectedVIPMapDigest, int64(artifact.PriorLeaseEpoch)).Scan(
		&envelope.Version, &envelope.OrgID, &envelope.SiteID, &envelope.ClusterID, &envelope.PoolID,
		&envelope.ConnectorNodeID, &envelope.TargetNodeID, &envelope.OperationID, &envelope.ManifestIdentity, &envelope.Role,
		&promotion, &revision, &lease, &envelope.DeliveryPhase, &envelope.DeliveryID, &envelope.DeliveryNonce,
		&envelope.ExpectedRouteDigest, &envelope.ExpectedVIPMapDigest, &prior, &expires, &manifestJSON,
		&receipt, &storedAppliedRole, &storedAppliedIdentity, &appliedPromotion, &appliedRevision, &appliedLease,
		&storedRouteDigest, &storedVIPDigest, &appliedJSON)
	if err == pgx.ErrNoRows {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, nil
	}
	if err != nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, err
	}
	if promotion < 0 || revision < 0 || lease < 0 || prior < 0 || appliedPromotion < 0 || appliedRevision < 0 || appliedLease < 0 {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, fmt.Errorf("stored ownership handoff counters are invalid")
	}
	envelope.PromotionGeneration, envelope.ManifestRevision, envelope.LeaseEpoch, envelope.PriorLeaseEpoch = uint64(promotion), uint64(revision), uint64(lease), uint64(prior)
	envelope.ExpiresAt = expires.UTC()
	if err := json.Unmarshal(manifestJSON, &envelope.Manifest); err != nil || json.Unmarshal(appliedJSON, &ack.AppliedManifest) != nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, fmt.Errorf("stored ownership handoff manifest is invalid")
	}
	ack.PoolVIPOwnershipDeliveryAck = PoolVIPOwnershipDeliveryAck{Version: envelope.Version, OrgID: envelope.OrgID, SiteID: envelope.SiteID, ClusterID: envelope.ClusterID,
		PoolID: envelope.PoolID, ConnectorNodeID: envelope.ConnectorNodeID, TargetNodeID: envelope.TargetNodeID, OperationID: envelope.OperationID,
		ManifestIdentity: envelope.ManifestIdentity, Role: envelope.Role, PromotionGeneration: envelope.PromotionGeneration, ManifestRevision: envelope.ManifestRevision,
		LeaseEpoch: envelope.LeaseEpoch, DeliveryPhase: envelope.DeliveryPhase, DeliveryID: envelope.DeliveryID, DeliveryNonce: envelope.DeliveryNonce}
	ack.AppliedLeaseEpoch = uint64(appliedLease)
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, fmt.Errorf("stored ownership handoff delivery is invalid: %w", err)
	}
	if uint64(appliedPromotion) != envelope.PromotionGeneration || uint64(appliedRevision) != envelope.ManifestRevision ||
		storedAppliedRole != envelope.Role || storedAppliedIdentity != envelope.ManifestIdentity ||
		storedRouteDigest != envelope.ExpectedRouteDigest || storedVIPDigest != envelope.ExpectedVIPMapDigest {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, fmt.Errorf("stored ownership handoff receipt does not match delivery")
	}
	if err := validPoolVIPOwnershipAckV3Echo(envelope, ack); err != nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, err
	}
	appliedIdentity, err := policyspec.PoolVIPOwnershipManifestIdentity(ack.AppliedManifest.policyManifest())
	if err != nil || appliedIdentity != envelope.ManifestIdentity || !ack.AppliedManifest.LeaseExpiresAt.Equal(envelope.ExpiresAt) || !receipt.Before(expires) {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, fmt.Errorf("stored ownership handoff applied manifest does not match")
	}
	wantLease := envelope.LeaseEpoch
	if envelope.Role == policyspec.PoolVIPOwnershipWithdrawal {
		wantLease = envelope.PriorLeaseEpoch
	}
	if ack.AppliedLeaseEpoch != wantLease {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, fmt.Errorf("stored ownership handoff applied lease does not match")
	}
	return PoolVIPOwnershipHandoffAppliedAttestationRead{WireVersion: PoolVIPOwnershipDeliveryHandoffVersion, AppliedRole: storedAppliedRole, AppliedManifestIdentity: storedAppliedIdentity,
		AppliedPromotionGeneration: uint64(appliedPromotion), AppliedManifestRevision: uint64(appliedRevision), AppliedLeaseEpoch: uint64(appliedLease),
		ReceiptTime: receipt.UTC(), ExpiresAt: expires.UTC(), OwnedRouteDigest: storedRouteDigest, VIPMapDigest: storedVIPDigest}, true, nil
}
