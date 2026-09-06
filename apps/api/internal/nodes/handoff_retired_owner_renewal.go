package nodes

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// loadHandoffRetiredOwnerRenewalExemptionTx proves only a renewal exemption.
// The caller must hold the scheduler leadership session and the existing
// topology/member locks, and retain this transaction through lease issuance.
// The pool's FOR UPDATE lock also fences inserts through the delivery FK: an
// unacknowledged issued serving lease is as relevant as an acknowledged one.
// A zero clock margin preserves the strict pre-exemption behavior.
func loadHandoffRetiredOwnerRenewalExemptionTx(ctx context.Context, tx pgx.Tx, plan HandoffBootstrapPlan, now time.Time, clockSkew time.Duration) (uuid.UUID, bool, error) {
	if clockSkew <= 0 {
		return uuid.Nil, false, nil
	}
	if tx == nil || now.IsZero() || !validHandoffBootstrapScope(plan.Scope) || plan.ActiveNodeID == uuid.Nil || plan.Generation == 0 || plan.Generation > math.MaxInt64 {
		return uuid.Nil, false, ErrHandoffHATransitionRefused
	}
	var retired uuid.UUID
	err := tx.QueryRow(ctx, `SELECT o.old_node_id
		FROM k8s_connector_pools p
		JOIN k8s_connector_pool_ha_transitions t
		  ON t.pool_id=p.id AND t.org_id=p.org_id AND t.site_id=p.site_id AND t.cluster_id=p.cluster_id
		JOIN k8s_connector_pool_health_states h ON h.pool_id=p.id AND h.org_id=p.org_id
		JOIN k8s_connector_handoff_operations o
		  ON o.pool_id=p.id AND o.org_id=p.org_id AND o.site_id=p.site_id AND o.cluster_id=p.cluster_id
		JOIN audit_logs a ON a.id=o.cas_audit_id AND a.org_id=o.org_id
		WHERE p.org_id=$1 AND p.site_id=$2 AND p.cluster_id=$3 AND p.id=$4
		  AND p.active_node_id=$5 AND p.generation=$6
		  AND t.requested_mode='fenced_ha' AND t.actual_mode='fenced_ha'
		  AND t.active_node_id=p.active_node_id AND t.promotion_generation=p.generation
		  AND t.membership_epoch=h.membership_epoch
		  AND o.new_node_id=p.active_node_id AND o.target_generation=p.generation
		  AND o.old_node_id<>o.new_node_id AND o.phase='complete'
		  AND o.observed_membership_epoch=h.membership_epoch
		  AND o.prepared_ack_received_at IS NOT NULL AND o.prepared_ack_received_at<=$7
		  AND o.serving_ack_received_at IS NOT NULL AND o.serving_ack_received_at<=$7
		  AND ((o.withdrawal_ack_received_at IS NOT NULL AND o.withdrawal_expiry_received_at IS NULL)
		    OR (o.withdrawal_ack_received_at IS NULL AND o.withdrawal_expiry_received_at IS NOT NULL))
		  AND COALESCE(o.withdrawal_ack_received_at,o.withdrawal_expiry_received_at)<=$7
		  AND o.cas_audit_applied AND o.cas_receipt_at IS NOT NULL AND o.cas_receipt_at<=$7
		  AND a.action='k8s.connector_pool.handoff_applied' AND a.target_type='k8s_connector_pool'
		  AND a.target_id=p.id::text AND a.metadata->>'operation_id'=o.id::text
		  AND a.metadata->>'old_node_id'=o.old_node_id::text AND a.metadata->>'new_node_id'=o.new_node_id::text
		  AND a.metadata->>'expected_generation'=o.expected_generation::text
		  AND a.metadata->>'target_generation'=o.target_generation::text
		  AND NOT EXISTS (SELECT 1 FROM k8s_connector_handoff_operations pending
		    WHERE pending.org_id=p.org_id AND pending.site_id=p.site_id AND pending.cluster_id=p.cluster_id
		      AND pending.pool_id=p.id AND pending.phase NOT IN ('complete','failed'))
		FOR UPDATE OF p,t,h,o`, plan.Scope.OrgID, plan.Scope.SiteID, plan.Scope.ClusterID, plan.Scope.PoolID,
		plan.ActiveNodeID, int64(plan.Generation), now.UTC()).Scan(&retired)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	found := false
	for _, node := range plan.EligibleStandbyIDs {
		found = found || node == retired
	}
	if retired == uuid.Nil || retired == plan.ActiveNodeID || !found {
		return uuid.Nil, false, ErrHandoffHATransitionRefused
	}
	var lastExpiry *time.Time
	if err := tx.QueryRow(ctx, `SELECT max(expires_at) FROM pool_vip_ownership_deliveries
		WHERE org_id=$1 AND site_id=$2 AND cluster_id=$3 AND pool_id=$4
		  AND (connector_node_id=$5 OR target_node_id=$5) AND role='serving'`,
		plan.Scope.OrgID, plan.Scope.SiteID, plan.Scope.ClusterID, plan.Scope.PoolID, retired).Scan(&lastExpiry); err != nil {
		return uuid.Nil, false, err
	}
	if !retiredOwnerServingAuthorityExpired(lastExpiry, now, clockSkew) {
		return uuid.Nil, false, nil
	}
	return retired, true, nil
}

func retiredOwnerServingAuthorityExpired(lastExpiry *time.Time, now time.Time, clockSkew time.Duration) bool {
	return lastExpiry != nil && !lastExpiry.IsZero() && !now.IsZero() && clockSkew > 0 && !lastExpiry.Add(clockSkew).After(now)
}

// requireRetiredOwnerCandidateBaseTx is deliberately separate from renewal
// eligibility. A new operation may already exist, and expiry or membership
// churn must not turn a previously retired candidate's missing base into an
// admission success. Non-retired candidates retain their existing contract.
func requireRetiredOwnerCandidateBaseTx(ctx context.Context, tx pgx.Tx, plan k8s.HandoffPlan) error {
	var retired bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM k8s_connector_handoff_operations o
		JOIN k8s_connector_pools p
		  ON p.id=o.pool_id AND p.org_id=o.org_id AND p.site_id=o.site_id AND p.cluster_id=o.cluster_id
		JOIN k8s_connector_pool_ha_transitions t
		  ON t.pool_id=p.id AND t.org_id=p.org_id AND t.site_id=p.site_id AND t.cluster_id=p.cluster_id
		WHERE o.org_id=$1 AND o.site_id=$2 AND o.cluster_id=$3 AND o.pool_id=$4
		  AND o.old_node_id=$5 AND o.new_node_id=$6 AND o.target_generation=$7 AND o.phase='complete'
		  AND t.actual_mode<>'legacy'
	)`, plan.Scope.OrgID, plan.Scope.SiteID, plan.Scope.ClusterID, plan.Scope.PoolID,
		plan.CandidateID, plan.ExpectedActiveID, int64(plan.ExpectedGeneration)).Scan(&retired); err != nil {
		return err
	}
	if !retired {
		return nil
	}
	// Missing/achieved-legacy transitions retain the historical candidate
	// contract. All other modes may still carry a fence, including draining.
	// Do not compare the current pool owner/generation with the pre-CAS plan:
	// validation of that same operation must stay guarded after its CAS.
	// Preserve the ACK/issuer delivery -> node-state order. No compiler or
	// global-pool query runs while these transaction-owned locks are held.
	if err := lockLatestKubernetesOwnershipAuthorityDeliveryForNode(ctx, tx, plan.Scope.OrgID, plan.Scope.SiteID, plan.CandidateID); err != nil {
		return err
	}
	var acceptedRevision int64
	var acceptedDigest *string
	if err := tx.QueryRow(ctx, `SELECT accepted_authority_revision,accepted_payload_digest
		FROM k8s_base_authority_node_states WHERE org_id=$1 AND site_id=$2 AND node_id=$3 FOR UPDATE`,
		plan.Scope.OrgID, plan.Scope.SiteID, plan.CandidateID).Scan(&acceptedRevision, &acceptedDigest); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		return err
	}
	latest, found, err := loadLatestKubernetesOwnershipBaseAuthorityIssue(ctx, tx, plan.Scope.OrgID, plan.Scope.SiteID, plan.CandidateID)
	if err != nil {
		return err
	}
	if !found || !retiredOwnerCandidateBaseAccepted(latest, plan, acceptedRevision, acceptedDigest) {
		return ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	var exact bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM k8s_base_authority_ack_receipts
		WHERE delivery_id=$1 AND org_id=$2 AND site_id=$3 AND node_id=$4
		  AND authority_revision=$5 AND payload_digest=$6 AND applied_base_version=$7 AND applied_base_hash=$8)`,
		latest.DeliveryID, plan.Scope.OrgID, plan.Scope.SiteID, plan.CandidateID, int64(latest.Authority.AuthorityRevision),
		latest.PayloadDigest, int64(latest.Authority.BaseVersion), latest.Authority.BaseHash).Scan(&exact); err != nil {
		return err
	}
	if !exact {
		return ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	return nil
}

func retiredOwnerCandidateBaseAccepted(latest loadedKubernetesOwnershipIssueReplay, plan k8s.HandoffPlan, acceptedRevision int64, acceptedDigest *string) bool {
	authority := latest.Authority
	if !latest.Acknowledged || latest.AuthorityKind != "ordinary_base" || acceptedRevision <= 0 || acceptedDigest == nil ||
		authority.AuthorityRevision != uint64(acceptedRevision) || latest.PayloadDigest != *acceptedDigest ||
		authority.NodeID != plan.CandidateID.String() || authority.OrgID != plan.Scope.OrgID.String() || authority.SiteID != plan.Scope.SiteID.String() ||
		len(authority.UnfencedPools) != 0 {
		return false
	}
	_, digest, err := CanonicalKubernetesOwnershipBaseAuthority(authority)
	if err != nil || digest != latest.PayloadDigest {
		return false
	}
	pools, err := validateKubernetesOwnershipIssuePools(authority, latest.Pools)
	if err != nil {
		return false
	}
	want := KubernetesOwnershipPoolScope{OrgID: plan.Scope.OrgID.String(), SiteID: plan.Scope.SiteID.String(), ClusterID: plan.Scope.ClusterID.String(), PoolID: plan.Scope.PoolID.String()}
	pool, found := pools[want.PoolID]
	if !found || pool.Scope != want || pool.PromotionGeneration != plan.ExpectedGeneration {
		return false
	}
	matched := false
	for _, classification := range authority.Classifications {
		if classification.Disposition != KubernetesOwnershipPoolDispositionMaintainFence {
			return false
		}
		if classification.Scope == want {
			matched = true
		}
	}
	return matched
}
