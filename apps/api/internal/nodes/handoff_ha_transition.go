package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

var ErrHandoffHATransitionRefused = errors.New("handoff HA transition refused")

const (
	handoffHAAuthorityExpiredUnacknowledgedRetryReason = "expired_unacknowledged_base_authority_delivery"
	handoffHAAuthorityStaleReceiptRetryReason          = "stale_base_authority_receipt"
	handoffHAAuthorityCombinedRetryReason              = "expired_unacknowledged_and_stale_base_authority_receipts"
	handoffHAAuthorityRetryReasonCode                  = "base_authority_retry_pending"
)

// HandoffBaseStateSource returns the exact ordinary desired state that the
// authenticated agent route will serve, including its node-push version.
// Production supplies the existing nodes.Service + nodepush.Hub seam.
type HandoffBaseStateSource interface {
	HandoffBaseState(context.Context, uuid.UUID, uuid.UUID) (DesiredState, error)
}

type HandoffBaseStateSourceFunc func(context.Context, uuid.UUID, uuid.UUID) (DesiredState, error)

func (f HandoffBaseStateSourceFunc) HandoffBaseState(ctx context.Context, orgID, nodeID uuid.UUID) (DesiredState, error) {
	return f(ctx, orgID, nodeID)
}

type HandoffHATransitionConfig struct {
	MaxAckAge    time.Duration
	AuthorityTTL time.Duration
}

func (c HandoffHATransitionConfig) valid() bool {
	return c.MaxAckAge > 0 && c.AuthorityTTL >= time.Minute
}

// PostgresHandoffOwnershipModeTransition owns P3's closed activation boundary.
// It does not run a loop or select a pool. The caller names one immutable P2
// bootstrap plan while holding the scheduler advisory-lock session.
type PostgresHandoffOwnershipModeTransition struct {
	pool      *pgxpool.Pool
	base      HandoffBaseStateSource
	authority KubernetesOwnershipBaseAuthorityIssuer
	config    HandoffHATransitionConfig
}

func NewPostgresHandoffOwnershipModeTransition(pool *pgxpool.Pool, base HandoffBaseStateSource, authority KubernetesOwnershipBaseAuthorityIssuer, config HandoffHATransitionConfig) (*PostgresHandoffOwnershipModeTransition, error) {
	if pool == nil || !handoffActivationDependencyPresent(base) || !handoffActivationDependencyPresent(authority) || !config.valid() {
		return nil, ErrHandoffHATransitionRefused
	}
	return &PostgresHandoffOwnershipModeTransition{pool: pool, base: base, authority: authority, config: config}, nil
}

func (t *PostgresHandoffOwnershipModeTransition) ArmHandoffOwnershipBaseWithLeadership(ctx context.Context, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, plan HandoffBootstrapPlan) (HandoffBaseAuthorityArmSnapshot, bool, error) {
	if t == nil || !t.config.valid() || now.IsZero() || !validHandoffBootstrapPlan(plan, now.UTC()) {
		return HandoffBaseAuthorityArmSnapshot{}, false, ErrHandoffHATransitionRefused
	}
	if err := requireHandoffHALeaderSession(ctx, epoch, conn); err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	revision, membershipEpoch, members, err := t.advanceRetryableHandoffAuthorityWithLeadership(ctx, now.UTC(), epoch, conn, plan)
	if err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	classification, err := bootstrapBaseClassification(plan)
	if err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	expires := now.UTC().Truncate(t.config.AuthorityTTL).Add(2 * t.config.AuthorityTTL)
	result := HandoffBaseAuthorityArmSnapshot{TransitionRevision: revision, MembershipEpoch: membershipEpoch, Members: make([]HandoffBaseAuthorityArmMember, 0, len(members))}
	poolGeneration := KubernetesOwnershipBaseAuthorityPoolGeneration{Scope: classification.Scope, PromotionGeneration: plan.Generation}
	issueTx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	defer issueTx.Rollback(ctx) //nolint:errcheck
	if err := requireHandoffHALeaderSessionTx(ctx, issueTx, epoch); err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	lockedRevision, lockedMembershipEpoch, lockedMembers, err := loadHandoffHATransitionSnapshot(ctx, issueTx, plan, true)
	if err != nil || lockedRevision != revision || lockedMembershipEpoch != membershipEpoch || !sameUUIDSet(lockedMembers, members) {
		if err == nil {
			err = ErrHandoffHATransitionRefused
		}
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	for _, nodeID := range members {
		base, err := t.base.HandoffBaseState(ctx, plan.Scope.OrgID, nodeID)
		if err != nil || base.NodeID != nodeID.String() || base.Version == 0 {
			if err == nil {
				err = ErrHandoffHATransitionRefused
			}
			return HandoffBaseAuthorityArmSnapshot{}, false, err
		}
		hash, err := KubernetesOwnershipBaseStateHash(base)
		if err != nil {
			return HandoffBaseAuthorityArmSnapshot{}, false, err
		}
		issueExpiry, err := loadHandoffHAAuthorityIssueExpiry(ctx, issueTx, now.UTC(), expires, plan, nodeID, revision, base.Version, hash)
		if err != nil {
			return HandoffBaseAuthorityArmSnapshot{}, false, err
		}
		issued, err := t.authority.IssueKubernetesOwnershipBaseAuthorityWithLeadershipTx(ctx, epoch, issueTx, KubernetesOwnershipBaseAuthorityIssue{
			Authority: KubernetesOwnershipBaseAuthority{WireVersion: KubernetesOwnershipBaseAuthorityWireVersion, NodeID: nodeID.String(), OrgID: plan.Scope.OrgID.String(), SiteID: plan.Scope.SiteID.String(), BaseVersion: base.Version, BaseHash: hash, Classifications: []KubernetesOwnershipPoolClassification{classification}},
			Pools:     []KubernetesOwnershipBaseAuthorityPoolGeneration{poolGeneration}, TransitionRevision: revision, ExpiresAt: issueExpiry,
		})
		if err != nil {
			return HandoffBaseAuthorityArmSnapshot{}, false, err
		}
		result.Members = append(result.Members, HandoffBaseAuthorityArmMember{NodeID: nodeID, AuthorityRevision: issued.Authority.AuthorityRevision, BaseVersion: issued.Authority.BaseVersion, BaseHash: issued.Authority.BaseHash, PayloadDigest: issued.PayloadDigest})
	}
	finalIssueRevision, finalIssueMembershipEpoch, finalIssueMembers, err := loadHandoffHATransitionSnapshot(ctx, issueTx, plan, true)
	if err != nil || finalIssueRevision != revision || finalIssueMembershipEpoch != membershipEpoch || !sameUUIDSet(finalIssueMembers, members) {
		if err == nil {
			err = ErrHandoffHATransitionRefused
		}
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	if err := requireHandoffHALeaderSessionTx(ctx, issueTx, epoch); err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	if err := issueTx.Commit(ctx); err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	readyTx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	defer readyTx.Rollback(ctx) //nolint:errcheck
	if err := requireHandoffHALeaderSessionTx(ctx, readyTx, epoch); err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	readyRevision, readyMembershipEpoch, readyMembers, err := loadHandoffHATransitionSnapshot(ctx, readyTx, plan, true)
	if err != nil || readyRevision != revision || readyMembershipEpoch != membershipEpoch || !sameUUIDSet(readyMembers, members) {
		if err == nil {
			err = ErrHandoffHATransitionRefused
		}
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	for _, member := range result.Members {
		var receipt time.Time
		err := readyTx.QueryRow(ctx, `SELECT r.receipt_time
			FROM k8s_base_authority_deliveries d
			JOIN k8s_base_authority_delivery_pools p ON p.delivery_id=d.id AND p.org_id=d.org_id AND p.node_id=d.node_id
			JOIN k8s_base_authority_ack_receipts r ON r.delivery_id=d.id AND r.org_id=d.org_id AND r.node_id=d.node_id
			WHERE d.org_id=$1 AND d.site_id=$2 AND d.node_id=$3 AND d.authority_revision=$4
			  AND d.authority_kind='transition' AND d.transition_revision=$5 AND d.base_version=$6 AND d.base_hash=$7 AND d.payload_digest=$8
			  AND p.cluster_id=$9 AND p.pool_id=$10 AND p.promotion_generation=$11
			  AND p.kind='classification' AND p.disposition='arm_fence'`, plan.Scope.OrgID, plan.Scope.SiteID, member.NodeID,
			int64(member.AuthorityRevision), int64(revision), int64(member.BaseVersion), member.BaseHash, member.PayloadDigest,
			plan.Scope.ClusterID, plan.Scope.PoolID, int64(plan.Generation)).Scan(&receipt)
		if errors.Is(err, pgx.ErrNoRows) {
			return result, false, nil
		}
		if err != nil {
			return HandoffBaseAuthorityArmSnapshot{}, false, err
		}
		if receipt.After(now.UTC()) || now.UTC().Sub(receipt) > t.config.MaxAckAge {
			return result, false, nil
		}
	}
	if err := requireHandoffHALeaderSessionTx(ctx, readyTx, epoch); err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	if err := readyTx.Commit(ctx); err != nil {
		return HandoffBaseAuthorityArmSnapshot{}, false, err
	}
	return result, true, nil
}

// advanceRetryableHandoffAuthorityWithLeadership is the only
// bootstrap retry path for an expired unacknowledged delivery or a receipt
// older than MaxAckAge. It never extends, deletes, or supersedes evidence at
// its existing transition revision. Instead it locks the complete transition
// snapshot on the caller's advisory-lock connection, advances the transition
// revision once, and records the exact old/new revisions and reason. All
// members must therefore ACK newly issued authority before P2 can run.
func (t *PostgresHandoffOwnershipModeTransition) advanceRetryableHandoffAuthorityWithLeadership(ctx context.Context, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, plan HandoffBootstrapPlan) (uint64, uint64, []uuid.UUID, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, 0, nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return 0, 0, nil, err
	}
	revision, membershipEpoch, members, err := loadHandoffHATransitionSnapshot(ctx, tx, plan, true)
	if err != nil {
		return 0, 0, nil, err
	}
	var expiredUnacknowledged, staleReceipt bool
	err = tx.QueryRow(ctx, `SELECT
		COALESCE(bool_or(r.delivery_id IS NULL AND d.expires_at <= $8),false),
		COALESCE(bool_or(r.delivery_id IS NOT NULL AND (r.receipt_time > $8 OR r.receipt_time < $9)),false)
		FROM k8s_base_authority_deliveries d
		JOIN k8s_base_authority_delivery_pools p
		  ON p.delivery_id=d.id AND p.org_id=d.org_id AND p.site_id=d.site_id AND p.node_id=d.node_id
		LEFT JOIN k8s_base_authority_ack_receipts r
		  ON r.delivery_id=d.id AND r.org_id=d.org_id AND r.site_id=d.site_id AND r.node_id=d.node_id
		WHERE d.org_id=$1 AND d.site_id=$2 AND d.authority_kind='transition' AND d.transition_revision=$3
		  AND p.cluster_id=$4 AND p.pool_id=$5 AND p.promotion_generation=$6
		  AND p.kind='classification' AND p.disposition='arm_fence'
		  AND d.node_id=ANY($7)`, plan.Scope.OrgID, plan.Scope.SiteID, int64(revision), plan.Scope.ClusterID, plan.Scope.PoolID,
		int64(plan.Generation), members, now, now.Add(-t.config.MaxAckAge)).Scan(&expiredUnacknowledged, &staleReceipt)
	if err != nil {
		return 0, 0, nil, err
	}
	retryReason, retry := classifyHandoffHAAuthorityRetry(expiredUnacknowledged, staleReceipt)
	if !retry {
		return revision, membershipEpoch, members, nil
	}
	if revision == uint64(^uint64(0)>>1) {
		return 0, 0, nil, ErrHandoffHATransitionRefused
	}
	newRevision := revision + 1
	ct, err := tx.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET
		transition_revision=$3,reason_code=$4,achieved_authority_revision=NULL,achieved_at=NULL,
		actor_user_id=NULL,actor_system='k8s-ha-activation',cause='retry stale or expired base authority evidence'
		WHERE pool_id=$1 AND org_id=$2 AND transition_revision=$5
		  AND requested_mode='fenced_ha' AND actual_mode='bootstrap_pending'`, plan.Scope.PoolID, plan.Scope.OrgID,
		int64(newRevision), handoffHAAuthorityRetryReasonCode, int64(revision))
	if err != nil || ct.RowsAffected() != 1 {
		if err == nil {
			err = ErrHandoffHATransitionRefused
		}
		return 0, 0, nil, err
	}
	metadata, err := json.Marshal(map[string]any{
		"reason":                  retryReason,
		"old_transition_revision": revision,
		"new_transition_revision": newRevision,
		"promotion_generation":    plan.Generation,
		"membership_epoch":        membershipEpoch,
	})
	if err != nil {
		return 0, 0, nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata)
		VALUES($1,'k8s-ha-activation','k8s.connector_pool_ha_base_authority_retried','k8s_connector_pool',$2,$3)`,
		plan.Scope.OrgID, plan.Scope.PoolID.String(), metadata); err != nil {
		return 0, 0, nil, err
	}
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return 0, 0, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, nil, err
	}
	return newRevision, membershipEpoch, members, nil
}

func classifyHandoffHAAuthorityRetry(expiredUnacknowledged, staleReceipt bool) (string, bool) {
	switch {
	case expiredUnacknowledged && staleReceipt:
		return handoffHAAuthorityCombinedRetryReason, true
	case expiredUnacknowledged:
		return handoffHAAuthorityExpiredUnacknowledgedRetryReason, true
	case staleReceipt:
		return handoffHAAuthorityStaleReceiptRetryReason, true
	default:
		return "", false
	}
}

// loadHandoffHAAuthorityIssueExpiry makes same-revision retries immutable: an
// existing live delivery is replayed with its original expiry. An expired row
// at this revision is refused because only the revision-advancing path above
// may recover it.
func loadHandoffHAAuthorityIssueExpiry(ctx context.Context, q handoffHAQuerier, now, proposed time.Time, plan HandoffBootstrapPlan, nodeID uuid.UUID, revision, baseVersion uint64, baseHash string) (time.Time, error) {
	rows, err := q.Query(ctx, `SELECT d.expires_at,d.base_version,d.base_hash FROM k8s_base_authority_deliveries d
		JOIN k8s_base_authority_delivery_pools p
		 ON p.delivery_id=d.id AND p.org_id=d.org_id AND p.site_id=d.site_id AND p.node_id=d.node_id
		WHERE d.org_id=$1 AND d.site_id=$2 AND d.node_id=$3 AND d.authority_kind='transition' AND d.transition_revision=$4
		 AND p.cluster_id=$5 AND p.pool_id=$6 AND p.promotion_generation=$7
		 AND p.kind='classification' AND p.disposition='arm_fence'
		ORDER BY d.authority_revision`, plan.Scope.OrgID, plan.Scope.SiteID, nodeID, int64(revision),
		plan.Scope.ClusterID, plan.Scope.PoolID, int64(plan.Generation))
	if err != nil {
		return time.Time{}, err
	}
	defer rows.Close()
	var existing []time.Time
	for rows.Next() {
		var expires time.Time
		var storedBaseVersion int64
		var storedBaseHash string
		if err := rows.Scan(&expires, &storedBaseVersion, &storedBaseHash); err != nil {
			return time.Time{}, err
		}
		if storedBaseVersion != int64(baseVersion) || storedBaseHash != baseHash {
			return time.Time{}, ErrHandoffHATransitionRefused
		}
		existing = append(existing, expires.UTC())
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, err
	}
	return selectHandoffHAAuthorityIssueExpiry(now, proposed, existing)
}

func selectHandoffHAAuthorityIssueExpiry(now, proposed time.Time, existing []time.Time) (time.Time, error) {
	if now.IsZero() || len(existing) > 1 {
		return time.Time{}, ErrHandoffHATransitionRefused
	}
	if len(existing) == 1 {
		original := existing[0].UTC()
		if !original.After(now) {
			return time.Time{}, ErrHandoffHATransitionRefused
		}
		return original, nil
	}
	if !proposed.After(now) {
		return time.Time{}, ErrHandoffHATransitionRefused
	}
	return proposed, nil
}

func (t *PostgresHandoffOwnershipModeTransition) ConfirmHandoffOwnershipModeTransitionWithLeadership(ctx context.Context, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, plan HandoffBootstrapPlan, arm HandoffBaseAuthorityArmSnapshot) (HandoffFencedBasePrerequisite, error) {
	if t == nil || now.IsZero() || arm.TransitionRevision == 0 || len(arm.Members) != 1+len(plan.EligibleStandbyIDs) {
		return "", ErrHandoffHATransitionRefused
	}
	if err := requireHandoffHALeaderSession(ctx, epoch, conn); err != nil {
		return "", err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return "", err
	}
	revision, membershipEpoch, members, err := loadHandoffHATransitionSnapshot(ctx, tx, plan, true)
	if err != nil || revision != arm.TransitionRevision || membershipEpoch != arm.MembershipEpoch || !sameUUIDSet(members, armNodeIDs(arm)) {
		if err == nil {
			err = ErrHandoffHATransitionRefused
		}
		return "", err
	}
	var achievedAuthority uint64
	for _, member := range arm.Members {
		var receipt time.Time
		err := tx.QueryRow(ctx, `SELECT r.receipt_time FROM k8s_base_authority_deliveries d
			JOIN k8s_base_authority_delivery_pools p ON p.delivery_id=d.id AND p.org_id=d.org_id AND p.node_id=d.node_id
			JOIN k8s_base_authority_ack_receipts r ON r.delivery_id=d.id AND r.org_id=d.org_id AND r.node_id=d.node_id
			WHERE d.org_id=$1 AND d.site_id=$2 AND d.node_id=$3 AND d.authority_revision=$4
			 AND d.authority_kind='transition' AND d.transition_revision=$5 AND d.base_version=$6 AND d.base_hash=$7 AND d.payload_digest=$8
			 AND p.cluster_id=$9 AND p.pool_id=$10 AND p.promotion_generation=$11
			 AND p.kind='classification' AND p.disposition='arm_fence' FOR SHARE OF d,p,r`, plan.Scope.OrgID, plan.Scope.SiteID,
			member.NodeID, int64(member.AuthorityRevision), int64(revision), int64(member.BaseVersion), member.BaseHash, member.PayloadDigest,
			plan.Scope.ClusterID, plan.Scope.PoolID, int64(plan.Generation)).Scan(&receipt)
		if err != nil || receipt.After(now.UTC()) || now.UTC().Sub(receipt) > t.config.MaxAckAge {
			return "", ErrHandoffHATransitionRefused
		}
		if member.AuthorityRevision > achievedAuthority {
			achievedAuthority = member.AuthorityRevision
		}
	}
	for _, delivery := range append([]k8s.P2HandoffDelivery{plan.CurrentOwnerServing}, plan.StandbyPrepared...) {
		artifact, err := poolVIPOwnershipHandoffArtifactFromP2Identity(delivery.Identity)
		if err != nil {
			return "", ErrHandoffHATransitionRefused
		}
		read, found, err := readPoolVIPOwnershipHandoffAppliedAttestationV3(ctx, tx, artifact)
		if err != nil || !found {
			return "", ErrHandoffHATransitionRefused
		}
		attestation := k8s.P2HandoffAppliedAttestation{Version: read.WireVersion, Identity: delivery.Identity, CPReceiptAt: read.ReceiptTime, DeliveryExpiresAt: read.ExpiresAt,
			AppliedRole: k8s.P2HandoffRole(read.AppliedRole), AppliedManifestIdentity: read.AppliedManifestIdentity, AppliedPromotionGeneration: read.AppliedPromotionGeneration,
			AppliedManifestRevision: read.AppliedManifestRevision, AppliedLeaseEpoch: read.AppliedLeaseEpoch, AppliedRouteDigest: read.OwnedRouteDigest, AppliedVIPMapDigest: read.VIPMapDigest}
		if !exactBootstrapAttestation(now.UTC(), t.config.MaxAckAge, delivery, attestation) {
			return "", ErrHandoffHATransitionRefused
		}
	}
	if err := confirmHandoffBootstrapServiceUIDs(ctx, tx, plan); err != nil {
		return "", err
	}
	ct, err := tx.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET actual_mode='fenced_ha',reason_code='fenced_base_ready',
		achieved_authority_revision=$3,achieved_at=$4,actor_user_id=NULL,actor_system='k8s-ha-activation',cause='exact fenced base bootstrap achieved'
		WHERE pool_id=$1 AND transition_revision=$2 AND requested_mode='fenced_ha' AND actual_mode='bootstrap_pending'`, plan.Scope.PoolID, int64(revision), int64(achievedAuthority), now.UTC())
	if err != nil || ct.RowsAffected() != 1 {
		return "", ErrHandoffHATransitionRefused
	}
	metadata, _ := json.Marshal(map[string]any{
		"old_requested_mode": "fenced_ha", "new_requested_mode": "fenced_ha",
		"old_actual_mode": "bootstrap_pending", "new_actual_mode": "fenced_ha",
		"promotion_generation": plan.Generation, "membership_epoch": membershipEpoch,
		"old_transition_revision": revision, "new_transition_revision": revision,
		"achieved_authority_revision": achievedAuthority,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata)
		VALUES($1,'k8s-ha-activation','k8s.connector_pool_ha_activated','k8s_connector_pool',$2,$3)`, plan.Scope.OrgID, plan.Scope.PoolID.String(), metadata); err != nil {
		return "", err
	}
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return HandoffFencedBaseReady, nil
}

// ReconcileHandoffOwnershipDrainWithLeadership implements omission-proof D6.
// It first proves no active v3 lease/nonterminal handoff, then receives an
// exact maintain-fence base receipt from every armed member, followed by a
// newer explicit unfence receipt. Only the final transaction records legacy.
func (t *PostgresHandoffOwnershipModeTransition) ReconcileHandoffOwnershipDrainWithLeadership(ctx context.Context, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, scope k8s.HandoffPoolScope) (bool, error) {
	if t == nil || now.IsZero() || !validHandoffBootstrapScope(scope) {
		return false, ErrHandoffHATransitionRefused
	}
	if err := requireHandoffHALeaderSession(ctx, epoch, conn); err != nil {
		return false, err
	}
	var revision, generation int64
	var membershipEpoch *int64
	var active uuid.UUID
	err := conn.QueryRow(ctx, `SELECT t.transition_revision,p.generation,p.active_node_id,t.membership_epoch
		FROM k8s_connector_pool_ha_transitions t JOIN k8s_connector_pools p
		 ON p.id=t.pool_id AND p.org_id=t.org_id AND p.site_id=t.site_id AND p.cluster_id=t.cluster_id
		WHERE t.org_id=$1 AND t.site_id=$2 AND t.cluster_id=$3 AND t.pool_id=$4
		 AND t.requested_mode='legacy' AND t.actual_mode='drain_pending'`, scope.OrgID, scope.SiteID, scope.ClusterID, scope.PoolID).Scan(&revision, &generation, &active, &membershipEpoch)
	if err != nil || revision <= 0 || generation <= 0 || active == uuid.Nil || membershipEpoch == nil || *membershipEpoch < 0 {
		return false, ErrHandoffHATransitionRefused
	}
	var nonterminal, liveServing bool
	if err := conn.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM k8s_connector_handoff_operations WHERE org_id=$1 AND pool_id=$2 AND phase NOT IN ('complete','failed')),
		EXISTS(SELECT 1 FROM pool_vip_ownership_deliveries d
		 JOIN pool_vip_ownership_delivery_ack_receipts r ON r.delivery_row_id=d.id AND r.org_id=d.org_id
		 WHERE d.wire_version=3 AND d.org_id=$1 AND d.site_id=$3 AND d.cluster_id=$4 AND d.pool_id=$2
		   AND r.applied_role='serving' AND d.expires_at>$5)`, scope.OrgID, scope.PoolID, scope.SiteID, scope.ClusterID, now.UTC()).Scan(&nonterminal, &liveServing); err != nil {
		return false, err
	}
	if nonterminal || liveServing {
		return false, nil
	}
	members, err := loadHandoffHADrainMembers(ctx, conn, scope, false)
	if err != nil || len(members) < 2 {
		return false, ErrHandoffHATransitionRefused
	}
	// A drain keeps the same fail-closed authority contract as bootstrap: an
	// expired or stale receipt must advance its durable transition revision,
	// never mutate the prior authority evidence in place.
	if next, nextEpoch, nextMembers, err := t.advanceRetryableHandoffDrainAuthorityWithLeadership(ctx, now.UTC(), epoch, conn, scope, uint64(revision), uint64(generation), members); err != nil {
		return false, err
	} else if next != uint64(revision) {
		nextEpochValue := int64(nextEpoch)
		revision, membershipEpoch, members = int64(next), &nextEpochValue, nextMembers
	}
	classification, err := loadHandoffHADrainClassification(ctx, conn, scope, uint64(generation))
	if err != nil {
		return false, err
	}
	classification.Disposition = KubernetesOwnershipPoolDispositionMaintainFence
	expires := now.UTC().Truncate(t.config.AuthorityTTL).Add(2 * t.config.AuthorityTTL)
	maintained := make([]HandoffBaseAuthorityArmMember, 0, len(members))
	for _, nodeID := range members {
		base, err := t.base.HandoffBaseState(ctx, scope.OrgID, nodeID)
		if err != nil || base.NodeID != nodeID.String() || base.Version == 0 {
			return false, ErrHandoffHATransitionRefused
		}
		hash, err := KubernetesOwnershipBaseStateHash(base)
		if err != nil {
			return false, err
		}
		issued, err := t.authority.IssueKubernetesOwnershipBaseAuthorityWithLeadership(ctx, epoch, conn, KubernetesOwnershipBaseAuthorityIssue{
			Authority: KubernetesOwnershipBaseAuthority{WireVersion: 1, NodeID: nodeID.String(), OrgID: scope.OrgID.String(), SiteID: scope.SiteID.String(), BaseVersion: base.Version, BaseHash: hash, Classifications: []KubernetesOwnershipPoolClassification{classification}},
			Pools:     []KubernetesOwnershipBaseAuthorityPoolGeneration{{Scope: classification.Scope, PromotionGeneration: uint64(generation)}}, TransitionRevision: uint64(revision), ExpiresAt: expires,
		})
		if err != nil {
			return false, err
		}
		if err := requireHandoffHALeaderSession(ctx, epoch, conn); err != nil {
			return false, err
		}
		maintained = append(maintained, HandoffBaseAuthorityArmMember{NodeID: nodeID, AuthorityRevision: issued.Authority.AuthorityRevision, BaseVersion: issued.Authority.BaseVersion, BaseHash: issued.Authority.BaseHash, PayloadDigest: issued.PayloadDigest})
	}
	ready, err := exactHandoffHAAuthorityReceipts(ctx, conn, now.UTC(), t.config.MaxAckAge, scope, uint64(generation), uint64(revision), "classification", "maintain_fence", maintained)
	if err != nil || !ready {
		return false, err
	}
	// A distinct transition-revision domain makes the explicit release a newer
	// authority even when the ordinary base bytes did not change during drain.
	unfenceRevision := uint64(revision) + 1
	unfenced := make([]HandoffBaseAuthorityArmMember, 0, len(maintained))
	for _, prior := range maintained {
		issued, err := t.authority.IssueKubernetesOwnershipBaseAuthorityWithLeadership(ctx, epoch, conn, KubernetesOwnershipBaseAuthorityIssue{
			Authority: KubernetesOwnershipBaseAuthority{WireVersion: 1, NodeID: prior.NodeID.String(), OrgID: scope.OrgID.String(), SiteID: scope.SiteID.String(), BaseVersion: prior.BaseVersion, BaseHash: prior.BaseHash, UnfencedPools: []KubernetesOwnershipPoolScope{classification.Scope}},
			Pools:     []KubernetesOwnershipBaseAuthorityPoolGeneration{{Scope: classification.Scope, PromotionGeneration: uint64(generation)}}, TransitionRevision: unfenceRevision, ExpiresAt: expires,
		})
		if err != nil {
			return false, err
		}
		unfenced = append(unfenced, HandoffBaseAuthorityArmMember{NodeID: prior.NodeID, AuthorityRevision: issued.Authority.AuthorityRevision, BaseVersion: issued.Authority.BaseVersion, BaseHash: issued.Authority.BaseHash, PayloadDigest: issued.PayloadDigest})
	}
	ready, err = exactHandoffHAAuthorityReceipts(ctx, conn, now.UTC(), t.config.MaxAckAge, scope, uint64(generation), unfenceRevision, "unfence", "", unfenced)
	if err != nil || !ready {
		return false, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return false, err
	}
	var lockedGeneration int64
	var lockedMembershipEpoch *int64
	var lockedActive uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT p.generation,p.active_node_id,t.membership_epoch FROM k8s_connector_pool_ha_transitions t
		JOIN k8s_connector_pools p ON p.id=t.pool_id AND p.org_id=t.org_id AND p.site_id=t.site_id AND p.cluster_id=t.cluster_id
		WHERE t.pool_id=$1 AND t.org_id=$2 AND t.transition_revision=$3 AND t.requested_mode='legacy' AND t.actual_mode='drain_pending'
		FOR UPDATE OF t,p`, scope.PoolID, scope.OrgID, revision).Scan(&lockedGeneration, &lockedActive, &lockedMembershipEpoch); err != nil || lockedGeneration != generation || lockedActive != active || lockedMembershipEpoch == nil || *lockedMembershipEpoch != *membershipEpoch {
		return false, ErrHandoffHATransitionRefused
	}
	lockedMembers, err := loadHandoffHADrainMembers(ctx, tx, scope, true)
	if err != nil || !sameUUIDSet(lockedMembers, members) {
		return false, ErrHandoffHATransitionRefused
	}
	if ready, err := exactHandoffHAAuthorityReceipts(ctx, tx, now.UTC(), t.config.MaxAckAge, scope, uint64(generation), unfenceRevision, "unfence", "", unfenced); err != nil || !ready {
		return false, ErrHandoffHATransitionRefused
	}
	var stillNonterminal, stillServing bool
	if err := tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM k8s_connector_handoff_operations WHERE org_id=$1 AND pool_id=$2 AND phase NOT IN ('complete','failed')),
		EXISTS(SELECT 1 FROM pool_vip_ownership_deliveries d JOIN pool_vip_ownership_delivery_ack_receipts r ON r.delivery_row_id=d.id AND r.org_id=d.org_id
		 WHERE d.wire_version=3 AND d.org_id=$1 AND d.pool_id=$2 AND r.applied_role='serving' AND d.expires_at>$3)`, scope.OrgID, scope.PoolID, now.UTC()).Scan(&stillNonterminal, &stillServing); err != nil || stillNonterminal || stillServing {
		return false, ErrHandoffHATransitionRefused
	}
	var achieved uint64
	for _, item := range unfenced {
		if item.AuthorityRevision > achieved {
			achieved = item.AuthorityRevision
		}
	}
	ct, err := tx.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET actual_mode='legacy',reason_code='legacy',
		transition_revision=$3,achieved_authority_revision=$4,achieved_at=$5,actor_user_id=NULL,actor_system='k8s-ha-activation',cause='exact drain and unfence achieved'
		WHERE pool_id=$1 AND org_id=$2 AND transition_revision=$6 AND requested_mode='legacy' AND actual_mode='drain_pending'`, scope.PoolID, scope.OrgID, int64(unfenceRevision), int64(achieved), now.UTC(), revision)
	if err != nil || ct.RowsAffected() != 1 {
		return false, ErrHandoffHATransitionRefused
	}
	metadata, _ := json.Marshal(map[string]any{
		"old_requested_mode": "legacy", "new_requested_mode": "legacy",
		"old_actual_mode": "drain_pending", "new_actual_mode": "legacy",
		"promotion_generation": generation, "membership_epoch": *membershipEpoch,
		"old_transition_revision": uint64(revision), "new_transition_revision": unfenceRevision,
		"achieved_authority_revision": achieved,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata)
		VALUES($1,'k8s-ha-activation','k8s.connector_pool_ha_deactivated','k8s_connector_pool',$2,$3)`, scope.OrgID, scope.PoolID.String(), metadata); err != nil {
		return false, err
	}
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// advanceRetryableHandoffDrainAuthorityWithLeadership is the drain equivalent
// of bootstrap retry. It only advances a persisted transition after its
// maintain-fence authority expired or its receipt became stale; it never
// rewrites evidence at the existing revision.
func (t *PostgresHandoffOwnershipModeTransition) advanceRetryableHandoffDrainAuthorityWithLeadership(ctx context.Context, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, scope k8s.HandoffPoolScope, revision, generation uint64, members []uuid.UUID) (uint64, uint64, []uuid.UUID, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, 0, nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return 0, 0, nil, err
	}
	var currentRevision, membershipEpoch int64
	if err := tx.QueryRow(ctx, `SELECT transition_revision,membership_epoch FROM k8s_connector_pool_ha_transitions
		WHERE org_id=$1 AND site_id=$2 AND cluster_id=$3 AND pool_id=$4 AND requested_mode='legacy' AND actual_mode='drain_pending' FOR UPDATE`,
		scope.OrgID, scope.SiteID, scope.ClusterID, scope.PoolID).Scan(&currentRevision, &membershipEpoch); err != nil || currentRevision <= 0 || membershipEpoch < 0 || uint64(currentRevision) != revision {
		return 0, 0, nil, ErrHandoffHATransitionRefused
	}
	lockedMembers, err := loadHandoffHADrainMembers(ctx, tx, scope, true)
	if err != nil || !sameUUIDSet(lockedMembers, members) {
		return 0, 0, nil, ErrHandoffHATransitionRefused
	}
	var expiredUnacknowledged, staleReceipt bool
	err = tx.QueryRow(ctx, `SELECT COALESCE(bool_or(r.delivery_id IS NULL AND d.expires_at <= $8),false),
		COALESCE(bool_or(r.delivery_id IS NOT NULL AND (r.receipt_time > $8 OR r.receipt_time < $9)),false)
		FROM k8s_base_authority_deliveries d JOIN k8s_base_authority_delivery_pools p ON p.delivery_id=d.id AND p.org_id=d.org_id AND p.site_id=d.site_id AND p.node_id=d.node_id
		LEFT JOIN k8s_base_authority_ack_receipts r ON r.delivery_id=d.id AND r.org_id=d.org_id AND r.site_id=d.site_id AND r.node_id=d.node_id
		WHERE d.org_id=$1 AND d.site_id=$2 AND d.authority_kind='transition' AND d.transition_revision=$3 AND p.cluster_id=$4 AND p.pool_id=$5 AND p.promotion_generation=$6
		AND p.kind='classification' AND p.disposition='maintain_fence' AND d.node_id=ANY($7)`,
		scope.OrgID, scope.SiteID, int64(revision), scope.ClusterID, scope.PoolID, int64(generation), lockedMembers, now, now.Add(-t.config.MaxAckAge)).Scan(&expiredUnacknowledged, &staleReceipt)
	if err != nil {
		return 0, 0, nil, err
	}
	_, retry := classifyHandoffHAAuthorityRetry(expiredUnacknowledged, staleReceipt)
	if !retry {
		return revision, uint64(membershipEpoch), lockedMembers, nil
	}
	if revision == uint64(^uint64(0)>>1) {
		return 0, 0, nil, ErrHandoffHATransitionRefused
	}
	next := revision + 1
	ct, err := tx.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET transition_revision=$3,reason_code=$4,achieved_authority_revision=NULL,achieved_at=NULL,actor_user_id=NULL,actor_system='k8s-ha-activation',cause='retry stale or expired drain base authority evidence'
		WHERE pool_id=$1 AND org_id=$2 AND transition_revision=$5 AND requested_mode='legacy' AND actual_mode='drain_pending'`, scope.PoolID, scope.OrgID, int64(next), handoffHAAuthorityRetryReasonCode, int64(revision))
	if err != nil || ct.RowsAffected() != 1 {
		return 0, 0, nil, ErrHandoffHATransitionRefused
	}
	metadata, err := json.Marshal(map[string]any{
		"old_transition_revision": revision,
		"new_transition_revision": next,
		"promotion_generation":    generation,
		"membership_epoch":        membershipEpoch,
	})
	if err != nil {
		return 0, 0, nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata)
		VALUES($1,'k8s-ha-activation','k8s.connector_pool_ha_drain_authority_retried','k8s_connector_pool',$2,$3)`, scope.OrgID, scope.PoolID.String(), metadata); err != nil {
		return 0, 0, nil, err
	}
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return 0, 0, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, nil, err
	}
	return next, uint64(membershipEpoch), lockedMembers, nil
}

func loadHandoffHADrainMembers(ctx context.Context, q handoffHAQuerier, scope k8s.HandoffPoolScope, lock bool) ([]uuid.UUID, error) {
	suffix := ""
	if lock {
		suffix = " FOR SHARE OF m,n"
	}
	rows, err := q.Query(ctx, `SELECT m.node_id FROM k8s_connector_pool_members m JOIN nodes n
		ON n.id=m.node_id AND n.org_id=m.org_id AND n.site_id=m.site_id
		WHERE m.pool_id=$1 AND m.org_id=$2 AND m.site_id=$3 AND n.status='active' AND n.revoked_at IS NULL ORDER BY m.node_id`+suffix, scope.PoolID, scope.OrgID, scope.SiteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func loadHandoffHADrainClassification(ctx context.Context, q handoffHAQuerier, scope k8s.HandoffPoolScope, generation uint64) (KubernetesOwnershipPoolClassification, error) {
	var raw []byte
	err := q.QueryRow(ctx, `SELECT p.classification FROM k8s_base_authority_delivery_pools p
		JOIN k8s_base_authority_ack_receipts r ON r.delivery_id=p.delivery_id
		WHERE p.org_id=$1 AND p.site_id=$2 AND p.cluster_id=$3 AND p.pool_id=$4 AND p.promotion_generation=$5
		 AND p.kind='classification' ORDER BY r.receipt_time DESC LIMIT 1`, scope.OrgID, scope.SiteID, scope.ClusterID, scope.PoolID, int64(generation)).Scan(&raw)
	if err != nil {
		return KubernetesOwnershipPoolClassification{}, err
	}
	var out KubernetesOwnershipPoolClassification
	if json.Unmarshal(raw, &out) != nil || out.Scope != (KubernetesOwnershipPoolScope{OrgID: scope.OrgID.String(), SiteID: scope.SiteID.String(), ClusterID: scope.ClusterID.String(), PoolID: scope.PoolID.String()}) {
		return KubernetesOwnershipPoolClassification{}, ErrHandoffHATransitionRefused
	}
	return out, nil
}

func exactHandoffHAAuthorityReceipts(ctx context.Context, q handoffHAQuerier, now time.Time, maxAge time.Duration, scope k8s.HandoffPoolScope, generation, transitionRevision uint64, kind, disposition string, members []HandoffBaseAuthorityArmMember) (bool, error) {
	for _, member := range members {
		var receipt time.Time
		err := q.QueryRow(ctx, `SELECT r.receipt_time FROM k8s_base_authority_deliveries d
			JOIN k8s_base_authority_delivery_pools p ON p.delivery_id=d.id AND p.org_id=d.org_id AND p.node_id=d.node_id
			JOIN k8s_base_authority_ack_receipts r ON r.delivery_id=d.id AND r.org_id=d.org_id AND r.node_id=d.node_id
			WHERE d.org_id=$1 AND d.site_id=$2 AND d.node_id=$3 AND d.authority_revision=$4 AND d.authority_kind='transition' AND d.transition_revision=$5
			 AND d.base_version=$6 AND d.base_hash=$7 AND d.payload_digest=$8 AND p.cluster_id=$9 AND p.pool_id=$10
			 AND p.promotion_generation=$11 AND p.kind=$12 AND (p.disposition=$13 OR ($13='' AND p.disposition IS NULL))`, scope.OrgID, scope.SiteID,
			member.NodeID, int64(member.AuthorityRevision), int64(transitionRevision), int64(member.BaseVersion), member.BaseHash, member.PayloadDigest,
			scope.ClusterID, scope.PoolID, int64(generation), kind, disposition).Scan(&receipt)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if receipt.After(now) || now.Sub(receipt) > maxAge {
			return false, nil
		}
	}
	return true, nil
}

type handoffHAQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadHandoffHATransitionSnapshot(ctx context.Context, q handoffHAQuerier, plan HandoffBootstrapPlan, lock bool) (uint64, uint64, []uuid.UUID, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE OF t,p,s,h"
	}
	var revision, generation, transitionGeneration int64
	var active, transitionActive uuid.UUID
	var membershipEpoch, transitionEpoch *int64
	var enabled bool
	err := q.QueryRow(ctx, `SELECT s.enabled,t.transition_revision,p.generation,p.active_node_id,
			t.promotion_generation,t.active_node_id,t.membership_epoch,h.membership_epoch
		FROM k8s_connector_pool_ha_transitions t
		JOIN k8s_ha_settings s ON s.org_id=t.org_id
		JOIN k8s_connector_pools p ON p.id=t.pool_id AND p.org_id=t.org_id AND p.site_id=t.site_id AND p.cluster_id=t.cluster_id
		JOIN k8s_connector_pool_health_states h ON h.pool_id=t.pool_id AND h.org_id=t.org_id
		WHERE t.org_id=$1 AND t.site_id=$2 AND t.cluster_id=$3 AND t.pool_id=$4
		 AND t.requested_mode='fenced_ha' AND t.actual_mode='bootstrap_pending'`+suffix,
		plan.Scope.OrgID, plan.Scope.SiteID, plan.Scope.ClusterID, plan.Scope.PoolID).Scan(&enabled, &revision, &generation, &active,
		&transitionGeneration, &transitionActive, &transitionEpoch, &membershipEpoch)
	if err != nil || !enabled || revision <= 0 || generation != int64(plan.Generation) || transitionGeneration != generation ||
		active != plan.ActiveNodeID || transitionActive != active || transitionEpoch == nil || membershipEpoch == nil || *transitionEpoch != *membershipEpoch {
		return 0, 0, nil, ErrHandoffHATransitionRefused
	}
	memberLock := ""
	if lock {
		memberLock = " FOR SHARE OF m,n"
	}
	rows, err := q.Query(ctx, `SELECT m.node_id FROM k8s_connector_pool_members m
		JOIN nodes n ON n.id=m.node_id AND n.org_id=m.org_id AND n.site_id=m.site_id
		WHERE m.pool_id=$1 AND m.org_id=$2 AND m.site_id=$3 AND n.status='active' AND n.revoked_at IS NULL ORDER BY m.node_id`+memberLock, plan.Scope.PoolID, plan.Scope.OrgID, plan.Scope.SiteID)
	if err != nil {
		return 0, 0, nil, err
	}
	defer rows.Close()
	var members []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return 0, 0, nil, err
		}
		members = append(members, id)
	}
	want := append([]uuid.UUID{plan.ActiveNodeID}, plan.EligibleStandbyIDs...)
	if err := rows.Err(); err != nil || !sameUUIDSet(members, want) {
		return 0, 0, nil, ErrHandoffHATransitionRefused
	}
	return uint64(revision), uint64(*membershipEpoch), members, nil
}

func bootstrapBaseClassification(plan HandoffBootstrapPlan) (KubernetesOwnershipPoolClassification, error) {
	m := plan.CurrentOwnerEnvelope.Manifest
	fields := KubernetesOwnershipPoolFields{Routes: append([]string(nil), m.Routes...)}
	for _, peer := range m.WGPeers {
		fields.WGPeers = append(fields.WGPeers, KubernetesOwnershipWGPeer{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)})
	}
	for _, service := range m.Services {
		fields.VIPMappings = append(fields.VIPMappings, policyspec.VIPMapping{ServiceID: service.ServiceID, VIP: service.VIP, Namespace: service.Namespace, Service: service.Service, ServiceCIDR: service.ServiceCIDR, DNSName: service.DNSName, Protocol: service.Protocol, PortLow: service.Port, PortHigh: service.Port})
	}
	if len(m.Services) > 0 {
		fields.DNSZones = []policyspec.K8sDNSZone{{ListenVIP: m.DNSVIP, Zone: m.DNSZone}}
	}
	classification := KubernetesOwnershipPoolClassification{Scope: KubernetesOwnershipPoolScope{OrgID: plan.Scope.OrgID.String(), SiteID: plan.Scope.SiteID.String(), ClusterID: plan.Scope.ClusterID.String(), PoolID: plan.Scope.PoolID.String()}, Disposition: KubernetesOwnershipPoolDispositionArmFence, Fields: fields}
	probe := KubernetesOwnershipBaseAuthority{WireVersion: 1, AuthorityRevision: 1, NodeID: plan.ActiveNodeID.String(), OrgID: plan.Scope.OrgID.String(), SiteID: plan.Scope.SiteID.String(), BaseVersion: 1, BaseHash: fmt.Sprintf("%064x", 1), Classifications: []KubernetesOwnershipPoolClassification{classification}}
	if _, _, err := CanonicalKubernetesOwnershipBaseAuthority(probe); err != nil {
		return KubernetesOwnershipPoolClassification{}, err
	}
	return classification, nil
}

func confirmHandoffBootstrapServiceUIDs(ctx context.Context, tx pgx.Tx, plan HandoffBootstrapPlan) error {
	for _, service := range plan.ServiceUIDs {
		var uid string
		var revision int64
		var node uuid.UUID
		err := tx.QueryRow(ctx, `SELECT c.uid,c.replay_sequence,r.connector_node_id
			FROM k8s_service_uid_observation_ledgers l
			JOIN k8s_service_uid_observation_current c ON c.ledger_id=l.id AND c.org_id=l.org_id
			JOIN k8s_service_uid_observation_current_attributions a ON a.ledger_id=c.ledger_id AND a.org_id=c.org_id AND a.namespace=c.namespace AND a.service=c.service AND a.replay_sequence=c.replay_sequence
			JOIN k8s_service_uid_observation_replay_states r ON r.id=a.replay_state_id AND r.org_id=a.org_id AND r.site_id=l.site_id AND r.cluster_id=l.cluster_id
			WHERE l.org_id=$1 AND l.site_id=$2 AND l.cluster_id=$3 AND c.namespace=$4 AND c.service=$5 AND c.state='live'
			FOR SHARE OF l,c,a,r`, plan.Scope.OrgID, plan.Scope.SiteID, plan.Scope.ClusterID, service.Namespace, service.Service).Scan(&uid, &revision, &node)
		if err != nil || uid != service.UID || revision != int64(service.ObservationRevision) || node != plan.ActiveNodeID {
			return ErrHandoffHATransitionRefused
		}
	}
	return nil
}

func requireHandoffHALeaderSession(ctx context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) error {
	if conn == nil || epoch.BackendPID <= 0 || epoch.LockKey != leader.SchedulerLockKey {
		return ErrHandoffBootstrapLeaderSession
	}
	return validPoolVIPOwnershipHandoffLeaderSession(ctx, PoolVIPOwnershipHandoffLeaderSession{Epoch: PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey}, Conn: conn})
}

func requireHandoffHALeaderSessionTx(ctx context.Context, tx pgx.Tx, epoch k8s.HandoffLeadershipEpoch) error {
	return validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey})
}

func sameUUIDSet(a, b []uuid.UUID) bool {
	a, b = append([]uuid.UUID(nil), a...), append([]uuid.UUID(nil), b...)
	sort.Slice(a, func(i, j int) bool { return a[i].String() < a[j].String() })
	sort.Slice(b, func(i, j int) bool { return b[i].String() < b[j].String() })
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func armNodeIDs(value HandoffBaseAuthorityArmSnapshot) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(value.Members))
	for _, member := range value.Members {
		out = append(out, member.NodeID)
	}
	return out
}

var _ HandoffOwnershipModeTransition = (*PostgresHandoffOwnershipModeTransition)(nil)
