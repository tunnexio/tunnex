package nodes

import (
	"context"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// HandoffOrdinaryBaseAuthorityMaintainer is the leader-bound D4/D5 seam for
// already-fenced pools. Bootstrap arm receipts prove only their exact initial
// base; every later ordinary-base change must classify every armed pool
// visible to that node with maintain_fence.
type HandoffOrdinaryBaseAuthorityMaintainer interface {
	MaintainHandoffOrdinaryBaseAuthorityWithLeadership(context.Context, time.Time, k8s.HandoffLeadershipEpoch, *pgxpool.Conn, []HandoffBootstrapPlan) (bool, error)
}

type handoffOrdinaryBaseMaintenanceNode struct {
	nodeID             uuid.UUID
	orgID              uuid.UUID
	siteID             uuid.UUID
	transitionRevision uint64
	classifications    []KubernetesOwnershipPoolClassification
	pools              []KubernetesOwnershipBaseAuthorityPoolGeneration
}

// MaintainHandoffOrdinaryBaseAuthorityWithLeadership batches by node, not by
// pool. A node may carry several armed pools, and sending one classification
// at a time would make the later delivery scope-incomplete and cause the node
// to reject it (or strand the omitted fence on the old base hash).
func (t *PostgresHandoffOwnershipModeTransition) MaintainHandoffOrdinaryBaseAuthorityWithLeadership(ctx context.Context, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, plans []HandoffBootstrapPlan) (bool, error) {
	if t == nil || !t.config.valid() || now.IsZero() || len(plans) == 0 {
		return false, ErrHandoffHATransitionRefused
	}
	if err := requireHandoffHALeaderSession(ctx, epoch, conn); err != nil {
		return false, err
	}
	plans = append([]HandoffBootstrapPlan(nil), plans...)
	sort.Slice(plans, func(i, j int) bool {
		if plans[i].Scope.OrgID != plans[j].Scope.OrgID {
			return plans[i].Scope.OrgID.String() < plans[j].Scope.OrgID.String()
		}
		if plans[i].Scope.SiteID != plans[j].Scope.SiteID {
			return plans[i].Scope.SiteID.String() < plans[j].Scope.SiteID.String()
		}
		return plans[i].Scope.PoolID.String() < plans[j].Scope.PoolID.String()
	})
	for i, plan := range plans {
		if !validHandoffBootstrapPlan(plan, now.UTC()) || (i > 0 && plan.Scope == plans[i-1].Scope) {
			return false, ErrHandoffHATransitionRefused
		}
	}

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return false, err
	}

	byNode := make(map[uuid.UUID]*handoffOrdinaryBaseMaintenanceNode)
	for _, plan := range plans {
		revision, members, err := loadHandoffHAFencedMaintenanceSnapshot(ctx, tx, plan)
		if err != nil {
			return false, err
		}
		// The earlier scheduler plan is only a hint. Re-derive it while this
		// transaction holds the pool/member/Service/UID locks, exactly like the
		// v3 envelope issuer, so D5 classification can never trail the base it
		// authorizes because of a Service recreation between planning and issue.
		topology, found, err := loadHandoffBootstrapTopology(ctx, tx, plan.Scope)
		if err != nil || !found {
			if err == nil {
				err = ErrHandoffHATransitionRefused
			}
			return false, err
		}
		if err := loadHandoffBootstrapCounters(ctx, tx, &topology, plan.CurrentOwnerEnvelope.ExpiresAt); err != nil {
			return false, err
		}
		lockedPlan, err := buildHandoffBootstrapPlan(topology, plan.CurrentOwnerEnvelope.ExpiresAt)
		if err != nil || !reflect.DeepEqual(lockedPlan, plan) {
			return false, ErrHandoffHATransitionRefused
		}
		classification, err := bootstrapBaseClassification(lockedPlan)
		if err != nil {
			return false, err
		}
		classification.Disposition = KubernetesOwnershipPoolDispositionMaintainFence
		pool := KubernetesOwnershipBaseAuthorityPoolGeneration{Scope: classification.Scope, PromotionGeneration: plan.Generation}
		for _, nodeID := range members {
			entry := byNode[nodeID]
			if entry == nil {
				entry = &handoffOrdinaryBaseMaintenanceNode{nodeID: nodeID, orgID: plan.Scope.OrgID, siteID: plan.Scope.SiteID}
				byNode[nodeID] = entry
			}
			if entry.orgID != plan.Scope.OrgID || entry.siteID != plan.Scope.SiteID {
				return false, ErrHandoffHATransitionRefused
			}
			if revision > entry.transitionRevision {
				entry.transitionRevision = revision
			}
			entry.classifications = append(entry.classifications, classification)
			entry.pools = append(entry.pools, pool)
		}
	}

	nodeIDs := make([]uuid.UUID, 0, len(byNode))
	for nodeID := range byNode {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Slice(nodeIDs, func(i, j int) bool { return nodeIDs[i].String() < nodeIDs[j].String() })
	expires := now.UTC().Truncate(t.config.AuthorityTTL).Add(2 * t.config.AuthorityTTL)
	allAccepted := true
	for _, nodeID := range nodeIDs {
		entry := byNode[nodeID]
		acceptedPools, err := loadAcceptedKubernetesOwnershipClassificationPools(ctx, tx, entry.orgID, entry.siteID, nodeID)
		if err != nil {
			return false, err
		}
		classifiedPools := make(map[uuid.UUID]struct{}, len(entry.pools))
		for _, pool := range entry.pools {
			poolID, err := uuid.Parse(pool.Scope.PoolID)
			if err != nil || poolID == uuid.Nil {
				return false, ErrHandoffHATransitionRefused
			}
			classifiedPools[poolID] = struct{}{}
		}
		// The latest accepted authority is the CP's exact durable view of the
		// fences this node has already armed. If a pool is absent from this batch
		// (for example because it has a handoff in progress), refuse rather than
		// emit a scope-incomplete authority that the node must reject.
		if !sameAcceptedKubernetesOwnershipClassificationPools(acceptedPools, classifiedPools) {
			// Extra maintain_fence is no safer than an omission: the node has no
			// durable armed-fence evidence for that scope and must reject it.
			return false, ErrHandoffHATransitionRefused
		}
		base, err := t.base.HandoffBaseState(ctx, entry.orgID, nodeID)
		if err != nil || base.NodeID != nodeID.String() || base.Version == 0 || entry.transitionRevision == 0 {
			if err == nil {
				err = ErrHandoffHATransitionRefused
			}
			return false, err
		}
		hash, err := KubernetesOwnershipBaseStateHash(base)
		if err != nil {
			return false, err
		}
		issued, err := t.authority.IssueKubernetesOwnershipBaseAuthorityWithLeadershipTx(ctx, epoch, tx, KubernetesOwnershipBaseAuthorityIssue{
			Authority: KubernetesOwnershipBaseAuthority{
				WireVersion: KubernetesOwnershipBaseAuthorityWireVersion, NodeID: nodeID.String(), OrgID: entry.orgID.String(), SiteID: entry.siteID.String(),
				BaseVersion: base.Version, BaseHash: hash, Classifications: entry.classifications,
			},
			Pools: entry.pools, ExpiresAt: expires, OrdinaryBaseUpdate: true,
		})
		if err != nil {
			return false, err
		}
		var accepted bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM k8s_base_authority_ack_receipts
			WHERE delivery_id=$1 AND org_id=$2 AND site_id=$3 AND node_id=$4
			  AND authority_revision=$5 AND payload_digest=$6
			  AND applied_base_version=$7 AND applied_base_hash=$8
		)`, issued.DeliveryID, entry.orgID, entry.siteID, nodeID, int64(issued.Authority.AuthorityRevision),
			issued.PayloadDigest, int64(issued.Authority.BaseVersion), issued.Authority.BaseHash).Scan(&accepted); err != nil {
			return false, err
		}
		if !accepted {
			allAccepted = false
		}
	}
	if err := requireHandoffHALeaderSessionTx(ctx, tx, epoch); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return allAccepted, nil
}

func sameAcceptedKubernetesOwnershipClassificationPools(accepted []uuid.UUID, classified map[uuid.UUID]struct{}) bool {
	if len(accepted) != len(classified) {
		return false
	}
	for _, poolID := range accepted {
		if _, ok := classified[poolID]; !ok {
			return false
		}
	}
	return true
}

func loadAcceptedKubernetesOwnershipClassificationPools(ctx context.Context, tx pgx.Tx, orgID, siteID, nodeID uuid.UUID) ([]uuid.UUID, error) {
	// Match the ACK path's delivery -> node-state order. In particular, do not
	// hold the state row while waiting for an agent that already owns its delivery
	// row and needs that same state row to persist the receipt.
	if err := lockLatestKubernetesOwnershipAuthorityDeliveryForNode(ctx, tx, orgID, siteID, nodeID); err != nil {
		return nil, err
	}
	var acceptedRevision int64
	if err := tx.QueryRow(ctx, `SELECT accepted_authority_revision
		FROM k8s_base_authority_node_states
		WHERE org_id=$1 AND site_id=$2 AND node_id=$3 FOR UPDATE`, orgID, siteID, nodeID).Scan(&acceptedRevision); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT p.pool_id,p.kind,d.authority_revision
		FROM k8s_base_authority_deliveries d
		JOIN k8s_base_authority_ack_receipts r
		  ON r.delivery_id=d.id AND r.org_id=d.org_id AND r.site_id=d.site_id AND r.node_id=d.node_id
		JOIN k8s_base_authority_delivery_pools p
		  ON p.delivery_id=d.id AND p.org_id=d.org_id AND p.site_id=d.site_id AND p.node_id=d.node_id
		WHERE d.org_id=$1 AND d.site_id=$2 AND d.node_id=$3 AND d.authority_revision <= $4
		ORDER BY p.pool_id,d.authority_revision DESC`, orgID, siteID, nodeID, acceptedRevision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pools []uuid.UUID
	seen := map[uuid.UUID]struct{}{}
	for rows.Next() {
		var poolID uuid.UUID
		var kind string
		var revision int64
		if err := rows.Scan(&poolID, &kind, &revision); err != nil {
			return nil, err
		}
		if _, ok := seen[poolID]; ok {
			continue
		}
		seen[poolID] = struct{}{}
		if kind == "classification" {
			pools = append(pools, poolID)
		}
	}
	return pools, rows.Err()
}

func loadHandoffHAFencedMaintenanceSnapshot(ctx context.Context, tx pgx.Tx, plan HandoffBootstrapPlan) (uint64, []uuid.UUID, error) {
	var revision, generation, transitionGeneration int64
	var active, transitionActive uuid.UUID
	var membershipEpoch, transitionEpoch *int64
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT s.enabled,t.transition_revision,p.generation,p.active_node_id,
			t.promotion_generation,t.active_node_id,t.membership_epoch,h.membership_epoch
		FROM k8s_connector_pool_ha_transitions t
		JOIN k8s_ha_settings s ON s.org_id=t.org_id
		JOIN k8s_connector_pools p ON p.id=t.pool_id AND p.org_id=t.org_id AND p.site_id=t.site_id AND p.cluster_id=t.cluster_id
		JOIN k8s_connector_pool_health_states h ON h.pool_id=t.pool_id AND h.org_id=t.org_id
		WHERE t.org_id=$1 AND t.site_id=$2 AND t.cluster_id=$3 AND t.pool_id=$4
		 AND t.requested_mode='fenced_ha' AND t.actual_mode='fenced_ha'
		 AND NOT EXISTS (SELECT 1 FROM k8s_connector_handoff_operations o
			WHERE o.org_id=t.org_id AND o.site_id=t.site_id AND o.cluster_id=t.cluster_id AND o.pool_id=t.pool_id
			  AND o.phase NOT IN ('complete','failed'))
		FOR UPDATE OF t,p,s,h`, plan.Scope.OrgID, plan.Scope.SiteID, plan.Scope.ClusterID, plan.Scope.PoolID).
		Scan(&enabled, &revision, &generation, &active, &transitionGeneration, &transitionActive, &transitionEpoch, &membershipEpoch)
	if err != nil || !enabled || revision <= 0 || generation != int64(plan.Generation) || transitionGeneration != generation ||
		active != plan.ActiveNodeID || transitionActive != active || transitionEpoch == nil || membershipEpoch == nil || *transitionEpoch != *membershipEpoch {
		return 0, nil, ErrHandoffHATransitionRefused
	}
	rows, err := tx.Query(ctx, `SELECT m.node_id FROM k8s_connector_pool_members m
		JOIN nodes n ON n.id=m.node_id AND n.org_id=m.org_id AND n.site_id=m.site_id
		WHERE m.pool_id=$1 AND m.org_id=$2 AND m.site_id=$3 AND n.status='active' AND n.revoked_at IS NULL
		ORDER BY m.node_id FOR SHARE OF m,n`, plan.Scope.PoolID, plan.Scope.OrgID, plan.Scope.SiteID)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var members []uuid.UUID
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			return 0, nil, err
		}
		members = append(members, nodeID)
	}
	want := append([]uuid.UUID{plan.ActiveNodeID}, plan.EligibleStandbyIDs...)
	if err := rows.Err(); err != nil || !sameUUIDSet(members, want) {
		return 0, nil, ErrHandoffHATransitionRefused
	}
	return uint64(revision), members, nil
}

var _ HandoffOrdinaryBaseAuthorityMaintainer = (*PostgresHandoffOwnershipModeTransition)(nil)
