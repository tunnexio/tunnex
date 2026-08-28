package k8s

import (
	"context"
	"errors"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/pgerr"
)

// ConnectorPoolMemberConfiguration is one operator-configured member. The
// priority is only an ordering input; it never changes active ownership.
type ConnectorPoolMemberConfiguration struct {
	NodeID        uuid.UUID
	AdminPriority int32
}

// ConnectorPoolConfiguration is the finite, server-read configuration seam
// for a future API/UI. It intentionally contains neither health readiness nor
// handoff/P2 provenance. MembershipEpoch is known only once 0083 has a
// durable state row; callers must not invent one when older rows lack it.
type ConnectorPoolConfiguration struct {
	PoolID               uuid.UUID
	ClusterID            uuid.UUID
	PreferredNodeID      uuid.UUID
	ActiveNodeID         uuid.UUID
	Generation           uint64
	MembershipEpoch      uint64
	MembershipEpochKnown bool
	Members              []ConnectorPoolMemberConfiguration
}

// ConfigureConnectorPoolRequest reconciles the full desired member set. An
// existing pool requires ExpectedMembershipEpoch for a change: two writers
// with the same epoch serialize on the cluster, and the loser observes the
// trigger-created epoch change rather than overwriting the winner.
//
// A nil expected epoch is accepted for a legacy-to-pool create and an exact
// replay only. It can never authorize a changed existing pool.
type ConfigureConnectorPoolRequest struct {
	ClusterID               uuid.UUID
	Members                 []ConnectorPoolMemberConfiguration
	ExpectedMembershipEpoch *uint64
}

const connectorPoolConfigurationAuditAction = "k8s.cluster_connector_set"

// connectorPoolConfigurationAfterMutation is an unexported test-only fault
// seam. A production Service leaves it nil; it exists solely to prove that a
// failure after member writes/audit still rolls back the entire transaction.
// It is deliberately not a hook for notification or runtime behavior.
//
// Kept as a method lookup rather than an exported option so future HTTP wiring
// cannot accidentally acquire a partially committed configuration contract.
func (s *Service) connectorPoolConfigurationAfterMutation() error {
	if s.connectorPoolConfigurationAfterMutationHook != nil {
		return s.connectorPoolConfigurationAfterMutationHook()
	}
	return nil
}

// ConfigureConnectorPool creates the exact cluster-owned pool from the
// currently selected legacy connector, or reconciles an already explicit pool
// binding. It never calls the promotion CAS: active/preferred/generation are
// immutable here. Membership changes rely on the 0083 database triggers for
// membership-epoch invalidation; application code never manufactures epochs.
func (s *Service) ConfigureConnectorPool(ctx context.Context, orgID, siteID uuid.UUID, req ConfigureConnectorPoolRequest, actorUserID uuid.UUID, actorSystem, cause string) (out ConnectorPoolConfiguration, err error) {
	desired, err := canonicalConnectorPoolMembers(req.Members)
	if err != nil {
		return out, err
	}
	if orgID == uuid.Nil || siteID == uuid.Nil || req.ClusterID == uuid.Nil {
		return out, apierr.BadRequest("connector_pool_scope_required", "organization, site, and cluster are required")
	}

	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		cluster, err := q.GetK8sClusterForConnectorPoolConfigForUpdate(ctx, sqlc.GetK8sClusterForConnectorPoolConfigForUpdateParams{
			OrgID: orgID, SiteID: siteID, ClusterID: req.ClusterID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("cluster_not_found", "no such cluster in this organization and site")
		}
		if err != nil {
			return err
		}

		// Lock target nodes in UUID order after the cluster lock. This makes their
		// active/revoked/readiness predicates stable to commit and avoids a
		// cross-request node-lock inversion.
		if err := lockAndValidateConnectorPoolMembers(ctx, q, orgID, siteID, desired); err != nil {
			return err
		}

		pool, poolExists, err := lockedConfiguredPool(ctx, q, orgID, siteID, cluster)
		if err != nil {
			return err
		}
		if !poolExists {
			if !cluster.ConnectorNodeID.Valid {
				return apierr.Conflict("connector_pool_initial_connector_required", "the cluster needs its currently selected connector before a pool can be configured")
			}
			initial := uuid.UUID(cluster.ConnectorNodeID.Bytes)
			if !containsConnectorPoolMember(desired, initial) {
				return apierr.Conflict("connector_pool_active_member_required", "the currently active connector must remain a member when creating its pool")
			}
			created, err := q.CreateK8sConnectorPoolForConfig(ctx, sqlc.CreateK8sConnectorPoolForConfigParams{
				InitialConnectorNodeID: initial, OrgID: orgID, SiteID: siteID, ClusterID: req.ClusterID,
			})
			if pgerr.IsUnique(err) {
				return apierr.Conflict("connector_pool_binding_conflict", "a connector pool is already bound to this cluster or a requested connector belongs to another pool")
			}
			if err != nil {
				return err
			}
			pool = sqlc.K8sConnectorPool{ID: created.ID, OrgID: created.OrgID, SiteID: created.SiteID, ClusterID: created.ClusterID, PreferredNodeID: created.PreferredNodeID, ActiveNodeID: created.ActiveNodeID, Generation: created.Generation}

			current, err := q.ListK8sConnectorPoolMembersForConfigForUpdate(ctx, sqlc.ListK8sConnectorPoolMembersForConfigForUpdateParams{PoolID: pool.ID, OrgID: orgID, SiteID: siteID})
			if err != nil {
				return err
			}
			if err := reconcileConnectorPoolMembers(ctx, q, pool, current, desired); err != nil {
				return err
			}
			// Initial membership is configured before the first durable health row,
			// so it starts at its truthful database default epoch rather than being
			// counted as a post-configuration membership change.
			if _, err := q.CreateK8sConnectorPoolHealthState(ctx, healthStateCreateParams(pool)); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if changed, err := q.BindK8sClusterConnectorPoolFromLegacyForConfig(ctx, sqlc.BindK8sClusterConnectorPoolFromLegacyForConfigParams{
				ConnectorPoolID: pgtype.UUID{Bytes: pool.ID, Valid: true}, OrgID: orgID, SiteID: siteID, ClusterID: req.ClusterID, ExpectedConnectorNodeID: pgtype.UUID{Bytes: initial, Valid: true},
			}); err != nil {
				return err
			} else if changed != 1 {
				return apierr.Conflict("connector_pool_binding_conflict", "the cluster connector binding changed while configuring the pool")
			}
			return s.finishConnectorPoolConfiguration(ctx, q, orgID, req.ClusterID, pool, actorUserID, actorSystem, cause, desired, true, &out)
		}

		current, err := q.ListK8sConnectorPoolMembersForConfigForUpdate(ctx, sqlc.ListK8sConnectorPoolMembersForConfigForUpdateParams{PoolID: pool.ID, OrgID: orgID, SiteID: siteID})
		if err != nil {
			return err
		}
		if !containsConnectorPoolMember(desired, pool.ActiveNodeID) || !containsConnectorPoolMember(desired, pool.PreferredNodeID) {
			return apierr.Conflict("connector_pool_active_member_required", "the configured preferred and active connectors must remain pool members")
		}
		if sameConnectorPoolMembers(current, desired) {
			return fillConnectorPoolConfiguration(ctx, q, pool, desired, &out)
		}
		if req.ExpectedMembershipEpoch == nil {
			return apierr.Conflict("connector_pool_membership_epoch_required", "an expected membership epoch is required to change an existing connector pool")
		}
		if _, err := q.CreateK8sConnectorPoolHealthState(ctx, healthStateCreateParams(pool)); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		state, err := q.GetK8sConnectorPoolHealthStateForUpdate(ctx, healthStateGetForUpdateParams(pool))
		if err != nil {
			return err
		}
		if state.MembershipEpoch < 0 || uint64(state.MembershipEpoch) != *req.ExpectedMembershipEpoch {
			return apierr.Conflict("connector_pool_membership_epoch_conflict", "the connector pool membership changed; read its current configuration and retry")
		}
		if err := reconcileConnectorPoolMembers(ctx, q, pool, current, desired); err != nil {
			return err
		}
		return s.finishConnectorPoolConfiguration(ctx, q, orgID, req.ClusterID, pool, actorUserID, actorSystem, cause, desired, true, &out)
	})
	return out, err
}

// GetConnectorPoolConfiguration reads one coherent, explicitly pool-bound
// configuration incarnation. Its cluster -> pool -> members -> health-state
// locks match ConfigureConnectorPool, so the returned membership epoch cannot
// be paired with members from another 0083 incarnation.
//
// A raw orphan pool, an incomplete bound ID, or legacy+pool ambiguity is
// rejected through lockedConfiguredPool rather than silently looking like an
// unconfigured cluster.
func (s *Service) GetConnectorPoolConfiguration(ctx context.Context, orgID, siteID, clusterID uuid.UUID) (out ConnectorPoolConfiguration, err error) {
	if orgID == uuid.Nil || siteID == uuid.Nil || clusterID == uuid.Nil {
		return out, apierr.BadRequest("connector_pool_scope_required", "organization, site, and cluster are required")
	}
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		cluster, err := q.GetK8sClusterForConnectorPoolConfigForUpdate(ctx, sqlc.GetK8sClusterForConnectorPoolConfigForUpdateParams{OrgID: orgID, SiteID: siteID, ClusterID: clusterID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("connector_pool_not_found", "no connector pool is configured for this cluster")
		}
		if err != nil {
			return err
		}
		pool, configured, err := lockedConfiguredPool(ctx, q, orgID, siteID, cluster)
		if err != nil {
			return err
		}
		if !configured {
			return apierr.NotFound("connector_pool_not_found", "no connector pool is configured for this cluster")
		}
		members, err := q.ListK8sConnectorPoolMembersForConfigForUpdate(ctx, sqlc.ListK8sConnectorPoolMembersForConfigForUpdateParams{PoolID: pool.ID, OrgID: orgID, SiteID: siteID})
		if err != nil {
			return err
		}
		return connectorPoolConfigurationFromLockedRows(ctx, q, pool, members, &out)
	})
	return out, err
}

func lockedConfiguredPool(ctx context.Context, q *sqlc.Queries, orgID, siteID uuid.UUID, cluster sqlc.K8sCluster) (sqlc.K8sConnectorPool, bool, error) {
	pool, err := q.GetK8sConnectorPoolForClusterForConfigForUpdate(ctx, sqlc.GetK8sConnectorPoolForClusterForConfigForUpdateParams{OrgID: orgID, SiteID: siteID, ClusterID: cluster.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		if cluster.ConnectorPoolID.Valid {
			return sqlc.K8sConnectorPool{}, false, apierr.Conflict("connector_pool_binding_invalid", "the cluster has an incomplete connector pool binding")
		}
		return sqlc.K8sConnectorPool{}, false, nil
	}
	if err != nil {
		return sqlc.K8sConnectorPool{}, false, err
	}
	if !cluster.ConnectorPoolID.Valid || uuid.UUID(cluster.ConnectorPoolID.Bytes) != pool.ID || cluster.ConnectorNodeID.Valid {
		return sqlc.K8sConnectorPool{}, false, apierr.Conflict("connector_pool_binding_invalid", "the cluster has an ambiguous connector pool binding")
	}
	return pool, true, nil
}

func canonicalConnectorPoolMembers(in []ConnectorPoolMemberConfiguration) ([]ConnectorPoolMemberConfiguration, error) {
	if len(in) == 0 {
		return nil, apierr.BadRequest("connector_pool_members_required", "configure at least the currently active connector")
	}
	out := append([]ConnectorPoolMemberConfiguration(nil), in...)
	seen := make(map[uuid.UUID]struct{}, len(out))
	for _, member := range out {
		if member.NodeID == uuid.Nil {
			return nil, apierr.BadRequest("connector_node_required", "each connector pool member needs a gateway ID")
		}
		if _, exists := seen[member.NodeID]; exists {
			return nil, apierr.BadRequest("connector_pool_member_duplicate", "a connector can appear only once in a pool")
		}
		seen[member.NodeID] = struct{}{}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AdminPriority != out[j].AdminPriority {
			return out[i].AdminPriority > out[j].AdminPriority
		}
		return out[i].NodeID.String() < out[j].NodeID.String()
	})
	return out, nil
}

func lockAndValidateConnectorPoolMembers(ctx context.Context, q *sqlc.Queries, orgID, siteID uuid.UUID, members []ConnectorPoolMemberConfiguration) error {
	locked := append([]ConnectorPoolMemberConfiguration(nil), members...)
	sort.Slice(locked, func(i, j int) bool { return locked[i].NodeID.String() < locked[j].NodeID.String() })
	for _, member := range locked {
		node, err := q.GetNodeForOrgForUpdate(ctx, sqlc.GetNodeForOrgForUpdateParams{ID: member.NodeID, OrgID: orgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("connector_not_found", "no such gateway in this organization")
		}
		if err != nil {
			return err
		}
		if err := validateConnectorPoolMemberNode(node, siteID); err != nil {
			return err
		}
	}
	return nil
}

func reconcileConnectorPoolMembers(ctx context.Context, q *sqlc.Queries, pool sqlc.K8sConnectorPool, current []sqlc.K8sConnectorPoolMember, desired []ConnectorPoolMemberConfiguration) error {
	currentByID := make(map[uuid.UUID]sqlc.K8sConnectorPoolMember, len(current))
	for _, member := range current {
		currentByID[member.NodeID] = member
	}
	desiredByID := make(map[uuid.UUID]ConnectorPoolMemberConfiguration, len(desired))
	for _, member := range desired {
		desiredByID[member.NodeID] = member
		if existing, ok := currentByID[member.NodeID]; ok {
			if existing.AdminPriority != member.AdminPriority {
				if _, err := q.SetK8sConnectorPoolMemberPriorityForConfig(ctx, sqlc.SetK8sConnectorPoolMemberPriorityForConfigParams{PoolID: pool.ID, OrgID: pool.OrgID, SiteID: pool.SiteID, NodeID: member.NodeID, AdminPriority: member.AdminPriority}); err != nil {
					return err
				}
			}
			continue
		}
		if _, err := q.AddK8sConnectorPoolMemberForConfig(ctx, sqlc.AddK8sConnectorPoolMemberForConfigParams{PoolID: pool.ID, OrgID: pool.OrgID, SiteID: pool.SiteID, NodeID: member.NodeID, AdminPriority: member.AdminPriority}); err != nil {
			if pgerr.IsUnique(err) {
				return apierr.Conflict("connector_already_assigned", "that gateway already belongs to another connector pool")
			}
			return err
		}
	}
	for _, member := range current {
		if _, keep := desiredByID[member.NodeID]; keep {
			continue
		}
		// Callers have already been refused if this is active/preferred; the
		// guard remains here to preserve that invariant if this helper evolves.
		if member.NodeID == pool.ActiveNodeID || member.NodeID == pool.PreferredNodeID {
			return apierr.Conflict("connector_pool_active_member_required", "the configured preferred and active connectors must remain pool members")
		}
		if changed, err := q.DeleteK8sConnectorPoolMemberForConfig(ctx, sqlc.DeleteK8sConnectorPoolMemberForConfigParams{PoolID: pool.ID, OrgID: pool.OrgID, SiteID: pool.SiteID, NodeID: member.NodeID}); err != nil {
			return err
		} else if changed != 1 {
			return apierr.Conflict("connector_pool_membership_conflict", "the connector pool membership changed while applying configuration")
		}
	}
	return nil
}

func (s *Service) finishConnectorPoolConfiguration(ctx context.Context, q *sqlc.Queries, orgID, clusterID uuid.UUID, pool sqlc.K8sConnectorPool, actorUserID uuid.UUID, actorSystem, cause string, desired []ConnectorPoolMemberConfiguration, audit bool, out *ConnectorPoolConfiguration) error {
	if audit {
		// Reuse the existing connector-selection event taxonomy rather than
		// introducing an externally visible pool action before API review.
		if err := s.audit(ctx, q, orgID, actorUserID, actorSystem, cause, "k8s_cluster", clusterID.String(), connectorPoolConfigurationAuditAction, map[string]any{
			"mode": "connector_pool", "connector_pool_id": pool.ID.String(), "configured_active_node_id": pool.ActiveNodeID.String(), "configured_preferred_node_id": pool.PreferredNodeID.String(), "membership_count": len(desired),
		}); err != nil {
			return err
		}
	}
	if err := s.connectorPoolConfigurationAfterMutation(); err != nil {
		return err
	}
	return fillConnectorPoolConfiguration(ctx, q, pool, desired, out)
}

func fillConnectorPoolConfiguration(ctx context.Context, q *sqlc.Queries, pool sqlc.K8sConnectorPool, members []ConnectorPoolMemberConfiguration, out *ConnectorPoolConfiguration) error {
	*out = ConnectorPoolConfiguration{PoolID: pool.ID, ClusterID: pool.ClusterID, PreferredNodeID: pool.PreferredNodeID, ActiveNodeID: pool.ActiveNodeID, Generation: uint64(pool.Generation), Members: append([]ConnectorPoolMemberConfiguration(nil), members...)}
	state, err := q.GetK8sConnectorPoolHealthState(ctx, healthStateGetParams(pool))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.MembershipEpoch < 0 {
		return apierr.Conflict("connector_pool_membership_epoch_invalid", "the connector pool has an invalid membership epoch")
	}
	out.MembershipEpoch, out.MembershipEpochKnown = uint64(state.MembershipEpoch), true
	return nil
}

func connectorPoolConfigurationFromRows(ctx context.Context, q *sqlc.Queries, pool sqlc.K8sConnectorPool, rows []sqlc.K8sConnectorPoolMember) (ConnectorPoolConfiguration, error) {
	members := make([]ConnectorPoolMemberConfiguration, 0, len(rows))
	for _, row := range rows {
		members = append(members, ConnectorPoolMemberConfiguration{NodeID: row.NodeID, AdminPriority: row.AdminPriority})
	}
	var out ConnectorPoolConfiguration
	return out, fillConnectorPoolConfiguration(ctx, q, pool, members, &out)
}

func connectorPoolConfigurationFromLockedRows(ctx context.Context, q *sqlc.Queries, pool sqlc.K8sConnectorPool, rows []sqlc.K8sConnectorPoolMember, out *ConnectorPoolConfiguration) error {
	members := make([]ConnectorPoolMemberConfiguration, 0, len(rows))
	for _, row := range rows {
		members = append(members, ConnectorPoolMemberConfiguration{NodeID: row.NodeID, AdminPriority: row.AdminPriority})
	}
	// The locking query orders by UUID to avoid writer/read lock inversion; the
	// returned configuration retains its documented priority/UUID order.
	var err error
	members, err = canonicalConnectorPoolMembers(members)
	if err != nil {
		return err
	}
	*out = ConnectorPoolConfiguration{PoolID: pool.ID, ClusterID: pool.ClusterID, PreferredNodeID: pool.PreferredNodeID, ActiveNodeID: pool.ActiveNodeID, Generation: uint64(pool.Generation), Members: members}
	state, err := q.GetK8sConnectorPoolHealthStateForUpdate(ctx, healthStateGetForUpdateParams(pool))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.MembershipEpoch < 0 {
		return apierr.Conflict("connector_pool_membership_epoch_invalid", "the connector pool has an invalid membership epoch")
	}
	out.MembershipEpoch, out.MembershipEpochKnown = uint64(state.MembershipEpoch), true
	return nil
}

func healthStateGetParams(pool sqlc.K8sConnectorPool) sqlc.GetK8sConnectorPoolHealthStateParams {
	return sqlc.GetK8sConnectorPoolHealthStateParams{OrgID: pool.OrgID, SiteID: pool.SiteID, ClusterID: pool.ClusterID, PoolID: pool.ID}
}

func healthStateGetForUpdateParams(pool sqlc.K8sConnectorPool) sqlc.GetK8sConnectorPoolHealthStateForUpdateParams {
	return sqlc.GetK8sConnectorPoolHealthStateForUpdateParams{OrgID: pool.OrgID, SiteID: pool.SiteID, ClusterID: pool.ClusterID, PoolID: pool.ID}
}

func healthStateCreateParams(pool sqlc.K8sConnectorPool) sqlc.CreateK8sConnectorPoolHealthStateParams {
	return sqlc.CreateK8sConnectorPoolHealthStateParams{OrgID: pool.OrgID, SiteID: pool.SiteID, ClusterID: pool.ClusterID, PoolID: pool.ID}
}

func containsConnectorPoolMember(members []ConnectorPoolMemberConfiguration, id uuid.UUID) bool {
	for _, member := range members {
		if member.NodeID == id {
			return true
		}
	}
	return false
}

func sameConnectorPoolMembers(current []sqlc.K8sConnectorPoolMember, desired []ConnectorPoolMemberConfiguration) bool {
	if len(current) != len(desired) {
		return false
	}
	desiredByID := make(map[uuid.UUID]int32, len(desired))
	for _, member := range desired {
		desiredByID[member.NodeID] = member.AdminPriority
	}
	for _, member := range current {
		if priority, ok := desiredByID[member.NodeID]; !ok || priority != member.AdminPriority {
			return false
		}
	}
	return true
}
