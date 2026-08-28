package nodes

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// ConnectorPoolHealthReason explains the control-plane evidence state for one
// pool member. It is intentionally not a readiness, failover, or application
// HA claim: the current CP evidence cannot establish those facts.
type ConnectorPoolHealthReason string

const (
	ConnectorPoolHealthHealthy                   ConnectorPoolHealthReason = "healthy"
	ConnectorPoolHealthUnknownScope              ConnectorPoolHealthReason = "scope_unknown"
	ConnectorPoolHealthUnknownHeartbeat          ConnectorPoolHealthReason = "heartbeat_unknown"
	ConnectorPoolHealthUnknownPolicyReport       ConnectorPoolHealthReason = "policy_report_unknown"
	ConnectorPoolHealthUnknownEndpointView       ConnectorPoolHealthReason = "endpoint_view_unknown"
	ConnectorPoolHealthUnknownPolicyAcknowledged ConnectorPoolHealthReason = "policy_acknowledgement_unknown"
	ConnectorPoolHealthInvalidEvidenceTime       ConnectorPoolHealthReason = "evidence_time_invalid"
	ConnectorPoolHealthStaleHeartbeat            ConnectorPoolHealthReason = "heartbeat_stale"
	ConnectorPoolHealthStalePolicyReport         ConnectorPoolHealthReason = "policy_report_stale"
	ConnectorPoolHealthRevoked                   ConnectorPoolHealthReason = "node_revoked"
	ConnectorPoolHealthInactive                  ConnectorPoolHealthReason = "node_inactive"
	ConnectorPoolHealthWGKeyNotReady             ConnectorPoolHealthReason = "wireguard_key_not_ready"
	ConnectorPoolHealthEndpointNotReady          ConnectorPoolHealthReason = "endpoint_not_ready"
	ConnectorPoolHealthPolicyNotAcknowledged     ConnectorPoolHealthReason = "policy_not_acknowledged"
	ConnectorPoolHealthEndpointViewDegraded      ConnectorPoolHealthReason = "endpoint_view_degraded"
)

// ConnectorPoolMemberHealth is a point-in-time CP evidence projection. Known
// is false when the CP lacks a required observation; Healthy is then always
// false. A known unhealthy member has a concrete, server-derived reason.
type ConnectorPoolMemberHealth struct {
	Known   bool
	Healthy bool
	Reason  ConnectorPoolHealthReason
}

// ConnectorPoolMemberStatus contains only configured pool membership and its
// current server-known health evidence. It carries no artefact, lease, or
// traffic-serving authority.
type ConnectorPoolMemberStatus struct {
	NodeID        uuid.UUID
	AdminPriority int32
	Health        ConnectorPoolMemberHealth
}

// ConnectorPoolHandoffStatus is durable operation progress when exactly one
// nonterminal 0082 operation is present. It is informational only and does
// not imply that failover is enabled or an action is scheduled.
type ConnectorPoolHandoffStatus struct {
	OperationID uuid.UUID
	Phase       k8s.HandoffPhase
}

// ConnectorPoolStatus is the narrow future API/UI read projection for an
// explicitly pool-bound cluster. It deliberately omits readiness counts,
// failover estimates, artifact identity, lease state, policy/VIP details, and
// any claim that the application is highly available.
type ConnectorPoolStatus struct {
	PoolID          uuid.UUID
	ClusterID       uuid.UUID
	PreferredNodeID uuid.UUID
	ActiveNodeID    uuid.UUID
	Generation      uint64
	Members         []ConnectorPoolMemberStatus
	Handoff         *ConnectorPoolHandoffStatus
}

type ConnectorPoolStatusProjectionConfig struct {
	ReportFreshness time.Duration
}

func (c ConnectorPoolStatusProjectionConfig) valid() bool { return c.ReportFreshness > 0 }

// PostgresConnectorPoolStatusProjection reads the existing 0079 pool and
// 0082 handoff-operation records. It has no mutation path, scheduler hook, or
// transport dependency. Policy acknowledgement comparison remains injected
// because an agent-reported hash alone cannot establish acknowledgement.
type PostgresConnectorPoolStatusProjection struct {
	pool   *pgxpool.Pool
	policy HandoffPolicyAcknowledgementSource
	config ConnectorPoolStatusProjectionConfig
}

func NewPostgresConnectorPoolStatusProjection(pool *pgxpool.Pool, policy HandoffPolicyAcknowledgementSource, config ConnectorPoolStatusProjectionConfig) *PostgresConnectorPoolStatusProjection {
	return &PostgresConnectorPoolStatusProjection{pool: pool, policy: policy, config: config}
}

// ConnectorPoolStatuses returns only pools explicitly bound to clusters in
// orgID. Missing or stale evidence is represented per member rather than
// inferred as readiness. A malformed pool snapshot is omitted fail-closed;
// query/provider errors return no partial result.
func (s *PostgresConnectorPoolStatusProjection) ConnectorPoolStatuses(ctx context.Context, orgID uuid.UUID, now time.Time) ([]ConnectorPoolStatus, error) {
	if s == nil || s.pool == nil || !s.config.valid() || orgID == uuid.Nil || now.IsZero() {
		return nil, errors.New("connector pool status projection prerequisites are incomplete")
	}
	rows, err := sqlc.New(s.pool).ListK8sConnectorPoolStatusMembersForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	pools := statusPoolsFromRows(orgID, rows)
	statuses := make([]ConnectorPoolStatus, 0, len(pools))
	for _, pool := range pools {
		if pool.invalid || !pool.valid() {
			continue
		}
		memberIDs := make([]uuid.UUID, 0, len(pool.members))
		for _, member := range pool.members {
			memberIDs = append(memberIDs, member.id)
		}
		acks := map[uuid.UUID]k8s.PolicyAcknowledgement{}
		if s.policy != nil {
			acks, err = s.policy.HandoffPolicyAcknowledgements(ctx, pool.org, pool.site, memberIDs)
			if err != nil {
				return nil, err
			}
		}
		status, ok := projectConnectorPoolStatus(now, s.config.ReportFreshness, pool, acks)
		if ok {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
}

type connectorPoolStatusSnapshot struct {
	id, org, site, cluster, preferred, active uuid.UUID
	generation                                int64
	members                                   []connectorPoolStatusMemberSnapshot
	handoff                                   *ConnectorPoolHandoffStatus
	invalid                                   bool
}

type connectorPoolStatusMemberSnapshot struct {
	id       uuid.UUID
	priority int32
	node     sqlc.Node
}

func statusPoolsFromRows(orgID uuid.UUID, rows []sqlc.ListK8sConnectorPoolStatusMembersForOrgRow) []connectorPoolStatusSnapshot {
	byID := make(map[uuid.UUID]*connectorPoolStatusSnapshot)
	order := make([]uuid.UUID, 0)
	for _, row := range rows {
		pool := byID[row.PoolID]
		if pool == nil {
			pool = &connectorPoolStatusSnapshot{id: row.PoolID, org: row.OrgID, site: row.SiteID, cluster: row.ClusterID, preferred: row.PreferredNodeID, active: row.ActiveNodeID, generation: row.Generation}
			byID[row.PoolID] = pool
			order = append(order, row.PoolID)
		} else if pool.org != row.OrgID || pool.site != row.SiteID || pool.cluster != row.ClusterID || pool.preferred != row.PreferredNodeID || pool.active != row.ActiveNodeID || pool.generation != row.Generation {
			pool.invalid = true
		}
		if row.OrgID != orgID {
			pool.invalid = true
		}
		if row.OperationID == uuid.Nil {
			if row.OperationPhase != "" {
				pool.invalid = true
			}
		} else {
			handoff := &ConnectorPoolHandoffStatus{OperationID: row.OperationID, Phase: k8s.HandoffPhase(row.OperationPhase)}
			if !nonterminalHandoffPhase(handoff.Phase) || (pool.handoff != nil && *pool.handoff != *handoff) {
				pool.invalid = true
			} else {
				pool.handoff = handoff
			}
		}
		pool.members = append(pool.members, connectorPoolStatusMemberSnapshot{id: row.NodeID, priority: row.AdminPriority, node: statusNode(row)})
	}
	result := make([]connectorPoolStatusSnapshot, 0, len(order))
	for _, id := range order {
		result = append(result, *byID[id])
	}
	return result
}

func statusNode(row sqlc.ListK8sConnectorPoolStatusMembersForOrgRow) sqlc.Node {
	return sqlc.Node{ID: row.NodeID, OrgID: row.OrgID, SiteID: pgtype.UUID{Bytes: row.SiteID, Valid: true}, Status: row.NodeStatus,
		RevokedAt: row.NodeRevokedAt, WgPublicKey: row.NodeWgPublicKey, Endpoint: row.NodeEndpoint,
		LastSeenAt: row.NodeLastSeenAt, PolicyReportedAt: row.NodePolicyReportedAt, Capabilities: row.NodeCapabilities}
}

func (p connectorPoolStatusSnapshot) valid() bool {
	if p.id == uuid.Nil || p.org == uuid.Nil || p.site == uuid.Nil || p.cluster == uuid.Nil || p.preferred == uuid.Nil || p.active == uuid.Nil || p.generation <= 0 || len(p.members) == 0 {
		return false
	}
	if p.handoff != nil && (p.handoff.OperationID == uuid.Nil || !nonterminalHandoffPhase(p.handoff.Phase)) {
		return false
	}
	seen := make(map[uuid.UUID]bool, len(p.members))
	for _, member := range p.members {
		if member.id == uuid.Nil || seen[member.id] || member.node.ID != member.id || member.node.OrgID != p.org || !member.node.SiteID.Valid || uuid.UUID(member.node.SiteID.Bytes) != p.site {
			return false
		}
		seen[member.id] = true
	}
	return seen[p.preferred] && seen[p.active]
}

func projectConnectorPoolStatus(now time.Time, freshness time.Duration, pool connectorPoolStatusSnapshot, acks map[uuid.UUID]k8s.PolicyAcknowledgement) (ConnectorPoolStatus, bool) {
	if !pool.valid() || freshness <= 0 || now.IsZero() {
		return ConnectorPoolStatus{}, false
	}
	status := ConnectorPoolStatus{PoolID: pool.id, ClusterID: pool.cluster, PreferredNodeID: pool.preferred, ActiveNodeID: pool.active, Generation: uint64(pool.generation)}
	if pool.handoff != nil {
		handoff := *pool.handoff
		status.Handoff = &handoff
	}
	status.Members = make([]ConnectorPoolMemberStatus, 0, len(pool.members))
	for _, member := range pool.members {
		evidence := ConnectorEvidenceFromNode(member.node, acks[member.id])
		_, health := k8s.AdaptConnectorEvidence(now, freshness, pool.org.String(), pool.site.String(), evidence)
		status.Members = append(status.Members, ConnectorPoolMemberStatus{NodeID: member.id, AdminPriority: member.priority, Health: connectorPoolMemberHealth(now, freshness, evidence, health)})
	}
	sort.Slice(status.Members, func(i, j int) bool {
		if status.Members[i].AdminPriority != status.Members[j].AdminPriority {
			return status.Members[i].AdminPriority > status.Members[j].AdminPriority
		}
		return status.Members[i].NodeID.String() < status.Members[j].NodeID.String()
	})
	return status, true
}

func connectorPoolMemberHealth(now time.Time, freshness time.Duration, evidence k8s.ConnectorEvidence, health k8s.ConnectorHealth) ConnectorPoolMemberHealth {
	if evidence.ID == "" || evidence.OrgID == "" || evidence.SiteID == "" {
		return unknownConnectorPoolHealth(ConnectorPoolHealthUnknownScope)
	}
	if evidence.LastSeenAt.IsZero() {
		return unknownConnectorPoolHealth(ConnectorPoolHealthUnknownHeartbeat)
	}
	if evidence.PolicyReportedAt.IsZero() {
		return unknownConnectorPoolHealth(ConnectorPoolHealthUnknownPolicyReport)
	}
	if !evidence.K8sEndpointViewKnown {
		return unknownConnectorPoolHealth(ConnectorPoolHealthUnknownEndpointView)
	}
	if !evidence.Policy.ExpectedKnown || evidence.Policy.ExpectedHash == "" || !evidence.Policy.HealthKnown || evidence.AppliedPolicyHash == "" {
		return unknownConnectorPoolHealth(ConnectorPoolHealthUnknownPolicyAcknowledged)
	}
	if evidence.LastSeenAt.After(now) || evidence.PolicyReportedAt.After(now) {
		return unknownConnectorPoolHealth(ConnectorPoolHealthInvalidEvidenceTime)
	}
	if !statusEvidenceFresh(now, evidence.LastSeenAt, freshness) {
		return unhealthyConnectorPoolHealth(ConnectorPoolHealthStaleHeartbeat)
	}
	if !statusEvidenceFresh(now, evidence.PolicyReportedAt, freshness) {
		return unhealthyConnectorPoolHealth(ConnectorPoolHealthStalePolicyReport)
	}
	if evidence.Revoked {
		return unhealthyConnectorPoolHealth(ConnectorPoolHealthRevoked)
	}
	if evidence.Status != "active" {
		return unhealthyConnectorPoolHealth(ConnectorPoolHealthInactive)
	}
	if !evidence.WGPublicKeyReady {
		return unhealthyConnectorPoolHealth(ConnectorPoolHealthWGKeyNotReady)
	}
	if !evidence.EndpointReady {
		return unhealthyConnectorPoolHealth(ConnectorPoolHealthEndpointNotReady)
	}
	if evidence.AppliedPolicyError != "" || evidence.AppliedPolicyRefusal != 0 || evidence.Policy.Degraded || evidence.AppliedPolicyHash != evidence.Policy.ExpectedHash {
		return unhealthyConnectorPoolHealth(ConnectorPoolHealthPolicyNotAcknowledged)
	}
	if evidence.K8sEndpointsUnavailable {
		return unhealthyConnectorPoolHealth(ConnectorPoolHealthEndpointViewDegraded)
	}
	if health.Healthy() {
		return ConnectorPoolMemberHealth{Known: true, Healthy: true, Reason: ConnectorPoolHealthHealthy}
	}
	return unknownConnectorPoolHealth(ConnectorPoolHealthUnknownPolicyAcknowledged)
}

func statusEvidenceFresh(now, observed time.Time, freshness time.Duration) bool {
	return freshness > 0 && !observed.IsZero() && !observed.After(now) && now.Sub(observed) < freshness
}

func unknownConnectorPoolHealth(reason ConnectorPoolHealthReason) ConnectorPoolMemberHealth {
	return ConnectorPoolMemberHealth{Reason: reason}
}

func unhealthyConnectorPoolHealth(reason ConnectorPoolHealthReason) ConnectorPoolMemberHealth {
	return ConnectorPoolMemberHealth{Known: true, Reason: reason}
}

func nonterminalHandoffPhase(phase k8s.HandoffPhase) bool {
	switch phase {
	case k8s.HandoffPrepareCandidate, k8s.HandoffAwaitPreparedAck, k8s.HandoffAwaitWithdrawal, k8s.HandoffCASActive, k8s.HandoffEnableServing, k8s.HandoffAwaitServingAck, k8s.HandoffFinalize:
		return true
	default:
		return false
	}
}
