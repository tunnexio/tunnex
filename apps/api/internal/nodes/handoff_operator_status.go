package nodes

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// ErrHandoffOperatorStatusUnavailable deliberately has no wrapped database,
// policy, or P2 error. A future API/UI can expose only status reason codes,
// rather than returning dependency details through this projection.
var ErrHandoffOperatorStatusUnavailable = errors.New("handoff operator status unavailable")

// HandoffOperatorState is a control-plane operator view. In particular,
// LeaderIdle is not a readiness, traffic-serving, failover, or application-HA
// claim; it says only that this CP process has confirmed leadership and sees
// no current nonterminal durable operation for the pool.
type HandoffOperatorState string

const (
	HandoffOperatorDisabled        HandoffOperatorState = "disabled"
	HandoffOperatorBlocked         HandoffOperatorState = "blocked"
	HandoffOperatorFollower        HandoffOperatorState = "follower"
	HandoffOperatorLeaderIdle      HandoffOperatorState = "leader_idle"
	HandoffOperatorLeaderOperating HandoffOperatorState = "leader_operating"
	HandoffOperatorDegraded        HandoffOperatorState = "degraded"
)

// HandoffOperatorReason is finite and server-derived. It intentionally omits
// node, operation, artifact, P2, connection-string, and raw-error identities.
type HandoffOperatorReason string

const (
	HandoffOperatorActivationDisabled           HandoffOperatorReason = "activation_disabled"
	HandoffOperatorActivationBlocked            HandoffOperatorReason = "activation_blocked"
	HandoffOperatorActivationPoolMissing        HandoffOperatorReason = "activation_postgres_pool_missing"
	HandoffOperatorActivationElectorMissing     HandoffOperatorReason = "activation_leader_elector_missing"
	HandoffOperatorActivationObserverMissing    HandoffOperatorReason = "activation_health_observer_missing"
	HandoffOperatorActivationObserverInvalid    HandoffOperatorReason = "activation_health_observer_invalid"
	HandoffOperatorActivationMigrationInvalid   HandoffOperatorReason = "activation_migration_state_invalid"
	HandoffOperatorActivationSourceMissing      HandoffOperatorReason = "activation_tick_source_missing"
	HandoffOperatorActivationSourceInvalid      HandoffOperatorReason = "activation_tick_source_invalid"
	HandoffOperatorActivationIssuerMissing      HandoffOperatorReason = "activation_p2_issuer_missing"
	HandoffOperatorActivationReaderMissing      HandoffOperatorReason = "activation_p2_attestation_reader_missing"
	HandoffOperatorActivationServiceMissing     HandoffOperatorReason = "activation_coordinator_service_missing"
	HandoffOperatorActivationServiceInvalid     HandoffOperatorReason = "activation_coordinator_service_invalid"
	HandoffOperatorActivationTimingInvalid      HandoffOperatorReason = "activation_timing_invalid"
	HandoffOperatorActivationConstructionFailed HandoffOperatorReason = "activation_construction_failed"
	HandoffOperatorActivationUnknown            HandoffOperatorReason = "activation_state_unknown"
	HandoffOperatorLeadershipUnknown            HandoffOperatorReason = "leadership_unknown"
	HandoffOperatorHealthHistoryMissing         HandoffOperatorReason = "health_history_missing"
	HandoffOperatorHealthHistoryAmbiguous       HandoffOperatorReason = "health_history_ambiguous"
	HandoffOperatorHealthSnapshotMismatch       HandoffOperatorReason = "health_snapshot_mismatch"
	HandoffOperatorHealthObservationMissing     HandoffOperatorReason = "health_observation_missing"
	HandoffOperatorHealthObservationInvalid     HandoffOperatorReason = "health_observation_time_invalid"
	HandoffOperatorHealthObservationStale       HandoffOperatorReason = "health_observation_stale"
	HandoffOperatorMemberHealthUnknown          HandoffOperatorReason = "member_health_unknown"
	HandoffOperatorMemberHealthUnhealthy        HandoffOperatorReason = "member_health_unhealthy"
)

// HandoffOperatorLeadership must come from a current leader-fence
// confirmation. IsLeader alone is intentionally insufficient because it is a
// stale local pre-filter, not authority for an operator status claim.
type HandoffOperatorLeadership struct {
	Confirmed bool
	Leader    bool
}

// handoffOperatorHealthHistory is the minimal durable state needed for an
// operator view. MembershipEpoch is not a count of healthy members. It names
// the membership incarnation under which LastObservationAt was accepted.
type handoffOperatorHealthHistory struct {
	OrgID                uuid.UUID
	SiteID               uuid.UUID
	ClusterID            uuid.UUID
	PoolID               uuid.UUID
	MembershipEpoch      uint64
	ObservedActiveNodeID uuid.UUID
	ObservedGeneration   uint64
	LastObservationAt    time.Time
}

// HandoffOperatorStatus contains no node, operation, artifact, lease, P2, or
// raw-error identity. MembershipEpochKnown distinguishes a valid zero epoch
// from absent health history. OperationPhase is present only for one durable
// nonterminal operation and does not imply it is progressing.
type HandoffOperatorStatus struct {
	PoolID               uuid.UUID
	ClusterID            uuid.UUID
	Generation           uint64
	MembershipEpochKnown bool
	MembershipEpoch      uint64
	State                HandoffOperatorState
	Reasons              []HandoffOperatorReason
	OperationPhase       *k8s.HandoffPhase
}

type HandoffOperatorStatusProjectionConfig struct {
	ReportFreshness      time.Duration
	ObservationFreshness time.Duration
}

func (c HandoffOperatorStatusProjectionConfig) valid() bool {
	return c.ReportFreshness > 0 && c.ObservationFreshness > 0
}

// PostgresHandoffOperatorStatusProjection composes the existing explicit
// pool-bound status reader with durable 0083 state. It is read-only: no
// scheduler, leader campaign, health observation, operation, or pool mutation
// occurs while producing this view.
type PostgresHandoffOperatorStatusProjection struct {
	pool   *pgxpool.Pool
	pools  *PostgresConnectorPoolStatusProjection
	config HandoffOperatorStatusProjectionConfig
}

func NewPostgresHandoffOperatorStatusProjection(pool *pgxpool.Pool, policy HandoffPolicyAcknowledgementSource, config HandoffOperatorStatusProjectionConfig) *PostgresHandoffOperatorStatusProjection {
	return &PostgresHandoffOperatorStatusProjection{
		pool:   pool,
		pools:  NewPostgresConnectorPoolStatusProjection(pool, policy, ConnectorPoolStatusProjectionConfig{ReportFreshness: config.ReportFreshness}),
		config: config,
	}
}

// HandoffOperatorStatuses returns one status per valid, explicitly bound pool
// in orgID. A missing, cleared-after-churn, stale, or mismatched health row is
// a degraded status, never a fabricated healthy/ready result. Query errors
// return no partial result.
func (s *PostgresHandoffOperatorStatusProjection) HandoffOperatorStatuses(ctx context.Context, orgID uuid.UUID, now time.Time, activation HandoffSchedulerFeatureStatus, leadership HandoffOperatorLeadership) ([]HandoffOperatorStatus, error) {
	if s == nil || s.pool == nil || s.pools == nil || !s.config.valid() || orgID == uuid.Nil || now.IsZero() {
		return nil, ErrHandoffOperatorStatusUnavailable
	}
	pools, err := s.pools.ConnectorPoolStatuses(ctx, orgID, now)
	if err != nil {
		return nil, ErrHandoffOperatorStatusUnavailable
	}
	rows, err := sqlc.New(s.pool).ListK8sConnectorPoolHealthStatesForOperatorStatus(ctx, orgID)
	if err != nil {
		return nil, ErrHandoffOperatorStatusUnavailable
	}
	history := make([]handoffOperatorHealthHistory, 0, len(rows))
	for _, row := range rows {
		if row.MembershipEpoch < 0 || row.ObservedGeneration <= 0 {
			// Retain an invalid record's scope to make the matching pool degrade;
			// the pure projector treats its zero observation as unusable.
			history = append(history, handoffOperatorHealthHistory{OrgID: row.OrgID, SiteID: row.SiteID, ClusterID: row.ClusterID, PoolID: row.PoolID})
			continue
		}
		at := time.Time{}
		if row.LastObservationAt.Valid {
			at = row.LastObservationAt.Time.UTC()
		}
		history = append(history, handoffOperatorHealthHistory{OrgID: row.OrgID, SiteID: row.SiteID, ClusterID: row.ClusterID, PoolID: row.PoolID, MembershipEpoch: uint64(row.MembershipEpoch), ObservedActiveNodeID: row.ObservedActiveNodeID, ObservedGeneration: uint64(row.ObservedGeneration), LastObservationAt: at})
	}
	return projectHandoffOperatorStatuses(orgID, now, s.config.ObservationFreshness, pools, history, activation, leadership), nil
}

// projectHandoffOperatorStatuses is pure so status semantics can be tested
// without a database, leader process, transport, or P2 implementation.
func projectHandoffOperatorStatuses(orgID uuid.UUID, now time.Time, observationFreshness time.Duration, pools []ConnectorPoolStatus, history []handoffOperatorHealthHistory, activation HandoffSchedulerFeatureStatus, leadership HandoffOperatorLeadership) []HandoffOperatorStatus {
	if orgID == uuid.Nil || now.IsZero() || observationFreshness <= 0 {
		return nil
	}
	byPool := make(map[uuid.UUID]handoffOperatorHealthHistory, len(history))
	ambiguous := make(map[uuid.UUID]bool)
	for _, item := range history {
		if item.PoolID == uuid.Nil {
			continue
		}
		if _, exists := byPool[item.PoolID]; exists {
			ambiguous[item.PoolID] = true
			continue
		}
		byPool[item.PoolID] = item
	}
	statuses := make([]HandoffOperatorStatus, 0, len(pools))
	for _, pool := range pools {
		if pool.PoolID == uuid.Nil || pool.ClusterID == uuid.Nil || pool.Generation == 0 {
			continue
		}
		status := HandoffOperatorStatus{PoolID: pool.PoolID, ClusterID: pool.ClusterID, Generation: pool.Generation}
		if pool.Handoff != nil && nonterminalHandoffPhase(pool.Handoff.Phase) {
			phase := pool.Handoff.Phase
			status.OperationPhase = &phase
		}
		if item, found := byPool[pool.PoolID]; found && !ambiguous[pool.PoolID] && item.OrgID == orgID && item.ClusterID == pool.ClusterID && item.PoolID == pool.PoolID && item.SiteID != uuid.Nil {
			status.MembershipEpochKnown, status.MembershipEpoch = true, item.MembershipEpoch
		}

		switch activation.State {
		case HandoffSchedulerDisabled:
			status.State, status.Reasons = HandoffOperatorDisabled, []HandoffOperatorReason{HandoffOperatorActivationDisabled}
		case HandoffSchedulerBlocked:
			status.State, status.Reasons = HandoffOperatorBlocked, operatorActivationReasons(activation)
		default:
			reasons := operatorHealthReasons(orgID, now, observationFreshness, pool, byPool[pool.PoolID], ambiguous[pool.PoolID], byPool)
			if len(reasons) != 0 {
				status.State, status.Reasons = HandoffOperatorDegraded, reasons
			} else if activation.State != HandoffSchedulerReady {
				status.State, status.Reasons = HandoffOperatorDegraded, []HandoffOperatorReason{HandoffOperatorActivationUnknown}
			} else if !leadership.Confirmed {
				status.State, status.Reasons = HandoffOperatorDegraded, []HandoffOperatorReason{HandoffOperatorLeadershipUnknown}
			} else if !leadership.Leader {
				status.State = HandoffOperatorFollower
			} else if status.OperationPhase != nil {
				status.State = HandoffOperatorLeaderOperating
			} else {
				status.State = HandoffOperatorLeaderIdle
			}
		}
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool {
		if statuses[i].ClusterID != statuses[j].ClusterID {
			return statuses[i].ClusterID.String() < statuses[j].ClusterID.String()
		}
		return statuses[i].PoolID.String() < statuses[j].PoolID.String()
	})
	return statuses
}

func operatorHealthReasons(orgID uuid.UUID, now time.Time, freshness time.Duration, pool ConnectorPoolStatus, history handoffOperatorHealthHistory, ambiguous bool, all map[uuid.UUID]handoffOperatorHealthHistory) []HandoffOperatorReason {
	reasons := make([]HandoffOperatorReason, 0, 4)
	_, found := all[pool.PoolID]
	if !found {
		reasons = append(reasons, HandoffOperatorHealthHistoryMissing)
	} else if ambiguous {
		reasons = append(reasons, HandoffOperatorHealthHistoryAmbiguous)
	} else if history.OrgID != orgID || history.ClusterID != pool.ClusterID || history.PoolID != pool.PoolID || history.SiteID == uuid.Nil || history.ObservedActiveNodeID != pool.ActiveNodeID || history.ObservedGeneration != pool.Generation {
		reasons = append(reasons, HandoffOperatorHealthSnapshotMismatch)
	} else if history.LastObservationAt.IsZero() {
		reasons = append(reasons, HandoffOperatorHealthObservationMissing)
	} else if history.LastObservationAt.After(now) {
		reasons = append(reasons, HandoffOperatorHealthObservationInvalid)
	} else if now.Sub(history.LastObservationAt) >= freshness {
		reasons = append(reasons, HandoffOperatorHealthObservationStale)
	}
	if anyMemberHealthUnknown(pool.Members) {
		reasons = append(reasons, HandoffOperatorMemberHealthUnknown)
	}
	if anyMemberHealthUnhealthy(pool.Members) {
		reasons = append(reasons, HandoffOperatorMemberHealthUnhealthy)
	}
	return uniqueOperatorReasons(reasons)
}

func anyMemberHealthUnknown(members []ConnectorPoolMemberStatus) bool {
	if len(members) == 0 {
		return true
	}
	for _, member := range members {
		if !member.Health.Known {
			return true
		}
	}
	return false
}

func anyMemberHealthUnhealthy(members []ConnectorPoolMemberStatus) bool {
	for _, member := range members {
		if member.Health.Known && !member.Health.Healthy {
			return true
		}
	}
	return false
}

func operatorActivationReasons(status HandoffSchedulerFeatureStatus) []HandoffOperatorReason {
	reasons := make([]HandoffOperatorReason, 0, len(status.Reasons))
	for _, reason := range status.Reasons {
		switch reason {
		case HandoffSchedulerPostgresPoolMissing:
			reasons = append(reasons, HandoffOperatorActivationPoolMissing)
		case HandoffSchedulerLeaderElectorMissing:
			reasons = append(reasons, HandoffOperatorActivationElectorMissing)
		case HandoffSchedulerHealthObserverMissing:
			reasons = append(reasons, HandoffOperatorActivationObserverMissing)
		case HandoffSchedulerHealthObserverInvalid:
			reasons = append(reasons, HandoffOperatorActivationObserverInvalid)
		case HandoffSchedulerMigrationStateInvalid:
			reasons = append(reasons, HandoffOperatorActivationMigrationInvalid)
		case HandoffSchedulerTickSourceMissing:
			reasons = append(reasons, HandoffOperatorActivationSourceMissing)
		case HandoffSchedulerTickSourceInvalid:
			reasons = append(reasons, HandoffOperatorActivationSourceInvalid)
		case HandoffSchedulerP2IssuerMissing:
			reasons = append(reasons, HandoffOperatorActivationIssuerMissing)
		case HandoffSchedulerP2AttestationReaderMissing:
			reasons = append(reasons, HandoffOperatorActivationReaderMissing)
		case HandoffSchedulerCoordinatorServiceMissing:
			reasons = append(reasons, HandoffOperatorActivationServiceMissing)
		case HandoffSchedulerCoordinatorServiceInvalid:
			reasons = append(reasons, HandoffOperatorActivationServiceInvalid)
		case HandoffSchedulerTimingInvalid:
			reasons = append(reasons, HandoffOperatorActivationTimingInvalid)
		case HandoffSchedulerConstructionFailed:
			reasons = append(reasons, HandoffOperatorActivationConstructionFailed)
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, HandoffOperatorActivationBlocked)
	}
	return uniqueOperatorReasons(reasons)
}

func uniqueOperatorReasons(in []HandoffOperatorReason) []HandoffOperatorReason {
	seen := make(map[HandoffOperatorReason]bool, len(in))
	out := make([]HandoffOperatorReason, 0, len(in))
	for _, reason := range in {
		if reason != "" && !seen[reason] {
			seen[reason] = true
			out = append(out, reason)
		}
	}
	return out
}
