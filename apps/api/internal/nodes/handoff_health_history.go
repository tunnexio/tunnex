package nodes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// ErrHandoffHealthObservationStale means a different observation attempted to
// overwrite an already accepted CP receipt time. It is intentionally not a
// retry signal: callers must obtain a newer CP-recorded report snapshot.
var ErrHandoffHealthObservationStale = errors.New("connector pool health observation is stale or out of order")

// ErrHandoffHealthLeaderSessionUnavailable means a fresh durable observation
// could not prove the exact advisory-lock session that authorized it. It is a
// fail-closed source error, never a reason to fall back to the pool writer.
var ErrHandoffHealthLeaderSessionUnavailable = errors.New("connector pool health observation leader session is unavailable")

// HandoffHealthObservation is the one persisted CP-owned health tick. It is
// an eligibility snapshot only, never a handoff plan or authorization.
type HandoffHealthObservation struct {
	State      k8s.HandoffHealthState
	Decision   k8s.Decision
	Evidence   map[uuid.UUID]k8s.ConnectorEvidence
	Health     map[string]k8s.ConnectorHealth
	Ordered    []uuid.UUID
	ActiveID   uuid.UUID
	Generation int64
	// MembershipEpoch is the durable membership incarnation read while the
	// pool observation lock is held. It is CP state, not an agent claim.
	MembershipEpoch int64
}

// HandoffHealthObserver is the narrow write seam consumed by the unregistered
// PostgreSQL tick source. The input time gates health freshness; identity and
// ordering derive from locked CP rows, never from that clock alone.
type HandoffHealthObserver interface {
	ObserveHandoffHealth(context.Context, k8s.HandoffPoolScope, time.Time) (HandoffHealthObservation, bool, error)
}

// HandoffLeaderBoundHealthObserver writes a fresh observation only through
// the scheduler's exact lock-holding PostgreSQL connection. The epoch is
// CP-issued advisory-lock provenance, not agent input.
type HandoffLeaderBoundHealthObserver interface {
	ObserveHandoffHealthWithLeadership(context.Context, k8s.HandoffPoolScope, time.Time, k8s.HandoffLeadershipEpoch, *pgxpool.Conn) (HandoffHealthObservation, bool, error)
}

// PostgresHandoffHealthHistory owns durable hysteresis state. It does not
// create a handoff operation, call transport, mutate pool ownership, or start
// a scheduler.
type PostgresHandoffHealthHistory struct {
	pool      *pgxpool.Pool
	policy    HandoffPolicyAcknowledgementSource
	freshness time.Duration
}

func NewPostgresHandoffHealthHistory(pool *pgxpool.Pool, policy HandoffPolicyAcknowledgementSource, freshness time.Duration) *PostgresHandoffHealthHistory {
	return &PostgresHandoffHealthHistory{pool: pool, policy: policy, freshness: freshness}
}

var _ HandoffHealthHistory = (*PostgresHandoffHealthHistory)(nil)
var _ HandoffHealthObserver = (*PostgresHandoffHealthHistory)(nil)
var _ HandoffLeaderBoundHealthObserver = (*PostgresHandoffHealthHistory)(nil)

// handoffSchedulerActivationReady is structural only: activation must not
// probe a database or agent as a side effect. The first elected tick performs
// the normal CP reads under its bounded context.
func (h *PostgresHandoffHealthHistory) handoffSchedulerActivationReady(pool *pgxpool.Pool) bool {
	return h != nil && pool != nil && h.pool == pool && h.freshness > 0 && handoffActivationDependencyPresent(h.policy)
}

func (h *PostgresHandoffHealthHistory) HandoffHealthState(ctx context.Context, scope k8s.HandoffPoolScope) (k8s.HandoffHealthState, bool, error) {
	if h == nil || h.pool == nil || !scopeValid(scope) {
		return k8s.HandoffHealthState{}, false, errors.New("connector pool health history prerequisites are incomplete")
	}
	state, err := sqlc.New(h.pool).GetK8sConnectorPoolHealthState(ctx, healthScopeParams(scope))
	if errors.Is(err, pgx.ErrNoRows) {
		return k8s.HandoffHealthState{}, false, nil
	}
	if err != nil {
		return k8s.HandoffHealthState{}, false, err
	}
	ticks, err := sqlc.New(h.pool).ListK8sConnectorPoolHealthCandidateTicks(ctx, healthTicksParams(state, scope))
	if err != nil {
		return k8s.HandoffHealthState{}, false, err
	}
	return healthStateFromRows(state, ticks), true, nil
}

func (h *PostgresHandoffHealthHistory) ObserveHandoffHealth(ctx context.Context, scope k8s.HandoffPoolScope, now time.Time) (result HandoffHealthObservation, available bool, err error) {
	if h == nil || h.pool == nil {
		return result, false, errors.New("connector pool health observer prerequisites are incomplete")
	}
	return h.observeHandoffHealth(ctx, scope, now, h.pool.BeginTx, nil)
}

// ObserveHandoffHealthWithLeadership is the only observation path used by
// PostgresHandoffTickSource for fresh handoff intent. It starts its state
// transaction on the exact advisory-lock session and proves that session still
// holds the expected lock inside the transaction before it reads or writes
// health state.
func (h *PostgresHandoffHealthHistory) ObserveHandoffHealthWithLeadership(ctx context.Context, scope k8s.HandoffPoolScope, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (result HandoffHealthObservation, available bool, err error) {
	if conn == nil || epoch.BackendPID <= 0 || epoch.LockKey == 0 {
		return result, false, ErrHandoffHealthLeaderSessionUnavailable
	}
	return h.observeHandoffHealth(ctx, scope, now, conn.BeginTx, &epoch)
}

func (h *PostgresHandoffHealthHistory) observeHandoffHealth(ctx context.Context, scope k8s.HandoffPoolScope, now time.Time, begin func(context.Context, pgx.TxOptions) (pgx.Tx, error), epoch *k8s.HandoffLeadershipEpoch) (result HandoffHealthObservation, available bool, err error) {
	if h == nil || h.pool == nil || h.freshness <= 0 || !scopeValid(scope) || now.IsZero() {
		return result, false, errors.New("connector pool health observer prerequisites are incomplete")
	}
	// The exact pool row is locked before any state read/write below, so it is
	// the serialization point. Read committed avoids turning a legitimate
	// duplicate observer race into a transaction-aborted error after the
	// idempotent state-row insert.
	tx, err := begin(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if epoch != nil {
		if err := handoffLeaderSessionHeld(ctx, tx, *epoch); err != nil {
			return result, false, err
		}
	}
	q := sqlc.New(tx)
	pool, err := q.GetK8sConnectorPoolForPromotion(ctx, sqlc.GetK8sConnectorPoolForPromotionParams{OrgID: scope.OrgID, SiteID: scope.SiteID, PoolID: scope.PoolID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && pool.ClusterID != scope.ClusterID {
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	rows, err := q.ListK8sConnectorPoolHealthObservationMembersForUpdate(ctx, sqlc.ListK8sConnectorPoolHealthObservationMembersForUpdateParams{PoolID: scope.PoolID, OrgID: scope.OrgID, SiteID: scope.SiteID})
	if err != nil {
		return result, false, err
	}
	observation, at, key, ok, err := h.lockedObservation(ctx, scope, pool, rows, now)
	if err != nil || !ok {
		return observation, false, err
	}
	if _, err := q.CreateK8sConnectorPoolHealthState(ctx, sqlc.CreateK8sConnectorPoolHealthStateParams{OrgID: scope.OrgID, SiteID: scope.SiteID, ClusterID: scope.ClusterID, PoolID: scope.PoolID}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, false, err
	}
	state, err := q.GetK8sConnectorPoolHealthStateForUpdate(ctx, sqlc.GetK8sConnectorPoolHealthStateForUpdateParams{OrgID: scope.OrgID, SiteID: scope.SiteID, ClusterID: scope.ClusterID, PoolID: scope.PoolID})
	if err != nil {
		return result, false, err
	}
	stateChanged := state.ObservedActiveNodeID != pool.ActiveNodeID || state.ObservedGeneration != pool.Generation
	if !stateChanged && state.LastObservationKey != nil && *state.LastObservationKey == key {
		ticks, err := q.ListK8sConnectorPoolHealthCandidateTicksForUpdate(ctx, healthTicksForUpdateParams(state, scope))
		if err != nil {
			return result, false, err
		}
		observation.State, observation.MembershipEpoch = healthStateFromRows(state, ticks), state.MembershipEpoch
		observation.Decision = decisionFromPersistedHealthState(state, pool)
		if epoch != nil {
			if err := handoffLeaderSessionHeld(ctx, tx, *epoch); err != nil {
				return result, false, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return result, false, err
		}
		return observation, true, nil
	}
	if !stateChanged && state.LastObservationAt.Valid && !at.After(state.LastObservationAt.Time) {
		return result, false, ErrHandoffHealthObservationStale
	}
	if stateChanged {
		if _, err := q.ResetK8sConnectorPoolHealthCandidateTicks(ctx, healthResetParams(state, scope)); err != nil {
			return result, false, err
		}
		state.StaleTicks, state.PreferredFreshTicks = 0, 0
	}
	ticks, err := q.ListK8sConnectorPoolHealthCandidateTicksForUpdate(ctx, healthTicksForUpdateParams(state, scope))
	if err != nil {
		return result, false, err
	}
	current := healthStateFromRows(state, ticks)
	model, err := poolModelFromObservation(scope, pool, rows, current)
	if err != nil {
		return result, false, nil
	}
	decision := k8s.Reconcile(model, observation.Health)
	// A threshold transition remains pending until the pool CAS moves the
	// active/generation snapshot. If plan resolution is temporarily unavailable
	// or the source restarts after observation commit, do not require three/five
	// brand-new ticks again. Retention is still fail-closed on current health.
	if decision.Transition == k8s.NoChange {
		if pending, ok := retainedHealthTransition(state, pool, observation.Health); ok {
			decision = pending
		}
	}
	next := decision.Pool
	_, err = q.UpdateK8sConnectorPoolHealthState(ctx, sqlc.UpdateK8sConnectorPoolHealthStateParams{
		ObservedActiveNodeID: pool.ActiveNodeID, ObservedGeneration: pool.Generation,
		StaleTicks: int32(next.StaleTicks), PreferredFreshTicks: int32(next.PreferredFreshTicks),
		LastTransition: string(decision.Transition), LastTransitionFromNodeID: transitionUUID(decision.Transition, decision.FromID), LastTransitionToNodeID: transitionUUID(decision.Transition, decision.ToID),
		LastObservationKey: &key, LastObservationAt: pgtype.Timestamptz{Time: at, Valid: true},
		ID: state.ID, OrgID: scope.OrgID, SiteID: scope.SiteID, ClusterID: scope.ClusterID, PoolID: scope.PoolID,
	})
	if err != nil {
		return result, false, err
	}
	for _, row := range rows {
		if row.NodeID == pool.ActiveNodeID {
			continue
		}
		count := next.CandidateHealthyTicks[row.NodeID.String()]
		if _, err := q.UpsertK8sConnectorPoolHealthCandidateTicks(ctx, sqlc.UpsertK8sConnectorPoolHealthCandidateTicksParams{StateID: state.ID, OrgID: scope.OrgID, SiteID: scope.SiteID, ClusterID: scope.ClusterID, PoolID: scope.PoolID, NodeID: row.NodeID, HealthyTicks: int32(count)}); err != nil {
			return result, false, err
		}
	}
	// `next` is the pure model's full state including candidate streaks. The
	// state-row RETURNING value deliberately has no joined candidate rows.
	observation.State, observation.Decision, observation.MembershipEpoch = healthStateFromPool(next), decision, state.MembershipEpoch
	if epoch != nil {
		if err := handoffLeaderSessionHeld(ctx, tx, *epoch); err != nil {
			return result, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return result, false, err
	}
	return observation, true, nil
}

type handoffLeaderSessionQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func handoffLeaderSessionHeld(ctx context.Context, query handoffLeaderSessionQuerier, epoch k8s.HandoffLeadershipEpoch) error {
	if query == nil || epoch.BackendPID <= 0 || epoch.LockKey == 0 {
		return ErrHandoffHealthLeaderSessionUnavailable
	}
	var held bool
	err := query.QueryRow(ctx, `
		SELECT pg_backend_pid() = $1 AND EXISTS (
			SELECT 1 FROM pg_locks
			WHERE locktype = 'advisory' AND granted AND objsubid = 1
			  AND pid = pg_backend_pid()
			  AND ((classid::bigint << 32) | (objid::bigint & 4294967295)) = $2
		)`, epoch.BackendPID, epoch.LockKey).Scan(&held)
	if err != nil || !held {
		return ErrHandoffHealthLeaderSessionUnavailable
	}
	return nil
}

func (h *PostgresHandoffHealthHistory) lockedObservation(ctx context.Context, scope k8s.HandoffPoolScope, pool sqlc.K8sConnectorPool, rows []sqlc.ListK8sConnectorPoolHealthObservationMembersForUpdateRow, now time.Time) (HandoffHealthObservation, time.Time, string, bool, error) {
	if len(rows) == 0 {
		return HandoffHealthObservation{}, time.Time{}, "", false, nil
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.NodeID)
	}
	acks := map[uuid.UUID]k8s.PolicyAcknowledgement{}
	if h.policy != nil {
		var err error
		acks, err = h.policy.HandoffPolicyAcknowledgements(ctx, scope.OrgID, scope.SiteID, ids)
		if err != nil {
			return HandoffHealthObservation{}, time.Time{}, "", false, err
		}
	}
	result := HandoffHealthObservation{Evidence: map[uuid.UUID]k8s.ConnectorEvidence{}, Health: map[string]k8s.ConnectorHealth{}, ActiveID: pool.ActiveNodeID, Generation: pool.Generation}
	maxAt := time.Time{}
	type fingerprintMember struct {
		ID           string                    `json:"id"`
		Priority     int32                     `json:"priority"`
		Status       string                    `json:"status"`
		Revoked      bool                      `json:"revoked"`
		WG           string                    `json:"wg"`
		Endpoint     string                    `json:"endpoint"`
		Seen         string                    `json:"seen"`
		Reported     string                    `json:"reported"`
		Capabilities json.RawMessage           `json:"capabilities"`
		Policy       k8s.PolicyAcknowledgement `json:"policy"`
	}
	members := make([]fingerprintMember, 0, len(rows))
	for _, row := range rows {
		node := healthObservationNode(row)
		e := ConnectorEvidenceFromNode(node, acks[row.NodeID])
		_, health := k8s.AdaptConnectorEvidence(now, h.freshness, scope.OrgID.String(), scope.SiteID.String(), e)
		result.Evidence[row.NodeID], result.Health[row.NodeID.String()] = e, health
		if node.LastSeenAt.Valid && node.LastSeenAt.Time.After(maxAt) {
			maxAt = node.LastSeenAt.Time
		}
		if node.PolicyReportedAt.Valid && node.PolicyReportedAt.Time.After(maxAt) {
			maxAt = node.PolicyReportedAt.Time
		}
		members = append(members, fingerprintMember{ID: row.NodeID.String(), Priority: row.AdminPriority, Status: row.NodeStatus, Revoked: row.NodeRevokedAt.Valid, WG: row.NodeWgPublicKey, Endpoint: row.NodeEndpoint, Seen: timeFingerprint(node.LastSeenAt), Reported: timeFingerprint(node.PolicyReportedAt), Capabilities: canonicalJSON(row.NodeCapabilities), Policy: acks[row.NodeID]})
	}
	if maxAt.IsZero() || maxAt.After(now) {
		return HandoffHealthObservation{}, time.Time{}, "", false, nil
	}
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
	orderedRows := append([]sqlc.ListK8sConnectorPoolHealthObservationMembersForUpdateRow(nil), rows...)
	sort.Slice(orderedRows, func(i, j int) bool {
		if orderedRows[i].AdminPriority != orderedRows[j].AdminPriority {
			return orderedRows[i].AdminPriority > orderedRows[j].AdminPriority
		}
		return orderedRows[i].NodeID.String() < orderedRows[j].NodeID.String()
	})
	for _, row := range orderedRows {
		result.Ordered = append(result.Ordered, row.NodeID)
	}
	payload, err := json.Marshal(struct {
		Org        string              `json:"org"`
		Site       string              `json:"site"`
		Cluster    string              `json:"cluster"`
		Pool       string              `json:"pool"`
		Preferred  string              `json:"preferred"`
		Active     string              `json:"active"`
		Generation int64               `json:"generation"`
		ObservedAt string              `json:"observed_at"`
		Members    []fingerprintMember `json:"members"`
	}{scope.OrgID.String(), scope.SiteID.String(), scope.ClusterID.String(), scope.PoolID.String(), pool.PreferredNodeID.String(), pool.ActiveNodeID.String(), pool.Generation, now.UTC().Format(time.RFC3339Nano), members})
	if err != nil {
		return HandoffHealthObservation{}, time.Time{}, "", false, err
	}
	sum := sha256.Sum256(payload)
	// `now` is the CP-issued observation slot. The key cannot be derived from
	// it alone: the locked node/report/capability/policy snapshot above is also
	// hashed. A retry has the same slot+evidence key; a later CP tick does not.
	return result, now.UTC(), hex.EncodeToString(sum[:]), true, nil
}

func healthObservationNode(row sqlc.ListK8sConnectorPoolHealthObservationMembersForUpdateRow) sqlc.Node {
	return sqlc.Node{ID: row.NodeID, OrgID: row.OrgID, SiteID: pgtype.UUID{Bytes: row.SiteID, Valid: true}, Status: row.NodeStatus, RevokedAt: row.NodeRevokedAt, WgPublicKey: row.NodeWgPublicKey, Endpoint: row.NodeEndpoint, LastSeenAt: row.NodeLastSeenAt, PolicyReportedAt: row.NodePolicyReportedAt, Capabilities: row.NodeCapabilities}
}
func canonicalJSON(in []byte) json.RawMessage {
	var v any
	if json.Unmarshal(in, &v) != nil {
		return json.RawMessage("null")
	}
	out, _ := json.Marshal(v)
	return out
}
func timeFingerprint(t pgtype.Timestamptz) string {
	if !t.Valid {
		return ""
	}
	return t.Time.UTC().Format(time.RFC3339Nano)
}
func scopeValid(s k8s.HandoffPoolScope) bool {
	return s.OrgID != uuid.Nil && s.SiteID != uuid.Nil && s.ClusterID != uuid.Nil && s.PoolID != uuid.Nil
}
func healthScopeParams(s k8s.HandoffPoolScope) sqlc.GetK8sConnectorPoolHealthStateParams {
	return sqlc.GetK8sConnectorPoolHealthStateParams{OrgID: s.OrgID, SiteID: s.SiteID, ClusterID: s.ClusterID, PoolID: s.PoolID}
}
func healthTicksParams(state sqlc.K8sConnectorPoolHealthState, scope k8s.HandoffPoolScope) sqlc.ListK8sConnectorPoolHealthCandidateTicksParams {
	return sqlc.ListK8sConnectorPoolHealthCandidateTicksParams{StateID: state.ID, OrgID: scope.OrgID, SiteID: scope.SiteID, ClusterID: scope.ClusterID, PoolID: scope.PoolID}
}
func healthTicksForUpdateParams(state sqlc.K8sConnectorPoolHealthState, scope k8s.HandoffPoolScope) sqlc.ListK8sConnectorPoolHealthCandidateTicksForUpdateParams {
	return sqlc.ListK8sConnectorPoolHealthCandidateTicksForUpdateParams{StateID: state.ID, OrgID: scope.OrgID, SiteID: scope.SiteID, ClusterID: scope.ClusterID, PoolID: scope.PoolID}
}
func healthResetParams(state sqlc.K8sConnectorPoolHealthState, scope k8s.HandoffPoolScope) sqlc.ResetK8sConnectorPoolHealthCandidateTicksParams {
	return sqlc.ResetK8sConnectorPoolHealthCandidateTicksParams{StateID: state.ID, OrgID: scope.OrgID, SiteID: scope.SiteID, ClusterID: scope.ClusterID, PoolID: scope.PoolID}
}
func healthStateFromRows(state sqlc.K8sConnectorPoolHealthState, rows []sqlc.K8sConnectorPoolHealthCandidateTick) k8s.HandoffHealthState {
	out := k8s.HandoffHealthState{StaleTicks: int(state.StaleTicks), PreferredFresh: int(state.PreferredFreshTicks), CandidateHealthyTicks: map[uuid.UUID]int{}}
	for _, row := range rows {
		out.CandidateHealthyTicks[row.NodeID] = int(row.HealthyTicks)
	}
	return out
}
func healthStateFromPool(pool k8s.ConnectorPool) k8s.HandoffHealthState {
	out := k8s.HandoffHealthState{StaleTicks: pool.StaleTicks, PreferredFresh: pool.PreferredFreshTicks, CandidateHealthyTicks: map[uuid.UUID]int{}}
	for raw, ticks := range pool.CandidateHealthyTicks {
		if id, err := uuid.Parse(raw); err == nil && id != uuid.Nil {
			out.CandidateHealthyTicks[id] = ticks
		}
	}
	return out
}
func nullableUUID(raw string) pgtype.UUID {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: id, Valid: true}
}
func transitionUUID(transition k8s.Transition, raw string) pgtype.UUID {
	if transition != k8s.Promoted && transition != k8s.FailedBack {
		return pgtype.UUID{}
	}
	return nullableUUID(raw)
}
func decisionFromPersistedHealthState(state sqlc.K8sConnectorPoolHealthState, pool sqlc.K8sConnectorPool) k8s.Decision {
	transition := k8s.Transition(state.LastTransition)
	// 0082 persists target_generation as bigint. A max-valued pool cannot
	// produce another durable transition, so never add one in the pure uint64
	// model and accidentally surface a wrapped target.
	if pool.Generation >= math.MaxInt64 {
		return k8s.Decision{Transition: k8s.NoChange, Pool: k8s.ConnectorPool{ActiveID: pool.ActiveNodeID.String(), Generation: uint64(pool.Generation)}}
	}
	if transition != k8s.Promoted && transition != k8s.FailedBack || !state.LastTransitionFromNodeID.Valid || !state.LastTransitionToNodeID.Valid {
		return k8s.Decision{Transition: transition, Pool: k8s.ConnectorPool{ActiveID: pool.ActiveNodeID.String(), Generation: uint64(pool.Generation)}}
	}
	return k8s.Decision{Transition: transition, FromID: uuid.UUID(state.LastTransitionFromNodeID.Bytes).String(), ToID: uuid.UUID(state.LastTransitionToNodeID.Bytes).String(), Pool: k8s.ConnectorPool{ActiveID: uuid.UUID(state.LastTransitionToNodeID.Bytes).String(), Generation: uint64(pool.Generation + 1)}}
}
func retainedHealthTransition(state sqlc.K8sConnectorPoolHealthState, pool sqlc.K8sConnectorPool, health map[string]k8s.ConnectorHealth) (k8s.Decision, bool) {
	decision := decisionFromPersistedHealthState(state, pool)
	if decision.Transition != k8s.Promoted && decision.Transition != k8s.FailedBack || decision.FromID != pool.ActiveNodeID.String() {
		return k8s.Decision{}, false
	}
	to, err := uuid.Parse(decision.ToID)
	if err != nil || to == uuid.Nil {
		return k8s.Decision{}, false
	}
	switch decision.Transition {
	case k8s.Promoted:
		return decision, health[to.String()].Healthy() && !health[pool.ActiveNodeID.String()].Healthy()
	case k8s.FailedBack:
		return decision, to == pool.PreferredNodeID && health[to.String()].Healthy()
	default:
		return k8s.Decision{}, false
	}
}
func poolModelFromObservation(scope k8s.HandoffPoolScope, pool sqlc.K8sConnectorPool, rows []sqlc.ListK8sConnectorPoolHealthObservationMembersForUpdateRow, state k8s.HandoffHealthState) (k8s.ConnectorPool, error) {
	candidates := make([]k8s.ConnectorCandidate, 0, len(rows))
	for _, row := range rows {
		candidates = append(candidates, k8s.ConnectorCandidate{ID: row.NodeID.String(), OrgID: scope.OrgID.String(), SiteID: scope.SiteID.String(), AdminPriority: int(row.AdminPriority), Active: true, EndpointReady: true})
	}
	model, err := k8s.NewConnectorPool(scope.OrgID.String(), scope.SiteID.String(), scope.ClusterID.String(), pool.PreferredNodeID.String(), candidates, nil)
	if err != nil {
		return k8s.ConnectorPool{}, err
	}
	model.ActiveID, model.Generation, model.StaleTicks, model.PreferredFreshTicks, model.CandidateHealthyTicks = pool.ActiveNodeID.String(), uint64(pool.Generation), state.StaleTicks, state.PreferredFresh, uuidTicks(state.CandidateHealthyTicks)
	return model, nil
}
