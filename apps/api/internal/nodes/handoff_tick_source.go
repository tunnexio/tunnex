package nodes

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// HandoffPolicyAcknowledgements is a read-only CP-side policy comparison needed
// for connector health. It must not mutate through a separate connection: a
// reported hash is not an expected hash, so a nil or incomplete provider is
// deliberately unknown and fails closed.
type HandoffPolicyAcknowledgementSource interface {
	HandoffPolicyAcknowledgements(context.Context, uuid.UUID, uuid.UUID, []uuid.UUID) (map[uuid.UUID]k8s.PolicyAcknowledgement, error)
}

// HandoffHealthHistory supplies CP-owned pure-model observation state. It is
// intentionally read-only here: this source never invents or persists ticks.
// A missing state prevents a fresh intent, but never replaces a durable one.
type HandoffHealthHistory interface {
	HandoffHealthState(context.Context, k8s.HandoffPoolScope) (k8s.HandoffHealthState, bool, error)
}

// HandoffTickIntent is the exact DB/evidence selection given to a later
// CP-owned prerequisite resolver. It is not a P2 transport request and grants
// no ownership. Existing means operation identity and candidate come from the
// immutable 0082 record, never a new selection.
type HandoffTickIntent struct {
	OperationID uuid.UUID
	Scope       k8s.HandoffPoolScope
	Existing    bool
	// ObservedMembershipEpoch is nil only for a legacy/non-observer operation.
	// It is CP-owned durable membership provenance, never report input.
	ObservedMembershipEpoch *uint64
	ExpectedActiveID        uuid.UUID
	CandidateID             uuid.UUID
	ExpectedGeneration      uint64
	TargetGeneration        uint64
	Decision                k8s.Decision
	OrderedCandidateIDs     []uuid.UUID
}

// HandoffPlanResolver is a read-only source of CP-validated P2 prerequisites;
// it must not mutate operations, pool ownership, or delivery state through a
// separate connection. The coordinator later locks and rechecks its output
// before any phase/CAS write. It must retain the transition and manifest
// revisions for an existing 0082 operation; those facts are intentionally not
// fabricated from opaque columns.
type HandoffPlanResolver interface {
	ResolveHandoffPlan(context.Context, HandoffTickIntent) (k8s.DurableHandoffPlan, bool, error)
}

// HandoffLeaderBoundPlanResolver is required while a leader-bound tick derives
// a fresh plan. Its session is not interchangeable with another currently
// leading connection because P2 locks CP-owned provenance with it.
type HandoffLeaderBoundPlanResolver interface {
	HandoffPlanResolver
	ResolveHandoffPlanWithLeadership(context.Context, HandoffTickIntent, k8s.HandoffLeadershipEpoch, *pgxpool.Conn) (k8s.DurableHandoffPlan, bool, error)
}

type HandoffTickSourceConfig struct {
	ReportFreshness time.Duration
	MaxAckAge       time.Duration
	ClockSkewMargin time.Duration
}

func (c HandoffTickSourceConfig) valid() bool {
	return c.ReportFreshness > 0 && c.MaxAckAge > 0 && c.ClockSkewMargin > 0
}

// PostgresHandoffTickSource is the concrete read adapter behind the unregistered
// scheduler. Its snapshot/policy/plan providers are read-only prerequisites;
// their output is revalidated by the leader-fenced observer and again by the
// coordinator's expected-state CAS. Fresh health history is the only durable
// source-side mutation and it is always written through the exact leader
// connection. It has no scheduler registration or P2 transport implementation.
type PostgresHandoffTickSource struct {
	pool    *pgxpool.Pool
	policy  HandoffPolicyAcknowledgementSource
	history HandoffHealthHistory
	plans   HandoffPlanResolver
	config  HandoffTickSourceConfig
}

func NewPostgresHandoffTickSource(pool *pgxpool.Pool, policy HandoffPolicyAcknowledgementSource, history HandoffHealthHistory, plans HandoffPlanResolver, config HandoffTickSourceConfig) *PostgresHandoffTickSource {
	return &PostgresHandoffTickSource{pool: pool, policy: policy, history: history, plans: plans, config: config}
}

// handoffSchedulerActivationReady makes the future composition root prove it
// assembled one exact CP evidence path: the pool and durable observer must be
// shared, and policy/P2-plan prerequisites must already exist. It intentionally
// performs no query; disabled activation must have no CP reads or writes.
func (s *PostgresHandoffTickSource) handoffSchedulerActivationReady(pool *pgxpool.Pool, observer *PostgresHandoffHealthHistory) bool {
	return s != nil && pool != nil && observer != nil && s.pool == pool && s.history == observer &&
		s.config.valid() && handoffActivationDependencyPresent(s.policy) && handoffActivationDependencyPresent(s.plans)
}

var _ k8s.HandoffTickSource = (*PostgresHandoffTickSource)(nil)
var _ k8s.HandoffLeaderBoundTickSource = (*PostgresHandoffTickSource)(nil)

// HandoffRequests implements k8s.HandoffTickSource. The request list is a
// safe subset: a pool with incomplete scope, membership, evidence, history, or
// prerequisites is omitted. A database/provider failure returns no partial
// list so the scheduler backs off without acting on a mixed snapshot.
func (s *PostgresHandoffTickSource) HandoffRequests(ctx context.Context, now time.Time) ([]k8s.HandoffCoordinatorRequest, error) {
	// A concrete durable observer would write via its own pool connection here.
	// Refuse instead: production scheduler calls must use the leader-bound
	// method below. A non-observer history is intentionally read-only and is
	// retained for narrow pure/read adapter tests.
	if s == nil {
		return nil, errors.New("postgres handoff tick source prerequisites are incomplete")
	}
	if _, writes := s.history.(HandoffHealthObserver); writes {
		return nil, ErrHandoffHealthLeaderSessionUnavailable
	}
	return s.handoffRequests(ctx, now, nil, nil, true)
}

// HandoffRequestsWithLeadership derives requests under an exact advisory-lock
// session. Discovery, policy acknowledgement, and plan provenance interfaces
// remain read-only; their values are rejected unless the locked observer and
// later coordinator CAS still match the exact pool scope, generation, members,
// and membership epoch.
func (s *PostgresHandoffTickSource) HandoffRequestsWithLeadership(ctx context.Context, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) ([]k8s.HandoffCoordinatorRequest, error) {
	if s == nil || conn == nil {
		return nil, ErrHandoffHealthLeaderSessionUnavailable
	}
	if err := handoffLeaderSessionHeld(ctx, conn, epoch); err != nil {
		return nil, err
	}
	observer, _ := s.history.(HandoffLeaderBoundHealthObserver)
	return s.handoffRequests(ctx, now, func(ctx context.Context, scope k8s.HandoffPoolScope, at time.Time) (HandoffHealthObservation, bool, error) {
		if observer == nil {
			return HandoffHealthObservation{}, false, nil
		}
		return observer.ObserveHandoffHealthWithLeadership(ctx, scope, at, epoch, conn)
	}, &handoffPlanLeadership{epoch: epoch, conn: conn}, false)
}

type handoffHealthObservationFunc func(context.Context, k8s.HandoffPoolScope, time.Time) (HandoffHealthObservation, bool, error)

type handoffPlanLeadership struct {
	epoch k8s.HandoffLeadershipEpoch
	conn  *pgxpool.Conn
}

func (s *PostgresHandoffTickSource) handoffRequests(ctx context.Context, now time.Time, observe handoffHealthObservationFunc, leadership *handoffPlanLeadership, allowReadOnlyHistory bool) ([]k8s.HandoffCoordinatorRequest, error) {
	if s == nil || s.pool == nil || !s.config.valid() || now.IsZero() {
		return nil, errors.New("postgres handoff tick source prerequisites are incomplete")
	}

	pools, operations, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	requests := make([]k8s.HandoffCoordinatorRequest, 0, len(pools))
	for _, pool := range pools {
		if !pool.valid() {
			continue
		}
		evidence, health, ordered, ok, err := s.poolEvidence(ctx, now, pool)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		op, resuming := operations[pool.id]
		if resuming {
			operationEpoch, epochValid := handoffOperationMembershipEpoch(op)
			if !epochValid || !operationMatchesPool(op, pool) || !pool.hasMember(op.OldNodeID) || !pool.hasMember(op.NewNodeID) || s.plans == nil {
				continue
			}
			intent := resumeIntent(op, pool, ordered)
			plan, available, err := s.plans.ResolveHandoffPlan(ctx, intent)
			if err != nil {
				return nil, err
			}
			if !available || k8s.ValidateDurableHandoffPlan(plan) != nil || !planMatchesOperation(plan, op) {
				continue
			}
			request := handoffRequest(plan, now, s.config, k8s.HandoffHealthState{}, evidence)
			request.CurrentPhase = k8s.HandoffPhase(op.Phase)
			request.ObservedMembershipEpoch = operationEpoch
			requests = append(requests, request)
			continue
		}
		// A fresh transition increments one PostgreSQL bigint generation. Keep a
		// max-valued pool inert rather than wrapping target_generation in the
		// uint64/P2 plan before the coordinator can reject it.
		if pool.generation >= math.MaxInt64 {
			continue
		}

		// A fresh handoff needs both CP-owned tick history and P2-validated
		// provenance. Do not turn an eligible pool into a durable intent here.
		if s.history == nil || s.plans == nil {
			continue
		}
		var state k8s.HandoffHealthState
		var decision k8s.Decision
		var observedMembershipEpoch *uint64
		if observe != nil {
			observed, observedAvailable, err := observe(ctx, pool.scope(), now)
			if err != nil {
				if errors.Is(err, ErrHandoffHealthObservationStale) {
					continue
				}
				return nil, err
			}
			if !observedAvailable || observed.ActiveID != pool.active || observed.Generation != pool.generation {
				continue
			}
			state, decision, evidence, health, ordered = observed.State, observed.Decision, observed.Evidence, observed.Health, observed.Ordered
			if observed.MembershipEpoch < 0 {
				continue
			}
			epoch := uint64(observed.MembershipEpoch)
			observedMembershipEpoch = &epoch
		} else if allowReadOnlyHistory {
			loaded, available, err := s.history.HandoffHealthState(ctx, pool.scope())
			if err != nil {
				return nil, err
			}
			if !available {
				continue
			}
			state = loaded
			model, err := pool.model(ordered)
			if err != nil {
				continue
			}
			model.StaleTicks = state.StaleTicks
			model.PreferredFreshTicks = state.PreferredFresh
			model.CandidateHealthyTicks = uuidTicks(state.CandidateHealthyTicks)
			decision = k8s.Reconcile(model, health)
		} else {
			// Without the leader-bound observer a fresh threshold is not
			// authoritative. Resume handling above is read-only and remains safe.
			continue
		}
		if decision.Transition != k8s.Promoted && decision.Transition != k8s.FailedBack {
			continue
		}
		candidateID, err := uuid.Parse(decision.ToID)
		if err != nil || candidateID == uuid.Nil {
			continue
		}
		intent := HandoffTickIntent{
			OperationID:             StableHandoffOperationID(pool.scope(), pool.active, candidateID, uint64(pool.generation), observedMembershipEpoch),
			Scope:                   pool.scope(),
			ObservedMembershipEpoch: observedMembershipEpoch,
			ExpectedActiveID:        pool.active,
			CandidateID:             candidateID,
			ExpectedGeneration:      uint64(pool.generation),
			TargetGeneration:        uint64(pool.generation + 1),
			Decision:                decision,
			OrderedCandidateIDs:     ordered,
		}
		var plan k8s.DurableHandoffPlan
		var available bool
		if leadership != nil {
			bound, ok := s.plans.(HandoffLeaderBoundPlanResolver)
			if !ok {
				continue
			}
			plan, available, err = bound.ResolveHandoffPlanWithLeadership(ctx, intent, leadership.epoch, leadership.conn)
		} else {
			plan, available, err = s.plans.ResolveHandoffPlan(ctx, intent)
		}
		if err != nil {
			return nil, err
		}
		if !available || k8s.ValidateDurableHandoffPlan(plan) != nil || !planMatchesIntent(plan, intent) {
			continue
		}
		request := handoffRequest(plan, now, s.config, state, evidence)
		if observedMembershipEpoch != nil {
			observed := decision
			request.ObservedHealthDecision = &observed
			request.ObservedMembershipEpoch = observedMembershipEpoch
		}
		requests = append(requests, request)
	}
	return requests, nil
}

// StableHandoffOperationID is a deterministic, non-secret operation key for
// a prospective immutable pool transition. A durable observer's membership
// epoch is part of that correlation: after epoch churn aborts an operation,
// a later full threshold creates a distinct intent rather than reopening the
// terminal record. Nil is the explicit legacy/non-observer domain.
func StableHandoffOperationID(scope k8s.HandoffPoolScope, active, candidate uuid.UUID, generation uint64, observedMembershipEpoch *uint64) uuid.UUID {
	epoch := "legacy"
	if observedMembershipEpoch != nil {
		epoch = fmt.Sprintf("epoch-%d", *observedMembershipEpoch)
	}
	name := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%d/%s", scope.OrgID, scope.SiteID, scope.PoolID, scope.ClusterID, active, candidate, generation, epoch)
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("tunnex.k8s.handoff/"+name))
}

type handoffTickPool struct {
	id, org, site, cluster, preferred, active uuid.UUID
	generation                                int64
	members                                   []handoffTickMember
	invalid                                   bool
}

type handoffTickMember struct {
	id       uuid.UUID
	priority int32
	node     sqlc.Node
}

func (s *PostgresHandoffTickSource) snapshot(ctx context.Context) ([]handoffTickPool, map[uuid.UUID]sqlc.K8sConnectorHandoffOperation, error) {
	// This deliberately uses a separate repeatable-read, read-only connection.
	// Its values are not write authorization: the exact leader-session observer
	// locks/rechecks fresh health state, and the coordinator later locks/rechecks
	// operation, pool generation, and membership before any mutation.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	rows, err := q.ListK8sConnectorHandoffTickMembers(ctx)
	if err != nil {
		return nil, nil, err
	}
	ops, err := q.ListNonterminalK8sConnectorHandoffOperationsForTick(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}

	byID := make(map[uuid.UUID]*handoffTickPool)
	order := make([]uuid.UUID, 0)
	for _, row := range rows {
		p := byID[row.PoolID]
		if p == nil {
			p = &handoffTickPool{id: row.PoolID, org: row.OrgID, site: row.SiteID, cluster: row.ClusterID, preferred: row.PreferredNodeID, active: row.ActiveNodeID, generation: row.Generation}
			byID[row.PoolID] = p
			order = append(order, row.PoolID)
		} else if p.org != row.OrgID || p.site != row.SiteID || p.cluster != row.ClusterID || p.preferred != row.PreferredNodeID || p.active != row.ActiveNodeID || p.generation != row.Generation {
			p.invalid = true
		}
		p.members = append(p.members, handoffTickMember{id: row.NodeID, priority: row.AdminPriority, node: tickNode(row)})
	}
	pools := make([]handoffTickPool, 0, len(order))
	for _, id := range order {
		pools = append(pools, *byID[id])
	}

	operationByPool := make(map[uuid.UUID]sqlc.K8sConnectorHandoffOperation, len(ops))
	for _, op := range ops {
		if _, duplicate := operationByPool[op.PoolID]; duplicate {
			// The partial unique index should make this impossible. Retain neither
			// record if a malformed snapshot ever presents it.
			operationByPool[op.PoolID] = sqlc.K8sConnectorHandoffOperation{}
			continue
		}
		operationByPool[op.PoolID] = op
	}
	return pools, operationByPool, nil
}

func tickNode(row sqlc.ListK8sConnectorHandoffTickMembersRow) sqlc.Node {
	return sqlc.Node{ID: row.NodeID, OrgID: row.OrgID, SiteID: pgtype.UUID{Bytes: row.SiteID, Valid: true}, Status: row.NodeStatus,
		RevokedAt: row.NodeRevokedAt, WgPublicKey: row.NodeWgPublicKey, Endpoint: row.NodeEndpoint,
		LastSeenAt: row.NodeLastSeenAt, PolicyReportedAt: row.NodePolicyReportedAt, Capabilities: row.NodeCapabilities}
}

func (p handoffTickPool) valid() bool {
	if p.invalid || p.id == uuid.Nil || p.org == uuid.Nil || p.site == uuid.Nil || p.cluster == uuid.Nil || p.preferred == uuid.Nil || p.active == uuid.Nil || p.generation <= 0 || len(p.members) == 0 {
		return false
	}
	seen := map[uuid.UUID]bool{}
	for _, member := range p.members {
		if member.id == uuid.Nil || seen[member.id] {
			return false
		}
		seen[member.id] = true
	}
	return seen[p.preferred] && seen[p.active]
}

func (p handoffTickPool) scope() k8s.HandoffPoolScope {
	return k8s.HandoffPoolScope{OrgID: p.org, SiteID: p.site, PoolID: p.id, ClusterID: p.cluster}
}

func (p handoffTickPool) hasMember(id uuid.UUID) bool {
	for _, member := range p.members {
		if member.id == id {
			return true
		}
	}
	return false
}

func (s *PostgresHandoffTickSource) poolEvidence(ctx context.Context, now time.Time, pool handoffTickPool) (map[uuid.UUID]k8s.ConnectorEvidence, map[string]k8s.ConnectorHealth, []uuid.UUID, bool, error) {
	memberIDs := make([]uuid.UUID, 0, len(pool.members))
	for _, member := range pool.members {
		memberIDs = append(memberIDs, member.id)
	}
	acks := map[uuid.UUID]k8s.PolicyAcknowledgement{}
	if s.policy != nil {
		var err error
		acks, err = s.policy.HandoffPolicyAcknowledgements(ctx, pool.org, pool.site, memberIDs)
		if err != nil {
			return nil, nil, nil, false, err
		}
	}

	evidence := make(map[uuid.UUID]k8s.ConnectorEvidence, len(pool.members))
	health := make(map[string]k8s.ConnectorHealth, len(pool.members))
	candidates := make([]k8s.ConnectorCandidate, 0, len(pool.members))
	for _, member := range pool.members {
		e := ConnectorEvidenceFromNode(member.node, acks[member.id])
		candidate, memberHealth := k8s.AdaptConnectorEvidence(now, s.config.ReportFreshness, pool.org.String(), pool.site.String(), e)
		candidate.AdminPriority = int(member.priority)
		evidence[member.id] = e
		health[member.id.String()] = memberHealth
		candidates = append(candidates, candidate)
	}
	model, err := k8s.NewConnectorPool(pool.org.String(), pool.site.String(), pool.cluster.String(), pool.preferred.String(), candidates, nil)
	if err != nil {
		return nil, nil, nil, false, nil
	}
	ordered := make([]uuid.UUID, 0, len(model.Candidates))
	for _, candidate := range model.Candidates {
		id, err := uuid.Parse(candidate.ID)
		if err != nil || id == uuid.Nil {
			return nil, nil, nil, false, nil
		}
		ordered = append(ordered, id)
	}
	return evidence, health, ordered, true, nil
}

func (p handoffTickPool) model(ordered []uuid.UUID) (k8s.ConnectorPool, error) {
	priority := map[uuid.UUID]int{}
	for _, member := range p.members {
		priority[member.id] = int(member.priority)
	}
	candidates := make([]k8s.ConnectorCandidate, 0, len(ordered))
	for _, id := range ordered {
		candidates = append(candidates, k8s.ConnectorCandidate{ID: id.String(), OrgID: p.org.String(), SiteID: p.site.String(), AdminPriority: priority[id], Active: true, EndpointReady: true})
	}
	model, err := k8s.NewConnectorPool(p.org.String(), p.site.String(), p.cluster.String(), p.preferred.String(), candidates, nil)
	if err != nil {
		return k8s.ConnectorPool{}, err
	}
	model.ActiveID, model.Generation = p.active.String(), uint64(p.generation)
	return model, nil
}

func uuidTicks(in map[uuid.UUID]int) map[string]int {
	out := make(map[string]int, len(in))
	for id, ticks := range in {
		out[id.String()] = ticks
	}
	return out
}

func resumeIntent(op sqlc.K8sConnectorHandoffOperation, pool handoffTickPool, ordered []uuid.UUID) HandoffTickIntent {
	epoch, _ := handoffOperationMembershipEpoch(op)
	return HandoffTickIntent{OperationID: op.ID, Scope: pool.scope(), Existing: true, ExpectedActiveID: op.OldNodeID, CandidateID: op.NewNodeID,
		ObservedMembershipEpoch: epoch, ExpectedGeneration: uint64(op.ExpectedGeneration), TargetGeneration: uint64(op.TargetGeneration), OrderedCandidateIDs: append([]uuid.UUID(nil), ordered...)}
}

// handoffOperationMembershipEpoch preserves the immutable epoch claimed by
// an observer-originated operation through restart. Nil is the explicit
// mixed-version legacy state; a negative raw value is malformed and cannot be
// resumed.
func handoffOperationMembershipEpoch(op sqlc.K8sConnectorHandoffOperation) (*uint64, bool) {
	if op.ObservedMembershipEpoch == nil {
		return nil, true
	}
	if *op.ObservedMembershipEpoch < 0 {
		return nil, false
	}
	epoch := uint64(*op.ObservedMembershipEpoch)
	return &epoch, true
}

func operationMatchesPool(op sqlc.K8sConnectorHandoffOperation, pool handoffTickPool) bool {
	if op.ID == uuid.Nil || op.OrgID != pool.org || op.SiteID != pool.site || op.PoolID != pool.id || op.ClusterID != pool.cluster ||
		op.ExpectedGeneration <= 0 || op.TargetGeneration != op.ExpectedGeneration+1 {
		return false
	}
	switch k8s.HandoffPhase(op.Phase) {
	case k8s.HandoffPrepareCandidate, k8s.HandoffAwaitPreparedAck, k8s.HandoffAwaitWithdrawal, k8s.HandoffCASActive:
		// No artifact delivery before/at CAS may be resumed once another
		// ownership path changed the pool from the operation's old snapshot.
		return pool.active == op.OldNodeID && pool.generation == op.ExpectedGeneration
	case k8s.HandoffEnableServing, k8s.HandoffAwaitServingAck, k8s.HandoffFinalize:
		// Serving/finalization must likewise stop if ownership drifted after
		// the committed target state. Never enable from a stale receipt.
		return pool.active == op.NewNodeID && pool.generation == op.TargetGeneration
	default:
		return false
	}
}

func handoffRequest(plan k8s.DurableHandoffPlan, now time.Time, config HandoffTickSourceConfig, state k8s.HandoffHealthState, evidence map[uuid.UUID]k8s.ConnectorEvidence) k8s.HandoffCoordinatorRequest {
	return k8s.HandoffCoordinatorRequest{Plan: plan, Now: now, ReportFreshness: config.ReportFreshness, MaxAckAge: config.MaxAckAge,
		ClockSkewMargin: config.ClockSkewMargin, HealthState: state, Evidence: evidence}
}

func planMatchesIntent(plan k8s.DurableHandoffPlan, intent HandoffTickIntent) bool {
	p := plan.Plan
	return p.OperationID == intent.OperationID && p.Scope == intent.Scope && p.ExpectedActiveID == intent.ExpectedActiveID && p.CandidateID == intent.CandidateID &&
		p.ExpectedGeneration == intent.ExpectedGeneration && p.TargetGeneration == intent.TargetGeneration && sameDecision(p.Decision, intent.Decision)
}

func planMatchesOperation(plan k8s.DurableHandoffPlan, op sqlc.K8sConnectorHandoffOperation) bool {
	p := plan.Plan
	return p.OperationID == op.ID && p.Scope.OrgID == op.OrgID && p.Scope.SiteID == op.SiteID && p.Scope.PoolID == op.PoolID && p.Scope.ClusterID == op.ClusterID &&
		p.ExpectedActiveID == op.OldNodeID && p.CandidateID == op.NewNodeID && p.ExpectedGeneration == uint64(op.ExpectedGeneration) && p.TargetGeneration == uint64(op.TargetGeneration) &&
		plan.OldLeaseIdentity == op.OldLeaseIdentity && plan.TargetLeaseIdentity == op.TargetLeaseIdentity &&
		string(p.Decision.Transition) == op.DecisionTransition &&
		matchesStoredArtifact(p.OldServing, op.OldServingManifestIdentity, op.OldServingManifestRevision, op.OldServingExpectedRouteDigest, op.OldServingExpectedVipMapDigest, op.OldLeaseEpoch, op.OldLeaseExpiresAt, k8s.Serving) &&
		matchesStoredArtifact(p.NewPrepared, op.CandidatePreparedManifestIdentity, op.CandidatePreparedManifestRevision, op.CandidatePreparedExpectedRouteDigest, op.CandidatePreparedExpectedVipMapDigest, op.TargetLeaseEpoch, op.TargetLeaseExpiresAt, k8s.PreparedNonServing) &&
		matchesStoredArtifact(p.OldWithdrawal, op.OldWithdrawalManifestIdentity, op.OldWithdrawalManifestRevision, op.OldWithdrawalExpectedRouteDigest, op.OldWithdrawalExpectedVipMapDigest, op.TargetLeaseEpoch, op.TargetLeaseExpiresAt, k8s.PreparedNonServing) &&
		matchesStoredArtifact(p.NewServing, op.NewServingManifestIdentity, op.NewServingManifestRevision, op.NewServingExpectedRouteDigest, op.NewServingExpectedVipMapDigest, op.TargetLeaseEpoch, op.TargetLeaseExpiresAt, k8s.Serving)
}

func matchesStoredArtifact(artifact k8s.ArtifactPrerequisite, identity string, revision int64, routeDigest, vipMapDigest string, epoch int64, expires time.Time, role k8s.OwnershipRole) bool {
	return artifact.ManifestIdentity == identity && artifact.ManifestRevision == uint64(revision) && artifact.ExpectedRouteDigest == routeDigest && artifact.ExpectedVIPMapDigest == vipMapDigest && artifact.Lease.Epoch == uint64(epoch) && artifact.Lease.ExpiresAt.Equal(expires) && artifact.Role == role
}

func sameDecision(a, b k8s.Decision) bool {
	return a.Transition == b.Transition && a.FromID == b.FromID && a.ToID == b.ToID && a.Pool.ActiveID == b.Pool.ActiveID && a.Pool.Generation == b.Pool.Generation
}
