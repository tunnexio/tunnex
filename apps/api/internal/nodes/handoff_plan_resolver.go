package nodes

import (
	"context"
	"errors"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// HandoffFreshPlanProvenanceSource is the narrow P1 boundary for the future
// CP-owned P2 facade. It returns only CP-validated opaque artifact and lease
// provenance for a fresh exact intent; it has no scheduler or transport role.
//
// The Postgres resolver never accepts agent assertions here. In particular,
// the source must have authenticated and matched its untrusted inputs before
// setting the internal ArtifactPrerequisite provenance flags. No source means
// no fresh plan.
type HandoffFreshPlanProvenanceSource interface {
	ResolveFreshHandoffPlan(context.Context, HandoffTickIntent) (k8s.DurableHandoffPlan, bool, error)
}

// HandoffLeaderBoundFreshPlanProvenanceSource is the scheduler-only variant
// of the fresh provenance boundary. It receives the exact advisory-lock
// connection held by the caller and must not reacquire a session through a
// provider. The coordinator's final provenance check remains in the same
// transaction as CreateOrResume.
type HandoffLeaderBoundFreshPlanProvenanceSource interface {
	HandoffFreshPlanProvenanceSource
	ResolveFreshHandoffPlanWithLeadership(context.Context, HandoffTickIntent, k8s.HandoffLeadershipEpoch, *pgxpool.Conn) (k8s.DurableHandoffPlan, bool, error)
}

// HandoffLeaderBoundFreshPlanClaimSource closes the production composition
// gap between a health decision and its immutable P2 provenance.  The claim
// is built and persisted from CP-owned topology on the caller's exact leader
// connection; agent input can never manufacture it.
type HandoffLeaderBoundFreshPlanClaimSource interface {
	BuildAndClaimFreshHandoffPlanWithLeadership(context.Context, HandoffTickIntent, k8s.HandoffLeadershipEpoch, *pgxpool.Conn) (k8s.DurableHandoffPlan, bool, error)
}

// PostgresHandoffPlanResolver turns an exact 0079/0083 observation intent into
// a durable-plan prerequisite. It never changes the active connector or pool
// generation: CreateOrResume and CommitK8sConnectorHandoffCAS remain the only
// mutation boundaries owned by the coordinator.
//
// Fresh plans require CP-validated artifact provenance. Existing plans are
// reconstructed solely from the immutable 0082 record, including revisions
// and transition kind, so restart cannot infer ownership from latest node
// state or a later preferred-node edit.
type PostgresHandoffPlanResolver struct {
	pool       *pgxpool.Pool
	provenance HandoffFreshPlanProvenanceSource
}

func NewPostgresHandoffPlanResolver(pool *pgxpool.Pool, provenance HandoffFreshPlanProvenanceSource) *PostgresHandoffPlanResolver {
	return &PostgresHandoffPlanResolver{pool: pool, provenance: provenance}
}

// NewPostgresHandoffPlanResolverWithLeadershipProvenance is the composition
// constructor for the default-off scheduler seam. Its typed input makes a
// provenance source that would reacquire a leader session fail at composition
// time rather than relying on a runtime convention.
func NewPostgresHandoffPlanResolverWithLeadershipProvenance(pool *pgxpool.Pool, provenance HandoffLeaderBoundFreshPlanProvenanceSource) *PostgresHandoffPlanResolver {
	return NewPostgresHandoffPlanResolver(pool, provenance)
}

var _ HandoffPlanResolver = (*PostgresHandoffPlanResolver)(nil)
var _ HandoffLeaderBoundPlanResolver = (*PostgresHandoffPlanResolver)(nil)

// ResolveHandoffPlanWithLeadership uses a P2 source only through its exact
// caller-held leader session. A missing direct seam fails closed rather than
// falling back to a source that could reacquire a different backend session.
func (r *PostgresHandoffPlanResolver) ResolveHandoffPlanWithLeadership(ctx context.Context, intent HandoffTickIntent, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (k8s.DurableHandoffPlan, bool, error) {
	if r == nil || r.pool == nil || conn == nil || epoch.BackendPID <= 0 || epoch.LockKey == 0 {
		return k8s.DurableHandoffPlan{}, false, ErrHandoffHealthLeaderSessionUnavailable
	}
	if err := handoffLeaderSessionHeld(ctx, conn, epoch); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	return r.resolveHandoffPlanWithLeadership(ctx, intent, epoch, conn)
}

func (r *PostgresHandoffPlanResolver) ResolveHandoffPlan(ctx context.Context, intent HandoffTickIntent) (k8s.DurableHandoffPlan, bool, error) {
	return r.resolveHandoffPlanWithLeadership(ctx, intent, k8s.HandoffLeadershipEpoch{}, nil)
}

func (r *PostgresHandoffPlanResolver) resolveHandoffPlanWithLeadership(ctx context.Context, intent HandoffTickIntent, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (k8s.DurableHandoffPlan, bool, error) {
	if r == nil || r.pool == nil || !validHandoffPlanIntent(intent) {
		return k8s.DurableHandoffPlan{}, false, nil
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	rows, err := q.ListK8sConnectorHandoffResolutionMembers(ctx, resolutionMembersParams(intent.Scope))
	if err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	snapshot, ok := handoffResolutionSnapshotFromRows(intent.Scope, rows)
	if !ok || (!intent.Existing && !snapshot.matchesIntent(intent)) || (intent.Existing && !snapshot.hasIntentMembers(intent)) {
		return k8s.DurableHandoffPlan{}, false, nil
	}

	if intent.Existing {
		op, err := q.GetK8sConnectorHandoffOperation(ctx, sqlc.GetK8sConnectorHandoffOperationParams{
			OperationID: intent.OperationID, OrgID: intent.Scope.OrgID, SiteID: intent.Scope.SiteID, PoolID: intent.Scope.PoolID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return k8s.DurableHandoffPlan{}, false, nil
			}
			return k8s.DurableHandoffPlan{}, false, err
		}
		plan, ok := durablePlanFromOperation(op)
		if !ok || !snapshot.matchesOperation(op, intent) || !planMatchesOperation(plan, op) || k8s.ValidateDurableHandoffPlan(plan) != nil {
			return k8s.DurableHandoffPlan{}, false, nil
		}
		if err := tx.Commit(ctx); err != nil {
			return k8s.DurableHandoffPlan{}, false, err
		}
		return plan, true, nil
	}

	// Returning a second fresh plan for the same pool would only create an
	// unusable stale intent. The coordinator's claim query is still the atomic
	// race authority; this exact read keeps direct/retry resolution fail closed.
	if op, err := q.GetNonterminalK8sConnectorHandoffOperationForPool(ctx, sqlc.GetNonterminalK8sConnectorHandoffOperationForPoolParams{
		OrgID: intent.Scope.OrgID, SiteID: intent.Scope.SiteID, PoolID: intent.Scope.PoolID,
	}); err == nil {
		plan, valid := durablePlanFromOperation(op)
		if valid && planMatchesIntent(plan, intent) && snapshot.matchesOperation(op, intent) {
			if err := tx.Commit(ctx); err != nil {
				return k8s.DurableHandoffPlan{}, false, err
			}
			return plan, true, nil
		}
		return k8s.DurableHandoffPlan{}, false, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return k8s.DurableHandoffPlan{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}

	if !handoffActivationDependencyPresent(r.provenance) {
		return k8s.DurableHandoffPlan{}, false, nil
	}
	var plan k8s.DurableHandoffPlan
	var available bool
	if conn != nil {
		bound, ok := r.provenance.(HandoffLeaderBoundFreshPlanProvenanceSource)
		if !ok {
			return k8s.DurableHandoffPlan{}, false, nil
		}
		if err := handoffLeaderSessionHeld(ctx, conn, epoch); err != nil {
			return k8s.DurableHandoffPlan{}, false, err
		}
		plan, available, err = bound.ResolveFreshHandoffPlanWithLeadership(ctx, intent, epoch, conn)
		if err == nil && !available {
			if claims, ok := r.provenance.(HandoffLeaderBoundFreshPlanClaimSource); ok {
				plan, available, err = claims.BuildAndClaimFreshHandoffPlanWithLeadership(ctx, intent, epoch, conn)
			}
		}
	} else {
		plan, available, err = r.provenance.ResolveFreshHandoffPlan(ctx, intent)
	}
	if err != nil || !available || k8s.ValidateDurableHandoffPlan(plan) != nil || !planMatchesIntent(plan, intent) {
		return k8s.DurableHandoffPlan{}, false, err
	}
	// Provenance retrieval may involve another CP-owned store and therefore
	// cannot share the read-only PostgreSQL snapshot above. Recheck the exact
	// binding/incarnation before returning a plan; the later create claim is
	// still the atomic authority for the remaining race.
	rows, err = sqlc.New(r.pool).ListK8sConnectorHandoffResolutionMembers(ctx, resolutionMembersParams(intent.Scope))
	if err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	current, currentOK := handoffResolutionSnapshotFromRows(intent.Scope, rows)
	if !currentOK || !current.matchesIntent(intent) {
		return k8s.DurableHandoffPlan{}, false, nil
	}
	return plan, true, nil
}

func validHandoffPlanIntent(intent HandoffTickIntent) bool {
	if intent.OperationID == uuid.Nil || intent.Scope.OrgID == uuid.Nil || intent.Scope.SiteID == uuid.Nil || intent.Scope.PoolID == uuid.Nil || intent.Scope.ClusterID == uuid.Nil ||
		intent.ExpectedActiveID == uuid.Nil || intent.CandidateID == uuid.Nil || intent.ExpectedActiveID == intent.CandidateID || intent.ExpectedGeneration == 0 || intent.ExpectedGeneration >= uint64(math.MaxInt64) || intent.TargetGeneration != intent.ExpectedGeneration+1 || intent.TargetGeneration > uint64(math.MaxInt64) {
		return false
	}
	if intent.Existing {
		return true
	}
	if intent.ObservedMembershipEpoch == nil || (intent.Decision.Transition != k8s.Promoted && intent.Decision.Transition != k8s.FailedBack) {
		return false
	}
	return true
}

func resolutionMembersParams(scope k8s.HandoffPoolScope) sqlc.ListK8sConnectorHandoffResolutionMembersParams {
	return sqlc.ListK8sConnectorHandoffResolutionMembersParams{OrgID: scope.OrgID, SiteID: scope.SiteID, PoolID: scope.PoolID, ClusterID: scope.ClusterID}
}

type handoffResolutionSnapshot struct {
	scope      k8s.HandoffPoolScope
	preferred  uuid.UUID
	active     uuid.UUID
	generation uint64
	epoch      uint64
	ordered    []uuid.UUID
	members    map[uuid.UUID]struct{}
}

func handoffResolutionSnapshotFromRows(scope k8s.HandoffPoolScope, rows []sqlc.ListK8sConnectorHandoffResolutionMembersRow) (handoffResolutionSnapshot, bool) {
	if len(rows) == 0 {
		return handoffResolutionSnapshot{}, false
	}
	first := rows[0]
	if first.PoolID != scope.PoolID || first.OrgID != scope.OrgID || first.SiteID != scope.SiteID || first.ClusterID != scope.ClusterID || first.PreferredNodeID == uuid.Nil || first.ActiveNodeID == uuid.Nil || first.Generation <= 0 || first.MembershipEpoch < 0 {
		return handoffResolutionSnapshot{}, false
	}
	snapshot := handoffResolutionSnapshot{scope: scope, preferred: first.PreferredNodeID, active: first.ActiveNodeID, generation: uint64(first.Generation), epoch: uint64(first.MembershipEpoch), members: make(map[uuid.UUID]struct{}, len(rows))}
	var previousPriority int32
	var previousID uuid.UUID
	for i, row := range rows {
		if row.PoolID != first.PoolID || row.OrgID != first.OrgID || row.SiteID != first.SiteID || row.ClusterID != first.ClusterID || row.PreferredNodeID != first.PreferredNodeID || row.ActiveNodeID != first.ActiveNodeID || row.Generation != first.Generation || row.MembershipEpoch != first.MembershipEpoch || row.NodeID == uuid.Nil {
			return handoffResolutionSnapshot{}, false
		}
		if i > 0 && (row.AdminPriority > previousPriority || (row.AdminPriority == previousPriority && string(row.NodeID[:]) <= string(previousID[:]))) {
			return handoffResolutionSnapshot{}, false
		}
		if _, exists := snapshot.members[row.NodeID]; exists {
			return handoffResolutionSnapshot{}, false
		}
		snapshot.members[row.NodeID] = struct{}{}
		snapshot.ordered = append(snapshot.ordered, row.NodeID)
		previousPriority, previousID = row.AdminPriority, row.NodeID
	}
	if _, ok := snapshot.members[snapshot.preferred]; !ok {
		return handoffResolutionSnapshot{}, false
	}
	if _, ok := snapshot.members[snapshot.active]; !ok {
		return handoffResolutionSnapshot{}, false
	}
	return snapshot, true
}

func (s handoffResolutionSnapshot) matchesIntent(intent HandoffTickIntent) bool {
	if s.scope != intent.Scope || s.active != intent.ExpectedActiveID || s.generation != intent.ExpectedGeneration {
		return false
	}
	if intent.ObservedMembershipEpoch != nil && s.epoch != *intent.ObservedMembershipEpoch {
		return false
	}
	return s.matchesMembersIntent(intent)
}

func (s handoffResolutionSnapshot) matchesMembersIntent(intent HandoffTickIntent) bool {
	if s.scope != intent.Scope {
		return false
	}
	if !s.hasIntentMembers(intent) {
		return false
	}
	if len(intent.OrderedCandidateIDs) != len(s.ordered) {
		return false
	}
	for i := range s.ordered {
		if intent.OrderedCandidateIDs[i] != s.ordered[i] {
			return false
		}
	}
	return true
}

func (s handoffResolutionSnapshot) hasIntentMembers(intent HandoffTickIntent) bool {
	if s.scope != intent.Scope {
		return false
	}
	if _, ok := s.members[intent.CandidateID]; !ok {
		return false
	}
	if _, ok := s.members[intent.ExpectedActiveID]; !ok {
		return false
	}
	return true
}

func (s handoffResolutionSnapshot) matchesOperation(op sqlc.K8sConnectorHandoffOperation, intent HandoffTickIntent) bool {
	if op.OrgID != s.scope.OrgID || op.SiteID != s.scope.SiteID || op.PoolID != s.scope.PoolID || op.ClusterID != s.scope.ClusterID || op.ID != intent.OperationID ||
		op.OldNodeID != intent.ExpectedActiveID || op.NewNodeID != intent.CandidateID || op.ExpectedGeneration <= 0 || op.TargetGeneration != op.ExpectedGeneration+1 ||
		uint64(op.ExpectedGeneration) != intent.ExpectedGeneration || uint64(op.TargetGeneration) != intent.TargetGeneration {
		return false
	}
	if _, oldMember := s.members[op.OldNodeID]; !oldMember {
		return false
	}
	if _, newMember := s.members[op.NewNodeID]; !newMember {
		return false
	}
	phase := k8s.HandoffPhase(op.Phase)
	switch phase {
	case k8s.HandoffPrepareCandidate, k8s.HandoffAwaitPreparedAck, k8s.HandoffAwaitWithdrawal, k8s.HandoffCASActive:
		if s.active != op.OldNodeID || s.generation != uint64(op.ExpectedGeneration) {
			return false
		}
		if op.ObservedMembershipEpoch != nil && (s.epoch != uint64(*op.ObservedMembershipEpoch) || intent.ObservedMembershipEpoch == nil || *intent.ObservedMembershipEpoch != s.epoch) {
			return false
		}
	case k8s.HandoffEnableServing, k8s.HandoffAwaitServingAck, k8s.HandoffFinalize:
		if s.active != op.NewNodeID || s.generation != uint64(op.TargetGeneration) {
			return false
		}
	default:
		return false
	}
	return true
}

func durablePlanFromOperation(op sqlc.K8sConnectorHandoffOperation) (k8s.DurableHandoffPlan, bool) {
	if op.ID == uuid.Nil || op.OrgID == uuid.Nil || op.SiteID == uuid.Nil || op.PoolID == uuid.Nil || op.ClusterID == uuid.Nil || op.OldNodeID == uuid.Nil || op.NewNodeID == uuid.Nil ||
		op.ExpectedGeneration <= 0 || op.TargetGeneration != op.ExpectedGeneration+1 || op.OldServingManifestRevision <= 0 || op.CandidatePreparedManifestRevision <= 0 || op.OldWithdrawalManifestRevision <= 0 || op.NewServingManifestRevision <= 0 ||
		op.OldLeaseEpoch <= 0 || op.TargetLeaseEpoch <= op.OldLeaseEpoch || op.OldLeaseExpiresAt.IsZero() || op.TargetLeaseExpiresAt.IsZero() ||
		op.OldServingRole != string(k8s.Serving) || op.CandidatePreparedRole != string(k8s.PreparedNonServing) || op.OldWithdrawalRole != string(k8s.PreparedNonServing) || op.NewServingRole != string(k8s.Serving) {
		return k8s.DurableHandoffPlan{}, false
	}
	transition := k8s.Transition(op.DecisionTransition)
	if transition != k8s.Promoted && transition != k8s.FailedBack {
		return k8s.DurableHandoffPlan{}, false
	}
	scope := k8s.HandoffPoolScope{OrgID: op.OrgID, SiteID: op.SiteID, PoolID: op.PoolID, ClusterID: op.ClusterID}
	oldScope := k8s.OwnershipScope{OrgID: op.OrgID, SiteID: op.SiteID, PoolID: op.PoolID, ClusterID: op.ClusterID, ConnectorID: op.OldNodeID}
	newScope := k8s.OwnershipScope{OrgID: op.OrgID, SiteID: op.SiteID, PoolID: op.PoolID, ClusterID: op.ClusterID, ConnectorID: op.NewNodeID}
	oldLease := k8s.CPOwnershipLease{Epoch: uint64(op.OldLeaseEpoch), ExpiresAt: op.OldLeaseExpiresAt, CPIssuedValidated: true}
	targetLease := k8s.CPOwnershipLease{Epoch: uint64(op.TargetLeaseEpoch), ExpiresAt: op.TargetLeaseExpiresAt, CPIssuedValidated: true}
	plan := k8s.DurableHandoffPlan{OldLeaseIdentity: op.OldLeaseIdentity, TargetLeaseIdentity: op.TargetLeaseIdentity, Plan: k8s.HandoffPlan{
		OperationID: op.ID, Scope: scope, ExpectedActiveID: op.OldNodeID, CandidateID: op.NewNodeID,
		ExpectedGeneration: uint64(op.ExpectedGeneration), TargetGeneration: uint64(op.TargetGeneration),
		Decision:      k8s.Decision{Transition: transition, FromID: op.OldNodeID.String(), ToID: op.NewNodeID.String(), Pool: k8s.ConnectorPool{ActiveID: op.NewNodeID.String(), Generation: uint64(op.TargetGeneration)}},
		OldServing:    artifactFromOperation(oldScope, uint64(op.ExpectedGeneration), uint64(op.OldServingManifestRevision), op.OldServingManifestIdentity, op.OldServingExpectedRouteDigest, op.OldServingExpectedVipMapDigest, oldLease, k8s.Serving),
		NewPrepared:   artifactFromOperation(newScope, uint64(op.TargetGeneration), uint64(op.CandidatePreparedManifestRevision), op.CandidatePreparedManifestIdentity, op.CandidatePreparedExpectedRouteDigest, op.CandidatePreparedExpectedVipMapDigest, targetLease, k8s.PreparedNonServing),
		OldWithdrawal: artifactFromOperation(oldScope, uint64(op.TargetGeneration), uint64(op.OldWithdrawalManifestRevision), op.OldWithdrawalManifestIdentity, op.OldWithdrawalExpectedRouteDigest, op.OldWithdrawalExpectedVipMapDigest, targetLease, k8s.PreparedNonServing),
		NewServing:    artifactFromOperation(newScope, uint64(op.TargetGeneration), uint64(op.NewServingManifestRevision), op.NewServingManifestIdentity, op.NewServingExpectedRouteDigest, op.NewServingExpectedVipMapDigest, targetLease, k8s.Serving),
	}}
	if err := k8s.ValidateDurableHandoffPlan(plan); err != nil {
		return k8s.DurableHandoffPlan{}, false
	}
	return plan, true
}

func artifactFromOperation(scope k8s.OwnershipScope, generation, revision uint64, identity, routeDigest, vipMapDigest string, lease k8s.CPOwnershipLease, role k8s.OwnershipRole) k8s.ArtifactPrerequisite {
	return k8s.ArtifactPrerequisite{Scope: scope, PromotionGeneration: generation, ManifestRevision: revision, ManifestIdentity: identity, ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: vipMapDigest, IdentityValidated: true, Lease: lease, Role: role}
}
