package k8s

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// HandoffTransport is the only side-effect dependency of the coordinator.
// Each call is keyed by OperationID and must be idempotent: a crash after a
// delivery but before the phase CAS causes the same request to be retried.
// This interface has no HTTP, agent-report, or data-plane implementation.
type HandoffTransport interface {
	PrepareCandidate(context.Context, HandoffDelivery) error
	WithdrawOld(context.Context, HandoffDelivery) error
	EnableNew(context.Context, HandoffDelivery) error
}

// HandoffOperationProvenanceFence revalidates a P2-owned fresh-plan claim
// inside the exact transaction that creates 0082's operation. This closes the
// resolve-to-create window for capability revocation and Service UID churn.
// It is optional only for legacy/test-only coordinator construction; a P2
// provenance-backed composition must provide it and has no receipt fallback.
type HandoffOperationProvenanceFence interface {
	ValidateHandoffOperationProvenance(context.Context, pgx.Tx, DurableHandoffPlan, HandoffLeadershipEpoch) error
}

// HandoffDelivery is CP-constructed input to a future transport. The artifact
// already carries CP-validated P2 identity/lease provenance; this coordinator
// never constructs a manifest or treats delivery as an acknowledgement.
type HandoffDelivery struct {
	OperationID uuid.UUID
	Scope       HandoffPoolScope
	Artifact    ArtifactPrerequisite
	// PriorLeaseEpoch is set only for the old-owner withdrawal artifact. It
	// names the serving lease being withdrawn, not the newer non-serving lease
	// carried by Artifact itself.
	PriorLeaseEpoch uint64
	LeadershipEpoch HandoffLeadershipEpoch
	// LeaderConn is the exact advisory-lock-holding PostgreSQL session. A
	// delivery issuer must use this connection for its durable issue write; an
	// epoch/PID check on another pooled connection is not a leadership fence.
	LeaderConn *pgxpool.Conn
}

// DurableHandoffPlan pairs the pure handoff intent with the two opaque lease
// identities persisted by 0082. Lease identities remain opaque because their
// format belongs to P2; equality is all this coordinator needs.
type DurableHandoffPlan struct {
	Plan                HandoffPlan
	OldLeaseIdentity    string
	TargetLeaseIdentity string
}

// HandoffHealthState is CP scheduler-owned observation history. 0082 starts
// only after a transition is eligible, so it intentionally persists operation
// phase rather than inventing a health-history store. A restarted scheduler
// must supply its authoritative observation state again; an existing durable
// operation resumes from its phase without reselecting a candidate.
type HandoffHealthState struct {
	StaleTicks            int
	PreferredFresh        int
	CandidateHealthyTicks map[uuid.UUID]int
}

// HandoffCoordinatorRequest is one CP tick. Evidence and acknowledgements are
// CP-constructed after authenticating untrusted reports; agent time or an
// untrusted role claim never advances a phase by itself.
type HandoffCoordinatorRequest struct {
	Plan DurableHandoffPlan
	// CurrentPhase is populated only when the durable source resumes an
	// existing operation. The leader-bound runner uses it to select exactly one
	// v3 attestation, and the coordinator rechecks it against the stored phase so
	// a source-to-runner race cannot apply an acknowledgement to a later phase.
	CurrentPhase    HandoffPhase
	Now             time.Time
	ReportFreshness time.Duration
	MaxAckAge       time.Duration
	ClockSkewMargin time.Duration
	HealthState     HandoffHealthState
	Evidence        map[uuid.UUID]ConnectorEvidence
	PreparedAck     *ArtifactAcknowledgement
	WithdrawalAck   *ArtifactAcknowledgement
	ServingAck      *ArtifactAcknowledgement
	// ObservedHealthDecision is emitted only by the durable CP observation
	// writer after it atomically advances hysteresis. It avoids re-applying the
	// same threshold observation after restart. It is not agent input and does
	// not replace the pool/member CAS in CreateOrResume.
	ObservedHealthDecision *Decision
	// ObservedMembershipEpoch is the durable 0083 membership incarnation that
	// produced ObservedHealthDecision. When supplied by the PostgreSQL observer,
	// CreateOrResume checks it in the same statement that claims the operation,
	// so a member leave/rejoin or priority change cannot reuse a threshold that
	// the health-history trigger has invalidated.
	ObservedMembershipEpoch *uint64
	leadershipEpoch         HandoffLeadershipEpoch
	leaderConn              *pgxpool.Conn
}

// HandoffCoordinatorResult is deliberately compact: an external scheduler can
// persist HealthState independently, while Applied/Waiting/Conflict make it
// impossible to mistake a refused or stale tick for progress.
type HandoffCoordinatorResult struct {
	OperationID uuid.UUID
	Phase       HandoffPhase
	Action      HandoffAction
	HealthState HandoffHealthState
	Applied     bool
	Waiting     bool
	Conflict    bool
	Terminal    bool
}

var (
	ErrInvalidHandoffCoordinatorRequest = errors.New("invalid handoff coordinator request")
	ErrHandoffOperationConflict         = errors.New("connector pool handoff operation conflicts with persisted state")
	ErrHandoffAcknowledgementRefused    = errors.New("connector pool handoff acknowledgement is not CP-eligible")
	ErrHandoffLeadershipUnavailable     = errors.New("connector handoff leadership epoch is unavailable")
)

// HandoffCoordinator is an opt-in local service. It has no goroutine, timer,
// HTTP route, report handler, or transport implementation; a future scheduler
// must call Tick explicitly with fresh CP evidence and validated P2 intent.
type HandoffCoordinator struct {
	service    *Service
	transport  HandoffTransport
	provenance HandoffOperationProvenanceFence
	// beforeDeferredIssue is a test-only crash seam for the committed-intent to
	// durable-issue boundary. Production construction leaves it nil.
	beforeDeferredIssue func() error
}

func NewHandoffCoordinator(service *Service, transport HandoffTransport) *HandoffCoordinator {
	return &HandoffCoordinator{service: service, transport: transport}
}

// WithHandoffOperationProvenanceFence returns this unregistered coordinator
// with the P2 final-validation seam. Scheduler/main construction remains
// separate and disabled by default.
func (c *HandoffCoordinator) WithHandoffOperationProvenanceFence(fence HandoffOperationProvenanceFence) *HandoffCoordinator {
	if c != nil {
		c.provenance = fence
	}
	return c
}

// Tick creates/resumes exactly one durable operation, then executes at most
// one phase action. It never changes active ownership except through
// CommitK8sConnectorHandoffCAS, whose audit reason is server-derived below.
func (c *HandoffCoordinator) Tick(ctx context.Context, req HandoffCoordinatorRequest) (HandoffCoordinatorResult, error) {
	return c.tick(ctx, req)
}

// TickWithLeadership is the scheduler-only entry point. The epoch is captured
// from the exact advisory-lock session. Every coordinator mutation starts a
// transaction that verifies that exact lock on the pinned connection, then its
// SQL also predicates on the matching backend PID. It is not distributed
// fencing: P2 generation and lease evidence remain the data-plane fence in
// each artifact.
func (c *HandoffCoordinator) TickWithLeadership(ctx context.Context, req HandoffCoordinatorRequest, epoch HandoffLeadershipEpoch, conn *pgxpool.Conn) (HandoffCoordinatorResult, error) {
	if !epoch.valid() || conn == nil {
		return HandoffCoordinatorResult{}, ErrHandoffLeadershipUnavailable
	}
	req.leadershipEpoch = epoch
	req.leaderConn = conn
	return c.tick(ctx, req)
}

func (c *HandoffCoordinator) tick(ctx context.Context, req HandoffCoordinatorRequest) (HandoffCoordinatorResult, error) {
	if c == nil || c.service == nil || c.transport == nil {
		return HandoffCoordinatorResult{}, fmt.Errorf("%w: service and transport are required", ErrInvalidHandoffCoordinatorRequest)
	}
	if req.ObservedHealthDecision != nil && (req.ObservedMembershipEpoch == nil || *req.ObservedMembershipEpoch > uint64(^uint64(0)>>1)) {
		return HandoffCoordinatorResult{}, fmt.Errorf("%w: durable health decision requires a valid membership epoch", ErrInvalidHandoffCoordinatorRequest)
	}
	if err := validateDurablePlan(req.Plan); err != nil || req.Now.IsZero() || req.MaxAckAge <= 0 || req.ClockSkewMargin <= 0 {
		if err == nil {
			err = errors.New("CP time, acknowledgement age, and clock-skew margin are required")
		}
		return HandoffCoordinatorResult{}, fmt.Errorf("%w: %v", ErrInvalidHandoffCoordinatorRequest, err)
	}

	q := c.queries(req)
	op, err := q.GetK8sConnectorHandoffOperation(ctx, sqlc.GetK8sConnectorHandoffOperationParams{
		OperationID: req.Plan.Plan.OperationID, OrgID: req.Plan.Plan.Scope.OrgID,
		SiteID: req.Plan.Plan.Scope.SiteID, PoolID: req.Plan.Plan.Scope.PoolID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return c.start(ctx, req)
	}
	if err != nil {
		return HandoffCoordinatorResult{}, err
	}
	if !matchesDurableOperation(req.Plan, op, req.ObservedMembershipEpoch) {
		return HandoffCoordinatorResult{}, ErrHandoffOperationConflict
	}
	if req.leaderConn != nil && req.CurrentPhase != HandoffPhase(op.Phase) {
		return HandoffCoordinatorResult{}, ErrHandoffOperationConflict
	}
	return c.resume(ctx, req, op)
}

func (c *HandoffCoordinator) start(ctx context.Context, req HandoffCoordinatorRequest) (HandoffCoordinatorResult, error) {
	pool, members, nextHealth, decision, err := c.selectFromEvidence(ctx, req)
	if err != nil {
		return HandoffCoordinatorResult{}, err
	}
	if req.ObservedHealthDecision != nil {
		decision = *req.ObservedHealthDecision
		if !observedDecisionMatchesPool(decision, req.Plan.Plan, pool, members) {
			return HandoffCoordinatorResult{}, fmt.Errorf("%w: durable observation no longer matches pool", ErrInvalidHandoffCoordinatorRequest)
		}
	}
	if decision.Transition != Promoted && decision.Transition != FailedBack {
		return HandoffCoordinatorResult{Phase: HandoffPrepareCandidate, Action: HandoffRefuse, HealthState: nextHealth, Waiting: true}, nil
	}
	if !sameTransition(req.Plan.Plan.Decision, decision) || req.Plan.Plan.ExpectedActiveID != pool.ActiveNodeID || req.Plan.Plan.ExpectedGeneration != uint64(pool.Generation) {
		return HandoffCoordinatorResult{}, fmt.Errorf("%w: supplied durable intent does not match deterministic CP evidence", ErrInvalidHandoffCoordinatorRequest)
	}
	q := c.queries(req)
	create := func(q *sqlc.Queries) error {
		_, err = q.CreateOrResumeK8sConnectorHandoffOperation(ctx, createOperationParams(req.Plan, req.leadershipEpoch, req.ObservedMembershipEpoch))
		return err
	}
	if req.leaderConn != nil {
		err = c.service.withLeaderTxRaw(ctx, req.leaderConn, req.leadershipEpoch, func(q *sqlc.Queries, tx pgx.Tx) error {
			if c.provenance != nil {
				if err := c.provenance.ValidateHandoffOperationProvenance(ctx, tx, req.Plan, req.leadershipEpoch); err != nil {
					return err
				}
			}
			return create(q)
		})
	} else {
		if c.provenance != nil {
			return HandoffCoordinatorResult{}, ErrHandoffLeadershipUnavailable
		}
		err = create(q)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return HandoffCoordinatorResult{OperationID: req.Plan.Plan.OperationID, HealthState: nextHealth, Conflict: true}, nil
	}
	if err != nil {
		return HandoffCoordinatorResult{}, err
	}
	op, err := q.GetK8sConnectorHandoffOperation(ctx, sqlc.GetK8sConnectorHandoffOperationParams{
		OperationID: req.Plan.Plan.OperationID, OrgID: req.Plan.Plan.Scope.OrgID,
		SiteID: req.Plan.Plan.Scope.SiteID, PoolID: req.Plan.Plan.Scope.PoolID,
	})
	if err != nil {
		return HandoffCoordinatorResult{}, err
	}
	return c.resume(ctx, req, op)
}

func observedDecisionMatchesPool(decision Decision, plan HandoffPlan, pool sqlc.K8sConnectorPool, members []sqlc.K8sConnectorPoolMember) bool {
	if (decision.Transition != Promoted && decision.Transition != FailedBack) || !sameTransition(plan.Decision, decision) ||
		plan.ExpectedActiveID != pool.ActiveNodeID || plan.ExpectedGeneration != uint64(pool.Generation) {
		return false
	}
	to, err := uuid.Parse(decision.ToID)
	if err != nil || to == uuid.Nil {
		return false
	}
	found := false
	for _, member := range members {
		if member.NodeID == to {
			found = true
			break
		}
	}
	return found && (decision.Transition != FailedBack || pool.PreferredNodeID == to)
}

func (c *HandoffCoordinator) selectFromEvidence(ctx context.Context, req HandoffCoordinatorRequest) (sqlc.K8sConnectorPool, []sqlc.K8sConnectorPoolMember, HandoffHealthState, Decision, error) {
	q := c.queries(req)
	pool, err := q.GetK8sConnectorPoolForPromotion(ctx, sqlc.GetK8sConnectorPoolForPromotionParams{
		OrgID: req.Plan.Plan.Scope.OrgID, SiteID: req.Plan.Plan.Scope.SiteID, PoolID: req.Plan.Plan.Scope.PoolID,
	})
	if err != nil {
		return sqlc.K8sConnectorPool{}, nil, HandoffHealthState{}, Decision{}, err
	}
	if pool.ClusterID != req.Plan.Plan.Scope.ClusterID {
		return sqlc.K8sConnectorPool{}, nil, HandoffHealthState{}, Decision{}, ErrHandoffOperationConflict
	}
	members, err := q.ListK8sConnectorPoolMembersForPromotion(ctx, sqlc.ListK8sConnectorPoolMembersForPromotionParams{
		OrgID: pool.OrgID, SiteID: pool.SiteID, PoolID: pool.ID,
	})
	if err != nil {
		return sqlc.K8sConnectorPool{}, nil, HandoffHealthState{}, Decision{}, err
	}
	candidates := make([]ConnectorCandidate, 0, len(members))
	health := make(map[string]ConnectorHealth, len(members))
	for _, member := range members {
		evidence := req.Evidence[member.NodeID]
		_, h := AdaptConnectorEvidence(req.Now, req.ReportFreshness, pool.OrgID.String(), pool.SiteID.String(), evidence)
		// Membership is DB-authoritative. Readiness lives in the dual-signal
		// health map, so a stale/revoked/old agent can never become selected.
		candidates = append(candidates, ConnectorCandidate{ID: member.NodeID.String(), OrgID: pool.OrgID.String(), SiteID: pool.SiteID.String(), AdminPriority: int(member.AdminPriority), Active: true, EndpointReady: true})
		health[member.NodeID.String()] = h
	}
	model, err := NewConnectorPool(pool.OrgID.String(), pool.SiteID.String(), pool.ClusterID.String(), pool.PreferredNodeID.String(), candidates, nil)
	if err != nil {
		return sqlc.K8sConnectorPool{}, nil, HandoffHealthState{}, Decision{}, err
	}
	model.ActiveID, model.Generation = pool.ActiveNodeID.String(), uint64(pool.Generation)
	model.StaleTicks, model.PreferredFreshTicks = req.HealthState.StaleTicks, req.HealthState.PreferredFresh
	model.CandidateHealthyTicks = stringTicks(req.HealthState.CandidateHealthyTicks)
	decision := Reconcile(model, health)
	return pool, members, healthState(decision.Pool), decision, nil
}

func (c *HandoffCoordinator) resume(ctx context.Context, req HandoffCoordinatorRequest, op sqlc.K8sConnectorHandoffOperation) (HandoffCoordinatorResult, error) {
	var result HandoffCoordinatorResult
	var deferred *deferredHandoffDelivery
	withTx := c.service.withTx
	if req.leaderConn != nil {
		withTx = func(ctx context.Context, fn func(*sqlc.Queries) error) error {
			return c.service.withLeaderTx(ctx, req.leaderConn, req.leadershipEpoch, fn)
		}
	}
	err := withTx(ctx, func(q *sqlc.Queries) error {
		locked, err := q.GetK8sConnectorHandoffOperationForUpdate(ctx, sqlc.GetK8sConnectorHandoffOperationForUpdateParams{
			OperationID: op.ID, OrgID: req.Plan.Plan.Scope.OrgID, SiteID: req.Plan.Plan.Scope.SiteID, PoolID: req.Plan.Plan.Scope.PoolID,
		})
		if err != nil {
			return err
		}
		if !matchesDurableOperation(req.Plan, locked, req.ObservedMembershipEpoch) {
			return ErrHandoffOperationConflict
		}
		result, deferred, err = c.resumeLocked(ctx, q, req, locked)
		return err
	})
	if err != nil || deferred == nil {
		return result, err
	}
	// P2's durable issuer starts its own transaction on the exact leader
	// session. Never invoke it while this coordinator transaction is open on
	// that same connection: issue first after the locked decision commits, then
	// perform the expected-phase CAS in a fresh leader-bound transaction. A
	// crash between them safely retries the same operation-keyed artifact.
	if c.beforeDeferredIssue != nil {
		if err := c.beforeDeferredIssue(); err != nil {
			return result, err
		}
	}
	if err := c.deliver(ctx, deferred.action, deferred.delivery); err != nil {
		return result, err
	}
	return c.advanceDeferredDelivery(ctx, req, result, *deferred)
}

type deferredHandoffDelivery struct {
	action         HandoffAction
	delivery       HandoffDelivery
	expected, next HandoffPhase
	prepared       *time.Time
}

func (c *HandoffCoordinator) resumeLocked(ctx context.Context, q *sqlc.Queries, req HandoffCoordinatorRequest, op sqlc.K8sConnectorHandoffOperation) (HandoffCoordinatorResult, *deferredHandoffDelivery, error) {
	result := HandoffCoordinatorResult{OperationID: op.ID, Phase: HandoffPhase(op.Phase), HealthState: req.HealthState}
	if op.Phase == string(HandoffComplete) {
		result.Action, result.Terminal, result.Waiting = HandoffAlreadyComplete, true, true
		return result, nil, nil
	}
	if op.Phase == "failed" {
		result.Terminal, result.Waiting = true, true
		return result, nil, nil
	}
	progress, err := c.progress(ctx, q, req, op)
	if err != nil {
		return result, nil, err
	}
	decision := EvaluateHandoff(HandoffInput{Now: req.Now, MaxAckAge: req.MaxAckAge, ClockSkewMargin: req.ClockSkewMargin, Plan: req.Plan.Plan, Progress: progress})
	if decision.Action == HandoffRefuse {
		// Missing acknowledgement is an expected wait. Any supplied
		// acknowledgement that fails exact CP validation is a refusal, not a
		// retryable delivery.
		if ackForPhase(req, HandoffPhase(op.Phase)) {
			return result, nil, fmt.Errorf("%w: %s", ErrHandoffAcknowledgementRefused, decision.Reason)
		}
		result.Action, result.Waiting = HandoffRefuse, true
		return result, nil, nil
	}
	result.Action = decision.Action
	switch decision.Action {
	case HandoffDeliverPrepared:
		delivery := handoffDelivery(req, op.ID, req.Plan.Plan.NewPrepared)
		if req.leaderConn != nil {
			return result, &deferredHandoffDelivery{action: decision.Action, delivery: delivery, expected: HandoffPrepareCandidate, next: HandoffAwaitPreparedAck}, nil
		}
		if err := c.deliver(ctx, decision.Action, delivery); err != nil {
			return result, nil, err
		}
		advanced, err := c.advance(ctx, q, result, req, HandoffPrepareCandidate, HandoffAwaitPreparedAck, nil, nil, nil, nil)
		return advanced, nil, err
	case HandoffDeliverWithdrawal:
		withdrawal := handoffDelivery(req, op.ID, req.Plan.Plan.OldWithdrawal)
		withdrawal.PriorLeaseEpoch = req.Plan.Plan.OldServing.Lease.Epoch
		if req.leaderConn != nil {
			return result, &deferredHandoffDelivery{action: decision.Action, delivery: withdrawal, expected: HandoffAwaitPreparedAck, next: HandoffAwaitWithdrawal, prepared: receipt(req.PreparedAck)}, nil
		}
		if err := c.deliver(ctx, decision.Action, withdrawal); err != nil {
			return result, nil, err
		}
		advanced, err := c.advance(ctx, q, result, req, HandoffAwaitPreparedAck, HandoffAwaitWithdrawal, receipt(req.PreparedAck), nil, nil, nil)
		return advanced, nil, err
	case HandoffRecordCASReady:
		var withdrawal, expiry *time.Time
		if decision.LeaseExpiryFallback {
			expiry = &req.Now
		} else {
			withdrawal = receipt(req.WithdrawalAck)
		}
		advanced, err := c.advance(ctx, q, result, req, HandoffAwaitWithdrawal, HandoffCASActive, nil, withdrawal, expiry, nil)
		return advanced, nil, err
	case HandoffApplyCAS:
		updated, err := q.CommitK8sConnectorHandoffCAS(ctx, sqlc.CommitK8sConnectorHandoffCASParams{
			ActorSystem: "connector-ha", AuditReason: handoffAuditReason(req.Plan.Plan.Decision.Transition),
			OperationID: op.ID, OrgID: req.Plan.Plan.Scope.OrgID, SiteID: req.Plan.Plan.Scope.SiteID, PoolID: req.Plan.Plan.Scope.PoolID,
			LeaderBackendPid: req.leadershipEpoch.BackendPID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			result.Conflict = true
			return result, nil, nil
		}
		if err != nil {
			return result, nil, err
		}
		result.Phase, result.Applied = HandoffPhase(updated.Phase), true
		return result, nil, nil
	case HandoffDeliverServing:
		delivery := handoffDelivery(req, op.ID, req.Plan.Plan.NewServing)
		if req.leaderConn != nil {
			return result, &deferredHandoffDelivery{action: decision.Action, delivery: delivery, expected: HandoffEnableServing, next: HandoffAwaitServingAck}, nil
		}
		if err := c.deliver(ctx, decision.Action, delivery); err != nil {
			return result, nil, err
		}
		advanced, err := c.advance(ctx, q, result, req, HandoffEnableServing, HandoffAwaitServingAck, nil, nil, nil, nil)
		return advanced, nil, err
	case HandoffFinalizeSuccess:
		if HandoffPhase(op.Phase) == HandoffAwaitServingAck {
			advanced, err := c.advance(ctx, q, result, req, HandoffAwaitServingAck, HandoffFinalize, nil, nil, nil, receipt(req.ServingAck))
			return advanced, nil, err
		}
		advanced, err := c.advance(ctx, q, result, req, HandoffFinalize, HandoffComplete, nil, nil, nil, nil)
		return advanced, nil, err
	case HandoffAlreadyComplete:
		result.Terminal, result.Waiting = true, true
		return result, nil, nil
	default:
		return result, nil, fmt.Errorf("%w: unsupported action %q", ErrInvalidHandoffCoordinatorRequest, decision.Action)
	}
}

func (c *HandoffCoordinator) deliver(ctx context.Context, action HandoffAction, delivery HandoffDelivery) error {
	switch action {
	case HandoffDeliverPrepared:
		return c.transport.PrepareCandidate(ctx, delivery)
	case HandoffDeliverWithdrawal:
		return c.transport.WithdrawOld(ctx, delivery)
	case HandoffDeliverServing:
		return c.transport.EnableNew(ctx, delivery)
	default:
		return fmt.Errorf("%w: unsupported delivery action %q", ErrInvalidHandoffCoordinatorRequest, action)
	}
}

func (c *HandoffCoordinator) advanceDeferredDelivery(ctx context.Context, req HandoffCoordinatorRequest, result HandoffCoordinatorResult, delivery deferredHandoffDelivery) (HandoffCoordinatorResult, error) {
	var advanced HandoffCoordinatorResult
	err := c.service.withLeaderTx(ctx, req.leaderConn, req.leadershipEpoch, func(q *sqlc.Queries) error {
		// The artifact was durably issued after the first locked decision
		// committed. Before the expected-phase CAS can acknowledge that issue,
		// lock and reconstruct the current CP pool snapshot again. An
		// operation-ID/phase-only update would otherwise bless a delivery after
		// its active owner, generation, or exact old/new membership changed in
		// this intentional crash/retry gap.
		locked, err := q.GetK8sConnectorHandoffOperationForUpdate(ctx, sqlc.GetK8sConnectorHandoffOperationForUpdateParams{
			OperationID: result.OperationID, OrgID: req.Plan.Plan.Scope.OrgID, SiteID: req.Plan.Plan.Scope.SiteID, PoolID: req.Plan.Plan.Scope.PoolID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			advanced = result
			advanced.Conflict = true
			return nil
		}
		if err != nil {
			return err
		}
		if !matchesDurableOperation(req.Plan, locked, req.ObservedMembershipEpoch) || HandoffPhase(locked.Phase) != delivery.expected {
			advanced = result
			advanced.Conflict = true
			return nil
		}
		progress, err := c.progress(ctx, q, req, locked)
		if err != nil {
			return err
		}
		if !deferredDeliveryPoolMatches(req.Plan.Plan, delivery.expected, progress) {
			advanced = result
			advanced.Conflict = true
			return nil
		}
		advanced, err = c.advance(ctx, q, result, req, delivery.expected, delivery.next, delivery.prepared, nil, nil, nil)
		return err
	})
	if err != nil {
		return result, err
	}
	return advanced, nil
}

// deferredDeliveryPoolMatches is the second, post-issue CP claim fence. The
// pre-CAS artifact phases remain admissible only while the original owner,
// generation, and immutable old/new membership are unchanged. The serving
// artifact is admissible only after the one CAS+audit target state is still
// present. Auxiliary post-CAS membership churn is intentionally allowed by
// 0083 so a committed active owner is not stranded non-serving; old/new member
// deletion remains FK-refused and active/generation drift fails closed here.
func deferredDeliveryPoolMatches(plan HandoffPlan, expected HandoffPhase, progress HandoffProgress) bool {
	switch expected {
	case HandoffPrepareCandidate, HandoffAwaitPreparedAck:
		return preCASPoolMatches(plan, progress)
	case HandoffEnableServing:
		return postCASPoolMatches(plan, progress)
	default:
		return false
	}
}

func (c *HandoffCoordinator) progress(ctx context.Context, q *sqlc.Queries, req HandoffCoordinatorRequest, op sqlc.K8sConnectorHandoffOperation) (HandoffProgress, error) {
	pool, err := q.GetK8sConnectorPoolForPromotion(ctx, sqlc.GetK8sConnectorPoolForPromotionParams{OrgID: req.Plan.Plan.Scope.OrgID, SiteID: req.Plan.Plan.Scope.SiteID, PoolID: req.Plan.Plan.Scope.PoolID})
	if err != nil {
		return HandoffProgress{}, err
	}
	members, err := q.ListK8sConnectorPoolMembersForPromotion(ctx, sqlc.ListK8sConnectorPoolMembersForPromotionParams{OrgID: pool.OrgID, SiteID: pool.SiteID, PoolID: pool.ID})
	if err != nil {
		return HandoffProgress{}, err
	}
	p := HandoffProgress{Record: HandoffOperationRecord{OperationID: op.ID, Phase: HandoffPhase(op.Phase)}, Pool: HandoffPoolSnapshot{
		Scope: req.Plan.Plan.Scope, ActiveID: pool.ActiveNodeID, Generation: uint64(pool.Generation), Members: map[uuid.UUID]bool{},
	}}
	for _, member := range members {
		p.Pool.Members[member.NodeID] = true
	}
	if op.PreparedAckReceivedAt.Valid {
		a := acknowledged(req.Plan.Plan.NewPrepared, op.PreparedAckReceivedAt.Time, true, false, 0)
		p.PreparedAck = &a
	} else if req.PreparedAck != nil {
		p.PreparedAck = req.PreparedAck
	}
	if op.WithdrawalAckReceivedAt.Valid {
		a := acknowledged(req.Plan.Plan.OldWithdrawal, op.WithdrawalAckReceivedAt.Time, true, false, req.Plan.Plan.OldServing.Lease.Epoch)
		p.WithdrawalAck = &a
	} else if req.WithdrawalAck != nil {
		p.WithdrawalAck = req.WithdrawalAck
	}
	if op.ServingAckReceivedAt.Valid {
		a := acknowledged(req.Plan.Plan.NewServing, op.ServingAckReceivedAt.Time, false, true, 0)
		p.ServingAck = &a
	} else if req.ServingAck != nil {
		p.ServingAck = req.ServingAck
	}
	if op.CasAuditApplied && op.CasAuditID.Valid && op.CasReceiptAt.Valid {
		p.CASReceipt = &HandoffCASReceipt{OperationID: op.ID, Scope: req.Plan.Plan.Scope, FromID: op.OldNodeID, ToID: op.NewNodeID, Generation: uint64(op.TargetGeneration), AuditAppended: true}
	}
	return p, nil
}

func (c *HandoffCoordinator) advance(ctx context.Context, q *sqlc.Queries, result HandoffCoordinatorResult, req HandoffCoordinatorRequest, expected, next HandoffPhase, prepared, withdrawal, expiry, serving *time.Time) (HandoffCoordinatorResult, error) {
	params := sqlc.AdvanceK8sConnectorHandoffOperationPhaseParams{OperationID: result.OperationID, OrgID: req.Plan.Plan.Scope.OrgID, SiteID: req.Plan.Plan.Scope.SiteID, PoolID: req.Plan.Plan.Scope.PoolID, ExpectedPhase: string(expected), NextPhase: string(next)}
	params.PreparedAckReceivedAt = nullableTime(prepared)
	params.WithdrawalAckReceivedAt = nullableTime(withdrawal)
	params.WithdrawalExpiryReceivedAt = nullableTime(expiry)
	params.ServingAckReceivedAt = nullableTime(serving)
	params.LeaderBackendPid = req.leadershipEpoch.BackendPID
	updated, err := q.AdvanceK8sConnectorHandoffOperationPhase(ctx, params)
	if errors.Is(err, pgx.ErrNoRows) {
		result.Conflict = true
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.Phase, result.Applied = HandoffPhase(updated.Phase), true
	if result.Phase == HandoffComplete {
		result.Terminal = true
	}
	return result, nil
}

func handoffDelivery(req HandoffCoordinatorRequest, operationID uuid.UUID, artifact ArtifactPrerequisite) HandoffDelivery {
	return HandoffDelivery{OperationID: operationID, Scope: req.Plan.Plan.Scope, Artifact: artifact, LeadershipEpoch: req.leadershipEpoch, LeaderConn: req.leaderConn}
}

func validateDurablePlan(plan DurableHandoffPlan) error {
	if err := validateHandoffPlan(plan.Plan); err != nil {
		return err
	}
	if !boundedOpaque(plan.OldLeaseIdentity) || !boundedOpaque(plan.TargetLeaseIdentity) {
		return errors.New("opaque lease identities are required")
	}
	for _, artifact := range []ArtifactPrerequisite{plan.Plan.OldServing, plan.Plan.NewPrepared, plan.Plan.OldWithdrawal, plan.Plan.NewServing} {
		if artifact.ManifestRevision > maxPersistedHandoffValue || artifact.Lease.Epoch > maxPersistedHandoffValue {
			return errors.New("handoff artifact revision or lease epoch exceeds durable bigint range")
		}
	}
	return nil
}

// ValidateDurableHandoffPlan exposes the coordinator's pure boundary to
// CP-owned read adapters. It validates prerequisites only; it neither reads or
// writes persistence nor turns a valid plan into distributed fencing.
func ValidateDurableHandoffPlan(plan DurableHandoffPlan) error {
	return validateDurablePlan(plan)
}

func boundedOpaque(s string) bool { return len(s) <= 512 && strings.TrimSpace(s) != "" }

func matchesDurableOperation(plan DurableHandoffPlan, op sqlc.K8sConnectorHandoffOperation, observedMembershipEpoch *uint64) bool {
	p := plan.Plan
	if op.ID != p.OperationID || op.OrgID != p.Scope.OrgID || op.SiteID != p.Scope.SiteID || op.PoolID != p.Scope.PoolID || op.ClusterID != p.Scope.ClusterID ||
		op.OldNodeID != p.ExpectedActiveID || op.NewNodeID != p.CandidateID || op.ExpectedGeneration != int64(p.ExpectedGeneration) || op.TargetGeneration != int64(p.TargetGeneration) ||
		op.DecisionTransition != string(p.Decision.Transition) ||
		op.OldServingManifestIdentity != p.OldServing.ManifestIdentity || op.CandidatePreparedManifestIdentity != p.NewPrepared.ManifestIdentity || op.OldWithdrawalManifestIdentity != p.OldWithdrawal.ManifestIdentity || op.NewServingManifestIdentity != p.NewServing.ManifestIdentity ||
		op.OldServingManifestRevision != int64(p.OldServing.ManifestRevision) || op.CandidatePreparedManifestRevision != int64(p.NewPrepared.ManifestRevision) || op.OldWithdrawalManifestRevision != int64(p.OldWithdrawal.ManifestRevision) || op.NewServingManifestRevision != int64(p.NewServing.ManifestRevision) ||
		op.OldServingExpectedRouteDigest != p.OldServing.ExpectedRouteDigest || op.OldServingExpectedVipMapDigest != p.OldServing.ExpectedVIPMapDigest ||
		op.CandidatePreparedExpectedRouteDigest != p.NewPrepared.ExpectedRouteDigest || op.CandidatePreparedExpectedVipMapDigest != p.NewPrepared.ExpectedVIPMapDigest ||
		op.OldWithdrawalExpectedRouteDigest != p.OldWithdrawal.ExpectedRouteDigest || op.OldWithdrawalExpectedVipMapDigest != p.OldWithdrawal.ExpectedVIPMapDigest ||
		op.NewServingExpectedRouteDigest != p.NewServing.ExpectedRouteDigest || op.NewServingExpectedVipMapDigest != p.NewServing.ExpectedVIPMapDigest ||
		op.OldLeaseIdentity != plan.OldLeaseIdentity || op.TargetLeaseIdentity != plan.TargetLeaseIdentity || op.OldLeaseEpoch != int64(p.OldServing.Lease.Epoch) || op.TargetLeaseEpoch != int64(p.NewPrepared.Lease.Epoch) ||
		!op.OldLeaseExpiresAt.Equal(p.OldServing.Lease.ExpiresAt) || !op.TargetLeaseExpiresAt.Equal(p.NewPrepared.Lease.ExpiresAt) {
		return false
	}
	if observedMembershipEpoch == nil {
		return op.ObservedMembershipEpoch == nil
	}
	return *observedMembershipEpoch <= uint64(^uint64(0)>>1) && op.ObservedMembershipEpoch != nil && int64(*observedMembershipEpoch) == *op.ObservedMembershipEpoch
}

func createOperationParams(plan DurableHandoffPlan, epoch HandoffLeadershipEpoch, membershipEpoch *uint64) sqlc.CreateOrResumeK8sConnectorHandoffOperationParams {
	p := plan.Plan
	params := sqlc.CreateOrResumeK8sConnectorHandoffOperationParams{OperationID: p.OperationID, OrgID: p.Scope.OrgID, SiteID: p.Scope.SiteID, PoolID: p.Scope.PoolID, ClusterID: p.Scope.ClusterID,
		OldNodeID: p.ExpectedActiveID, NewNodeID: p.CandidateID, ExpectedGeneration: int64(p.ExpectedGeneration), TargetGeneration: int64(p.TargetGeneration),
		OldServingManifestIdentity: p.OldServing.ManifestIdentity, CandidatePreparedManifestIdentity: p.NewPrepared.ManifestIdentity, OldWithdrawalManifestIdentity: p.OldWithdrawal.ManifestIdentity, NewServingManifestIdentity: p.NewServing.ManifestIdentity,
		OldServingManifestRevision: int64(p.OldServing.ManifestRevision), CandidatePreparedManifestRevision: int64(p.NewPrepared.ManifestRevision), OldWithdrawalManifestRevision: int64(p.OldWithdrawal.ManifestRevision), NewServingManifestRevision: int64(p.NewServing.ManifestRevision),
		OldServingExpectedRouteDigest: p.OldServing.ExpectedRouteDigest, OldServingExpectedVipMapDigest: p.OldServing.ExpectedVIPMapDigest,
		CandidatePreparedExpectedRouteDigest: p.NewPrepared.ExpectedRouteDigest, CandidatePreparedExpectedVipMapDigest: p.NewPrepared.ExpectedVIPMapDigest,
		OldWithdrawalExpectedRouteDigest: p.OldWithdrawal.ExpectedRouteDigest, OldWithdrawalExpectedVipMapDigest: p.OldWithdrawal.ExpectedVIPMapDigest,
		NewServingExpectedRouteDigest: p.NewServing.ExpectedRouteDigest, NewServingExpectedVipMapDigest: p.NewServing.ExpectedVIPMapDigest,
		OldLeaseIdentity: plan.OldLeaseIdentity, TargetLeaseIdentity: plan.TargetLeaseIdentity, OldLeaseEpoch: int64(p.OldServing.Lease.Epoch), TargetLeaseEpoch: int64(p.NewPrepared.Lease.Epoch), OldLeaseExpiresAt: p.OldServing.Lease.ExpiresAt, TargetLeaseExpiresAt: p.NewPrepared.Lease.ExpiresAt,
		DecisionTransition: string(p.Decision.Transition), LeaderBackendPid: epoch.BackendPID}
	if membershipEpoch != nil {
		value := int64(*membershipEpoch)
		params.ExpectedMembershipEpoch = &value
	}
	return params
}

func (c *HandoffCoordinator) queries(req HandoffCoordinatorRequest) *sqlc.Queries {
	if req.leaderConn != nil {
		return sqlc.New(req.leaderConn)
	}
	return c.service.q
}

func sameTransition(want, got Decision) bool {
	return want.Transition == got.Transition && want.FromID == got.FromID && want.ToID == got.ToID && want.Pool.ActiveID == got.Pool.ActiveID && want.Pool.Generation == got.Pool.Generation
}
func stringTicks(in map[uuid.UUID]int) map[string]int {
	out := map[string]int{}
	for id, n := range in {
		out[id.String()] = n
	}
	return out
}
func healthState(pool ConnectorPool) HandoffHealthState {
	out := HandoffHealthState{StaleTicks: pool.StaleTicks, PreferredFresh: pool.PreferredFreshTicks, CandidateHealthyTicks: map[uuid.UUID]int{}}
	for id, n := range pool.CandidateHealthyTicks {
		if parsed, err := uuid.Parse(id); err == nil {
			out.CandidateHealthyTicks[parsed] = n
		}
	}
	return out
}
func receipt(a *ArtifactAcknowledgement) *time.Time {
	if a == nil {
		return nil
	}
	t := a.ReceiptAt
	return &t
}
func nullableTime(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}
func acknowledged(a ArtifactPrerequisite, at time.Time, nonServing, serving bool, withdrawalEpoch uint64) ArtifactAcknowledgement {
	return ArtifactAcknowledgement{Artifact: a, ReceiptAt: at, NonServingAttested: nonServing, ServingAttested: serving, WithdrawalLeaseEpoch: withdrawalEpoch}
}
func ackForPhase(req HandoffCoordinatorRequest, phase HandoffPhase) bool {
	switch phase {
	case HandoffAwaitPreparedAck:
		return req.PreparedAck != nil
	case HandoffAwaitWithdrawal, HandoffCASActive:
		return req.WithdrawalAck != nil
	case HandoffAwaitServingAck:
		return req.ServingAck != nil
	default:
		return false
	}
}
func handoffAuditReason(transition Transition) string {
	if transition == FailedBack {
		return "connector handoff failback"
	}
	return "connector handoff promotion"
}
