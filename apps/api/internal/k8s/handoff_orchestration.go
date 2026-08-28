package k8s

import (
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
)

// maxPersistedHandoffValue is PostgreSQL bigint's positive ceiling. Durable
// handoff fields use uint64 in the pure/P2 contract but are stored as bigint;
// accepting a larger value would wrap during a later cast.
const maxPersistedHandoffValue = uint64(math.MaxInt64)

// HandoffPoolScope is the exact cluster-owned pool being changed. It is kept
// separate from OwnershipScope because a handoff necessarily names two
// different connector scopes.
type HandoffPoolScope struct {
	OrgID     uuid.UUID
	SiteID    uuid.UUID
	PoolID    uuid.UUID
	ClusterID uuid.UUID
}

func (s HandoffPoolScope) valid() bool {
	return s.OrgID != uuid.Nil && s.SiteID != uuid.Nil && s.PoolID != uuid.Nil && s.ClusterID != uuid.Nil
}

func (s HandoffPoolScope) matchesOwnership(scope OwnershipScope, connectorID uuid.UUID) bool {
	return s.valid() && scope.OrgID == s.OrgID && scope.SiteID == s.SiteID && scope.PoolID == s.PoolID &&
		scope.ClusterID == s.ClusterID && scope.ConnectorID == connectorID
}

// HandoffPlan is immutable, CP-constructed intent for exactly one health
// decision. The future durable owner must create/claim OperationID before it
// sends any artifact. This model does not create that record or send anything.
type HandoffPlan struct {
	OperationID uuid.UUID
	Scope       HandoffPoolScope

	ExpectedActiveID   uuid.UUID
	CandidateID        uuid.UUID
	ExpectedGeneration uint64
	TargetGeneration   uint64
	Decision           Decision

	CandidatePrevious *ArtifactPrerequisite
	NewPrepared       ArtifactPrerequisite
	NewServing        ArtifactPrerequisite
	OldServing        ArtifactPrerequisite
	OldWithdrawal     ArtifactPrerequisite
}

// HandoffPhase is durable-operation progress owned by a future CP store. The
// evaluator returns a requested next phase but never advances it itself.
type HandoffPhase string

const (
	HandoffPrepareCandidate HandoffPhase = "prepare_candidate"
	HandoffAwaitPreparedAck HandoffPhase = "await_prepared_ack"
	HandoffAwaitWithdrawal  HandoffPhase = "await_withdrawal"
	HandoffCASActive        HandoffPhase = "cas_active"
	HandoffEnableServing    HandoffPhase = "enable_serving"
	HandoffAwaitServingAck  HandoffPhase = "await_serving_ack"
	HandoffFinalize         HandoffPhase = "finalize"
	HandoffComplete         HandoffPhase = "complete"
)

// HandoffAction is an idempotency-keyed request for a future owner. It is not
// an instruction to an agent and has no data-plane side effect in this model.
type HandoffAction string

const (
	HandoffRefuse            HandoffAction = "refuse"
	HandoffDeliverPrepared   HandoffAction = "deliver_prepared"
	HandoffDeliverWithdrawal HandoffAction = "deliver_withdrawal"
	HandoffRecordCASReady    HandoffAction = "record_cas_ready"
	HandoffApplyCAS          HandoffAction = "apply_cas"
	HandoffDeliverServing    HandoffAction = "deliver_serving"
	HandoffFinalizeSuccess   HandoffAction = "finalize"
	HandoffAlreadyComplete   HandoffAction = "already_complete"
)

// HandoffDecision is the only orchestration output. A non-refusal action is
// merely eligible to be performed by a future durable scheduler/transport
// owner; it is not a lease, a fence, or an agent authorization by itself.
type HandoffDecision struct {
	Action              HandoffAction
	NextPhase           HandoffPhase
	Reason              string
	LeaseExpiryFallback bool
}

// HandoffOperationRecord is the minimum durable provenance this pure model
// expects from its future owner. A mismatched operation is a conflict, never a
// chance to take over another operation's handoff.
type HandoffOperationRecord struct {
	OperationID uuid.UUID
	Phase       HandoffPhase
}

// HandoffPoolSnapshot is a CP read, not an agent assertion. Members represents
// the exact membership rechecked by the future CAS transaction.
type HandoffPoolSnapshot struct {
	Scope      HandoffPoolScope
	ActiveID   uuid.UUID
	Generation uint64
	Members    map[uuid.UUID]bool
}

// HandoffCASReceipt is CP-constructed only after a future transaction applies
// the pool CAS and appends its audit record together. It must be persisted with
// the phase advance to HandoffEnableServing; a crash between those writes is an
// ambiguous state this model deliberately refuses.
type HandoffCASReceipt struct {
	OperationID   uuid.UUID
	Scope         HandoffPoolScope
	FromID        uuid.UUID
	ToID          uuid.UUID
	Generation    uint64
	AuditAppended bool
}

// HandoffProgress is the CP-recorded operation view plus already-authenticated
// P2 acknowledgements. Nil or malformed acknowledgement data fails closed.
type HandoffProgress struct {
	Record HandoffOperationRecord
	Pool   HandoffPoolSnapshot

	CASReceipt    *HandoffCASReceipt
	PreparedAck   *ArtifactAcknowledgement
	WithdrawalAck *ArtifactAcknowledgement
	ServingAck    *ArtifactAcknowledgement
}

// HandoffInput carries CP-clock inputs into a deterministic, side-effect-free
// phase decision. The same model works for promotion and failback because it
// takes the prior health Decision as immutable intent rather than consulting
// priority or scheduling itself.
type HandoffInput struct {
	Now             time.Time
	MaxAckAge       time.Duration
	ClockSkewMargin time.Duration
	Plan            HandoffPlan
	Progress        HandoffProgress
}

// EvaluateHandoff chooses at most one next phase action. All pre-CAS phases
// require the original active/generation/member snapshot. Serving is eligible
// only after a receipt proves the one atomic CAS+audit action completed.
func EvaluateHandoff(in HandoffInput) HandoffDecision {
	if err := validateHandoffPlan(in.Plan); err != nil {
		return handoffRefuse(err.Error())
	}
	if in.Now.IsZero() || in.MaxAckAge <= 0 || in.ClockSkewMargin <= 0 {
		return handoffRefuse("CP clock, acknowledgement age, and clock-skew margin are required")
	}
	if in.Progress.Record.OperationID != in.Plan.OperationID {
		return handoffRefuse("operation ID conflicts with the CP-recorded handoff")
	}
	switch in.Progress.Record.Phase {
	case HandoffPrepareCandidate:
		if !preCASPoolMatches(in.Plan, in.Progress) || anyAckOrReceipt(in.Progress) {
			return handoffRefuse("prepare phase is stale, replayed, or no longer matches pool state")
		}
		return HandoffDecision{Action: HandoffDeliverPrepared, NextPhase: HandoffAwaitPreparedAck, Reason: "deliver exact non-serving candidate artifact"}
	case HandoffAwaitPreparedAck:
		if !preCASPoolMatches(in.Plan, in.Progress) || in.Progress.PreparedAck == nil || in.Progress.WithdrawalAck != nil || in.Progress.ServingAck != nil || in.Progress.CASReceipt != nil {
			return handoffRefuse("prepared acknowledgement phase is incomplete, stale, or replayed")
		}
		if d := preparedDecision(in); d.Transition != OwnershipPrepared {
			return handoffRefuse("candidate preparation is not eligible: " + d.Reason)
		}
		// Persisting AwaitWithdrawal is the causal delivery boundary: a later
		// withdrawal acknowledgement is admissible only after this exact,
		// operation-keyed old-owner artifact delivery has been requested.
		return HandoffDecision{Action: HandoffDeliverWithdrawal, NextPhase: HandoffAwaitWithdrawal, Reason: "deliver exact old-owner non-serving withdrawal artifact"}
	case HandoffAwaitWithdrawal:
		if !preCASPoolMatches(in.Plan, in.Progress) || in.Progress.PreparedAck == nil || in.Progress.ServingAck != nil || in.Progress.CASReceipt != nil {
			return handoffRefuse("withdrawal phase is incomplete, stale, or replayed")
		}
		d := servingDecision(in)
		if d.Transition != OwnershipEnableServing {
			return handoffRefuse("new owner cannot be enabled: " + d.Reason)
		}
		reason := "fresh old-owner withdrawal permits one CAS attempt"
		if d.LeaseExpiryFallback {
			reason = "conservative old-lease expiry permits one CAS attempt"
		}
		return HandoffDecision{Action: HandoffRecordCASReady, NextPhase: HandoffCASActive, Reason: reason, LeaseExpiryFallback: d.LeaseExpiryFallback}
	case HandoffCASActive:
		if !preCASPoolMatches(in.Plan, in.Progress) || in.Progress.PreparedAck == nil || in.Progress.ServingAck != nil || in.Progress.CASReceipt != nil {
			return handoffRefuse("CAS phase is stale, replayed, or ambiguous")
		}
		if d := servingDecision(in); d.Transition != OwnershipEnableServing {
			return handoffRefuse("CAS authorization no longer holds: " + d.Reason)
		}
		// The future persistence owner must use OperationID as an idempotency key
		// and atomically write this CAS receipt, its audit, and NextPhase. The
		// evaluator otherwise refuses the ambiguous post-crash state.
		return HandoffDecision{Action: HandoffApplyCAS, NextPhase: HandoffEnableServing, Reason: "apply expected active/generation CAS once with audit"}
	case HandoffEnableServing:
		if !postCASPoolMatches(in.Plan, in.Progress) || !validCASReceipt(in.Plan, in.Progress.CASReceipt) || in.Progress.PreparedAck == nil || in.Progress.ServingAck != nil {
			return handoffRefuse("enable phase lacks an atomic CAS and audit receipt")
		}
		if d := servingDecision(in); d.Transition != OwnershipEnableServing {
			return handoffRefuse("serving authorization no longer holds: " + d.Reason)
		}
		return HandoffDecision{Action: HandoffDeliverServing, NextPhase: HandoffAwaitServingAck, Reason: "deliver exact serving artifact after CAS"}
	case HandoffAwaitServingAck:
		if !postCASPoolMatches(in.Plan, in.Progress) || !validCASReceipt(in.Plan, in.Progress.CASReceipt) || !validServingAck(in) {
			return handoffRefuse("serving acknowledgement is missing, stale, or does not match the enabled artifact")
		}
		return HandoffDecision{Action: HandoffFinalizeSuccess, NextPhase: HandoffFinalize, Reason: "serving artifact is freshly acknowledged"}
	case HandoffFinalize:
		if !postCASPoolMatches(in.Plan, in.Progress) || !validCASReceipt(in.Plan, in.Progress.CASReceipt) || !validServingAck(in) {
			return handoffRefuse("finalize phase is stale or lacks serving acknowledgement")
		}
		return HandoffDecision{Action: HandoffFinalizeSuccess, NextPhase: HandoffComplete, Reason: "persist completed handoff without another CAS or audit"}
	case HandoffComplete:
		if !postCASPoolMatches(in.Plan, in.Progress) || !validCASReceipt(in.Plan, in.Progress.CASReceipt) || !validServingAck(in) {
			return handoffRefuse("completed handoff no longer has its CP receipt or serving acknowledgement")
		}
		return HandoffDecision{Action: HandoffAlreadyComplete, NextPhase: HandoffComplete, Reason: "handoff already finalized"}
	default:
		return handoffRefuse("handoff phase is missing or unknown")
	}
}

func validateHandoffPlan(p HandoffPlan) error {
	if p.OperationID == uuid.Nil || !p.Scope.valid() || p.ExpectedActiveID == uuid.Nil || p.CandidateID == uuid.Nil || p.ExpectedActiveID == p.CandidateID ||
		p.ExpectedGeneration == 0 || p.ExpectedGeneration >= maxPersistedHandoffValue || p.TargetGeneration != p.ExpectedGeneration+1 || p.TargetGeneration > maxPersistedHandoffValue {
		return fmt.Errorf("handoff plan has incomplete or inconsistent pool intent")
	}
	fromID, fromErr := uuid.Parse(p.Decision.FromID)
	toID, toErr := uuid.Parse(p.Decision.ToID)
	if fromErr != nil || toErr != nil || fromID != p.ExpectedActiveID || toID != p.CandidateID || p.Decision.Pool.ActiveID != p.CandidateID.String() ||
		p.Decision.Pool.Generation != p.TargetGeneration || (p.Decision.Transition != Promoted && p.Decision.Transition != FailedBack) {
		return fmt.Errorf("handoff plan does not match an eligible pure health transition")
	}
	if !p.Scope.matchesOwnership(p.NewPrepared.Scope, p.CandidateID) || !p.Scope.matchesOwnership(p.NewServing.Scope, p.CandidateID) ||
		!p.Scope.matchesOwnership(p.OldServing.Scope, p.ExpectedActiveID) || !p.Scope.matchesOwnership(p.OldWithdrawal.Scope, p.ExpectedActiveID) {
		return fmt.Errorf("handoff artifact scope or connector conflicts with the pool plan")
	}
	if p.NewPrepared.Role != PreparedNonServing || p.NewServing.Role != Serving || p.OldServing.Role != Serving || p.OldWithdrawal.Role != PreparedNonServing ||
		p.NewPrepared.PromotionGeneration != p.TargetGeneration || p.NewServing.PromotionGeneration != p.TargetGeneration ||
		p.OldServing.PromotionGeneration != p.ExpectedGeneration || p.OldWithdrawal.PromotionGeneration != p.TargetGeneration {
		return fmt.Errorf("handoff artifact roles or generations are inconsistent")
	}
	if !p.NewPrepared.valid() || !p.NewServing.valid() || !p.OldServing.valid() || !p.OldWithdrawal.valid() {
		return fmt.Errorf("handoff artifacts lack validated P2 identity or CP lease provenance")
	}
	// One handoff snapshot has one serving route/VIP view.  Accepting distinct
	// old/new digests would let CAS promote an owner whose P2 data plane cannot
	// prove it inherited the same owned state.  Non-serving artifacts are
	// intentionally canonical-empty and share the one exact target lease.
	if p.OldServing.ExpectedRouteDigest != p.NewServing.ExpectedRouteDigest ||
		p.OldServing.ExpectedVIPMapDigest != p.NewServing.ExpectedVIPMapDigest ||
		p.OldServing.Lease.Epoch >= p.NewPrepared.Lease.Epoch ||
		p.NewPrepared.Lease.Epoch != p.OldWithdrawal.Lease.Epoch || p.NewPrepared.Lease.Epoch != p.NewServing.Lease.Epoch ||
		!p.NewPrepared.Lease.ExpiresAt.Equal(p.OldWithdrawal.Lease.ExpiresAt) || !p.NewPrepared.Lease.ExpiresAt.Equal(p.NewServing.Lease.ExpiresAt) {
		return fmt.Errorf("handoff artifacts do not retain one exact serving snapshot and target lease")
	}
	return nil
}

func preCASPoolMatches(p HandoffPlan, progress HandoffProgress) bool {
	return progress.Pool.Scope == p.Scope && progress.Pool.ActiveID == p.ExpectedActiveID && progress.Pool.Generation == p.ExpectedGeneration &&
		progress.Pool.Members[p.ExpectedActiveID] && progress.Pool.Members[p.CandidateID]
}

func postCASPoolMatches(p HandoffPlan, progress HandoffProgress) bool {
	return progress.Pool.Scope == p.Scope && progress.Pool.ActiveID == p.CandidateID && progress.Pool.Generation == p.TargetGeneration &&
		progress.Pool.Members[p.ExpectedActiveID] && progress.Pool.Members[p.CandidateID]
}

func anyAckOrReceipt(p HandoffProgress) bool {
	return p.PreparedAck != nil || p.WithdrawalAck != nil || p.ServingAck != nil || p.CASReceipt != nil
}

func preparedDecision(in HandoffInput) OwnershipDecision {
	return EvaluatePreparedOwnership(PreparedOwnershipInput{
		Now: in.Now, MaxAckAge: in.MaxAckAge, ClockSkewMargin: in.ClockSkewMargin,
		Expected: in.Plan.NewPrepared, Previous: in.Plan.CandidatePrevious, Acknowledgement: *in.Progress.PreparedAck,
	})
}

func servingDecision(in HandoffInput) OwnershipDecision {
	return EvaluateServingOwnership(ServingOwnershipInput{
		Now: in.Now, MaxAckAge: in.MaxAckAge, ClockSkewMargin: in.ClockSkewMargin,
		NewPrepared: in.Plan.NewPrepared, NewServing: in.Plan.NewServing, PreparedAck: *in.Progress.PreparedAck,
		OldServing: in.Plan.OldServing, OldWithdrawal: in.Plan.OldWithdrawal, WithdrawalAck: in.Progress.WithdrawalAck,
	})
}

func validCASReceipt(p HandoffPlan, receipt *HandoffCASReceipt) bool {
	return receipt != nil && receipt.OperationID == p.OperationID && receipt.Scope == p.Scope && receipt.FromID == p.ExpectedActiveID &&
		receipt.ToID == p.CandidateID && receipt.Generation == p.TargetGeneration && receipt.AuditAppended
}

func validServingAck(in HandoffInput) bool {
	if in.Progress.ServingAck == nil {
		return false
	}
	ack := *in.Progress.ServingAck
	return matchesAcknowledgement(ack, in.Plan.NewServing, in.Now, in.MaxAckAge) && ack.ServingAttested && !ack.NonServingAttested
}

func handoffRefuse(reason string) HandoffDecision {
	return HandoffDecision{Action: HandoffRefuse, Reason: reason}
}
