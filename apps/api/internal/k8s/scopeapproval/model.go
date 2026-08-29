// Package scopeapproval owns the pure state model for approval-gated
// Kubernetes cluster scopes. It deliberately has no database, HTTP, policy
// compiler, or Kubernetes client dependency.
package scopeapproval

import (
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
)

const (
	MaxCurrentCandidates = 500
	MaxInitialSelections = 100
	MaxMemberships       = 500
)

var (
	ErrInvalidLimits            = errors.New("invalid cluster-scope approval limits")
	ErrInvalidScope             = errors.New("invalid cluster-scope")
	ErrInvalidChildIdentity     = errors.New("invalid exact-port child identity")
	ErrScopeMismatch            = errors.New("cluster-scope ownership mismatch")
	ErrDuplicateChildID         = errors.New("duplicate exact-port child id")
	ErrDuplicateExactIdentity   = errors.New("duplicate exact-port identity")
	ErrUnknownChildID           = errors.New("unknown exact-port child id")
	ErrNotLaterExposure         = errors.New("creation-time child cannot become a later exposure")
	ErrExposureNotLive          = errors.New("exact-port exposure is not live")
	ErrUIDAttributionNotCurrent = errors.New("Kubernetes Service UID attribution is not current")
	ErrInventoryUnavailable     = errors.New("Kubernetes Service inventory is unavailable")
	ErrInventoryStale           = errors.New("Kubernetes Service inventory is stale")
	ErrEntitlementUnavailable   = errors.New("cluster-scope entitlement is unavailable")
	ErrOptInDisabled            = errors.New("cluster-scope organization opt-in is disabled")
	ErrUnknownStatus            = errors.New("unknown cluster-scope membership status")
	ErrUnknownOrigin            = errors.New("unknown cluster-scope membership origin")
	ErrInvalidDecision          = errors.New("invalid cluster-scope decision")
	ErrInvalidDecisionActor     = errors.New("decision actor is required")
	ErrInvalidDecisionTime      = errors.New("decision time is required")
	ErrInvalidStatusMetadata    = errors.New("invalid cluster-scope status metadata")
	ErrMembershipLimitReached   = errors.New("cluster-scope membership limit reached")
	ErrCandidateLimitReached    = errors.New("cluster-scope candidate limit reached")
	ErrSelectionLimitReached    = errors.New("cluster-scope initial selection limit reached")
)

// ProductionLimits returns the locked S20.4 bounds. Callers may supply lower
// limits in tests, but must never silently substitute larger production ones.
func ProductionLimits() Limits {
	return Limits{
		MaxCurrentCandidates: MaxCurrentCandidates,
		MaxInitialSelections: MaxInitialSelections,
		MaxMemberships:       MaxMemberships,
	}
}

// Limits bound every state transition. A breach refuses the whole transition;
// the domain never truncates a candidate snapshot or membership fan-out.
type Limits struct {
	MaxCurrentCandidates int
	MaxInitialSelections int
	MaxMemberships       int
}

func (l Limits) validate() error {
	if l.MaxCurrentCandidates <= 0 || l.MaxCurrentCandidates > MaxCurrentCandidates ||
		l.MaxInitialSelections <= 0 || l.MaxInitialSelections > MaxInitialSelections ||
		l.MaxMemberships <= 0 || l.MaxMemberships > MaxMemberships {
		return ErrInvalidLimits
	}
	return nil
}

// FeatureState is server-owned licence and organization state. A caller must
// provide both inputs; their zero values deny gated state changes and output.
type FeatureState struct {
	EntitlementUnlocked      bool
	OrganizationOptInEnabled bool
}

func (s FeatureState) requireEnabled() error {
	if !s.EntitlementUnlocked {
		return ErrEntitlementUnavailable
	}
	if !s.OrganizationOptInEnabled {
		return ErrOptInDisabled
	}
	return nil
}

// InventoryState distinguishes an authoritative empty inventory from a failed
// or stale read. The zero value is unavailable and therefore fails closed.
type InventoryState string

const (
	InventoryUnavailable InventoryState = ""
	InventoryCurrent     InventoryState = "current"
	InventoryStale       InventoryState = "stale"
)

func (s InventoryState) requireCurrent() error {
	switch s {
	case InventoryCurrent:
		return nil
	case InventoryStale:
		return ErrInventoryStale
	default:
		return ErrInventoryUnavailable
	}
}

// Protocol is part of an immutable exact-port child identity. Cluster scopes
// never infer a sibling protocol or accept a wildcard.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// ExactChildIdentity is the complete approval identity. Name and other
// presentation fields are intentionally absent; a rename cannot transfer or
// revoke approval, while a UID, protocol, or port change cannot inherit it.
type ExactChildIdentity struct {
	ChildID     uuid.UUID
	OrgID       uuid.UUID
	ClusterID   uuid.UUID
	Namespace   string
	ServiceUID  string
	Protocol    Protocol
	ServicePort int32
}

// ExactPortChild is a server-authoritative live inventory/exposure row.
// UIDAttributionCurrent means its UID was reported by the current exact
// org/Site/cluster owner; this package never guesses attribution from names.
type ExactPortChild struct {
	Identity              ExactChildIdentity
	Live                  bool
	UIDAttributionCurrent bool
}

// InitialCandidateEvidence is the immutable creation-time evidence for every
// current candidate, including the ones the administrator did not select.
type InitialCandidateEvidence struct {
	Identity ExactChildIdentity
	Selected bool
}

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

type Origin string

const (
	OriginInitial Origin = "initial"
	OriginLater   Origin = "later"
)

// Membership records a decision for one immutable exact child. Initial
// memberships are approved during creation; later exposures start pending.
type Membership struct {
	RuleID          uuid.UUID
	Identity        ExactChildIdentity
	Origin          Origin
	Status          Status
	DecidedByUserID *uuid.UUID
	DecidedAt       *time.Time
}

// Scope is an immutable-value model. InitialEvidence is retained even after a
// selected child ceases to be live; liveness is checked only at expansion.
type Scope struct {
	RuleID          uuid.UUID
	OrgID           uuid.UUID
	ClusterID       uuid.UUID
	InitialEvidence []InitialCandidateEvidence
	Memberships     []Membership
}

type CreateInput struct {
	RuleID          uuid.UUID
	OrgID           uuid.UUID
	ClusterID       uuid.UUID
	Feature         FeatureState
	Inventory       InventoryState
	CurrentChildren []ExactPortChild
	InitialChildIDs []uuid.UUID
	ActorUserID     uuid.UUID
	Now             time.Time
}

// Create snapshots every current candidate and approves only explicit initial
// selections. Zero selections is valid; no candidate is selected by default.
func Create(in CreateInput, limits Limits) (Scope, error) {
	if err := limits.validate(); err != nil {
		return Scope{}, err
	}
	if err := in.Feature.requireEnabled(); err != nil {
		return Scope{}, err
	}
	if err := in.Inventory.requireCurrent(); err != nil {
		return Scope{}, err
	}
	if in.RuleID == uuid.Nil || in.OrgID == uuid.Nil || in.ClusterID == uuid.Nil {
		return Scope{}, ErrInvalidScope
	}
	if in.ActorUserID == uuid.Nil {
		return Scope{}, ErrInvalidDecisionActor
	}
	if in.Now.IsZero() {
		return Scope{}, ErrInvalidDecisionTime
	}
	if len(in.CurrentChildren) > limits.MaxCurrentCandidates {
		return Scope{}, ErrCandidateLimitReached
	}
	if len(in.InitialChildIDs) > limits.MaxInitialSelections {
		return Scope{}, ErrSelectionLimitReached
	}
	if len(in.InitialChildIDs) > limits.MaxMemberships {
		return Scope{}, ErrMembershipLimitReached
	}

	candidates := make(map[uuid.UUID]ExactChildIdentity, len(in.CurrentChildren))
	exactIdentities := make(map[exactIdentityKey]struct{}, len(in.CurrentChildren))
	for _, child := range in.CurrentChildren {
		if err := validateEligibleChild(in.OrgID, in.ClusterID, child); err != nil {
			return Scope{}, err
		}
		if _, exists := candidates[child.Identity.ChildID]; exists {
			return Scope{}, ErrDuplicateChildID
		}
		key := identityKey(child.Identity)
		if _, exists := exactIdentities[key]; exists {
			return Scope{}, ErrDuplicateExactIdentity
		}
		candidates[child.Identity.ChildID] = child.Identity
		exactIdentities[key] = struct{}{}
	}

	selected := make(map[uuid.UUID]struct{}, len(in.InitialChildIDs))
	for _, childID := range in.InitialChildIDs {
		if childID == uuid.Nil {
			return Scope{}, ErrUnknownChildID
		}
		if _, duplicate := selected[childID]; duplicate {
			return Scope{}, ErrDuplicateChildID
		}
		if _, exists := candidates[childID]; !exists {
			return Scope{}, ErrUnknownChildID
		}
		selected[childID] = struct{}{}
	}

	actor := in.ActorUserID
	now := in.Now.UTC()
	out := Scope{
		RuleID:          in.RuleID,
		OrgID:           in.OrgID,
		ClusterID:       in.ClusterID,
		InitialEvidence: make([]InitialCandidateEvidence, 0, len(candidates)),
		Memberships:     make([]Membership, 0, len(selected)),
	}
	for childID, identity := range candidates {
		_, isSelected := selected[childID]
		out.InitialEvidence = append(out.InitialEvidence, InitialCandidateEvidence{Identity: identity, Selected: isSelected})
		if isSelected {
			out.Memberships = append(out.Memberships, Membership{
				RuleID: in.RuleID, Identity: identity, Origin: OriginInitial,
				Status: StatusApproved, DecidedByUserID: &actor, DecidedAt: &now,
			})
		}
	}
	sortEvidence(out.InitialEvidence)
	sortMemberships(out.Memberships)
	return out, nil
}

// AddLaterExposure appends exactly one pending membership. Any child present
// in the creation snapshot remains initial forever, including an initially
// unselected child; explicit inclusion of that child is outside S20.4.
func AddLaterExposure(scope Scope, child ExactPortChild, limits Limits) (Scope, error) {
	if err := validateScope(scope, limits); err != nil {
		return Scope{}, err
	}
	if err := validateEligibleChild(scope.OrgID, scope.ClusterID, child); err != nil {
		return Scope{}, err
	}
	if evidence, found := initialEvidence(scope.InitialEvidence, child.Identity.ChildID); found {
		if evidence.Identity != child.Identity {
			return Scope{}, ErrScopeMismatch
		}
		return Scope{}, ErrNotLaterExposure
	}
	if idx := membershipIndex(scope.Memberships, child.Identity.ChildID); idx >= 0 {
		if scope.Memberships[idx].Identity != child.Identity {
			return Scope{}, ErrScopeMismatch
		}
		return Scope{}, ErrDuplicateChildID
	}
	if len(scope.Memberships) >= limits.MaxMemberships {
		return Scope{}, ErrMembershipLimitReached
	}

	out := cloneScope(scope)
	out.Memberships = append(out.Memberships, Membership{
		RuleID: scope.RuleID, Identity: child.Identity, Origin: OriginLater, Status: StatusPending,
	})
	sortMemberships(out.Memberships)
	return out, nil
}

// DecisionResult tells a persistence/audit caller whether the transition
// changed state. Same-decision retries return Changed=false so no second audit
// is emitted; opposing retries remain conflicts.
type DecisionResult struct {
	Scope   Scope
	Changed bool
}

// Decide performs the only valid one-way transitions: pending to approved or
// pending to rejected. Actor and time are server inputs, not request metadata.
func Decide(scope Scope, child ExactPortChild, decision Status, feature FeatureState, actorUserID uuid.UUID, now time.Time, limits Limits) (DecisionResult, error) {
	if err := validateScope(scope, limits); err != nil {
		return DecisionResult{}, err
	}
	if err := feature.requireEnabled(); err != nil {
		return DecisionResult{}, err
	}
	if err := validateIdentity(scope.OrgID, scope.ClusterID, child.Identity); err != nil {
		return DecisionResult{}, err
	}
	switch decision {
	case StatusApproved, StatusRejected:
	case StatusPending:
		return DecisionResult{}, ErrInvalidDecision
	default:
		return DecisionResult{}, ErrUnknownStatus
	}
	if actorUserID == uuid.Nil {
		return DecisionResult{}, ErrInvalidDecisionActor
	}
	if now.IsZero() {
		return DecisionResult{}, ErrInvalidDecisionTime
	}

	idx := membershipIndex(scope.Memberships, child.Identity.ChildID)
	if idx < 0 {
		return DecisionResult{}, ErrUnknownChildID
	}
	if scope.Memberships[idx].Identity != child.Identity {
		return DecisionResult{}, ErrScopeMismatch
	}
	if scope.Memberships[idx].Status == decision {
		return DecisionResult{Scope: cloneScope(scope), Changed: false}, nil
	}
	if scope.Memberships[idx].Status != StatusPending {
		return DecisionResult{}, ErrInvalidDecision
	}
	if err := validateEligibleChild(scope.OrgID, scope.ClusterID, child); err != nil {
		return DecisionResult{}, err
	}

	out := cloneScope(scope)
	actor := actorUserID
	decidedAt := now.UTC()
	out.Memberships[idx].Status = decision
	out.Memberships[idx].DecidedByUserID = &actor
	out.Memberships[idx].DecidedAt = &decidedAt
	return DecisionResult{Scope: out, Changed: true}, nil
}

func validateScope(scope Scope, limits Limits) error {
	if err := limits.validate(); err != nil {
		return err
	}
	if scope.RuleID == uuid.Nil || scope.OrgID == uuid.Nil || scope.ClusterID == uuid.Nil {
		return ErrInvalidScope
	}
	if len(scope.InitialEvidence) > limits.MaxCurrentCandidates {
		return ErrCandidateLimitReached
	}
	if len(scope.Memberships) > limits.MaxMemberships {
		return ErrMembershipLimitReached
	}

	evidenceByID := make(map[uuid.UUID]InitialCandidateEvidence, len(scope.InitialEvidence))
	evidenceIdentities := make(map[exactIdentityKey]struct{}, len(scope.InitialEvidence))
	selectedEvidence := 0
	for _, evidence := range scope.InitialEvidence {
		if err := validateIdentity(scope.OrgID, scope.ClusterID, evidence.Identity); err != nil {
			return err
		}
		if _, duplicate := evidenceByID[evidence.Identity.ChildID]; duplicate {
			return ErrDuplicateChildID
		}
		key := identityKey(evidence.Identity)
		if _, duplicate := evidenceIdentities[key]; duplicate {
			return ErrDuplicateExactIdentity
		}
		evidenceByID[evidence.Identity.ChildID] = evidence
		evidenceIdentities[key] = struct{}{}
		if evidence.Selected {
			selectedEvidence++
		}
	}
	if selectedEvidence > limits.MaxInitialSelections {
		return ErrSelectionLimitReached
	}

	seenMembership := make(map[uuid.UUID]struct{}, len(scope.Memberships))
	membershipIdentities := make(map[exactIdentityKey]struct{}, len(scope.Memberships))
	for _, membership := range scope.Memberships {
		if membership.RuleID != scope.RuleID {
			return ErrScopeMismatch
		}
		if err := validateIdentity(scope.OrgID, scope.ClusterID, membership.Identity); err != nil {
			return err
		}
		if _, duplicate := seenMembership[membership.Identity.ChildID]; duplicate {
			return ErrDuplicateChildID
		}
		key := identityKey(membership.Identity)
		if _, duplicate := membershipIdentities[key]; duplicate {
			return ErrDuplicateExactIdentity
		}
		seenMembership[membership.Identity.ChildID] = struct{}{}
		membershipIdentities[key] = struct{}{}
		switch membership.Origin {
		case OriginInitial:
			evidence, exists := evidenceByID[membership.Identity.ChildID]
			if !exists || !evidence.Selected || evidence.Identity != membership.Identity || membership.Status != StatusApproved {
				return ErrInvalidScope
			}
		case OriginLater:
			if _, existedAtCreation := evidenceByID[membership.Identity.ChildID]; existedAtCreation {
				return ErrNotLaterExposure
			}
		default:
			return ErrUnknownOrigin
		}
		if err := validateStatusMetadata(membership); err != nil {
			return err
		}
	}
	return nil
}

func validateEligibleChild(orgID, clusterID uuid.UUID, child ExactPortChild) error {
	if err := validateIdentity(orgID, clusterID, child.Identity); err != nil {
		return err
	}
	if !child.Live {
		return ErrExposureNotLive
	}
	if !child.UIDAttributionCurrent {
		return ErrUIDAttributionNotCurrent
	}
	return nil
}

func validateIdentity(orgID, clusterID uuid.UUID, identity ExactChildIdentity) error {
	if identity.ChildID == uuid.Nil || identity.Namespace == "" || identity.ServiceUID == "" || identity.ServicePort < 1 || identity.ServicePort > 65535 {
		return ErrInvalidChildIdentity
	}
	if identity.OrgID != orgID || identity.ClusterID != clusterID {
		return ErrScopeMismatch
	}
	if identity.Protocol != ProtocolTCP && identity.Protocol != ProtocolUDP {
		return ErrInvalidChildIdentity
	}
	return nil
}

func validateStatusMetadata(m Membership) error {
	switch m.Status {
	case StatusPending:
		if m.DecidedByUserID != nil || m.DecidedAt != nil {
			return ErrInvalidStatusMetadata
		}
	case StatusApproved, StatusRejected:
		if m.DecidedByUserID == nil || *m.DecidedByUserID == uuid.Nil || m.DecidedAt == nil || m.DecidedAt.IsZero() {
			return ErrInvalidStatusMetadata
		}
	default:
		return ErrUnknownStatus
	}
	return nil
}

func cloneScope(scope Scope) Scope {
	out := scope
	out.InitialEvidence = append([]InitialCandidateEvidence(nil), scope.InitialEvidence...)
	out.Memberships = make([]Membership, len(scope.Memberships))
	for i, membership := range scope.Memberships {
		out.Memberships[i] = membership
		if membership.DecidedByUserID != nil {
			actor := *membership.DecidedByUserID
			out.Memberships[i].DecidedByUserID = &actor
		}
		if membership.DecidedAt != nil {
			at := *membership.DecidedAt
			out.Memberships[i].DecidedAt = &at
		}
	}
	sortEvidence(out.InitialEvidence)
	sortMemberships(out.Memberships)
	return out
}

func initialEvidence(evidence []InitialCandidateEvidence, childID uuid.UUID) (InitialCandidateEvidence, bool) {
	for _, item := range evidence {
		if item.Identity.ChildID == childID {
			return item, true
		}
	}
	return InitialCandidateEvidence{}, false
}

func membershipIndex(memberships []Membership, childID uuid.UUID) int {
	for i, membership := range memberships {
		if membership.Identity.ChildID == childID {
			return i
		}
	}
	return -1
}

func sortEvidence(evidence []InitialCandidateEvidence) {
	sort.Slice(evidence, func(i, j int) bool { return compareIdentity(evidence[i].Identity, evidence[j].Identity) < 0 })
}

func sortMemberships(memberships []Membership) {
	sort.Slice(memberships, func(i, j int) bool { return compareIdentity(memberships[i].Identity, memberships[j].Identity) < 0 })
}

func compareIdentity(a, b ExactChildIdentity) int {
	for _, pair := range [][2]string{
		{a.ClusterID.String(), b.ClusterID.String()},
		{a.Namespace, b.Namespace},
		{a.ServiceUID, b.ServiceUID},
		{string(a.Protocol), string(b.Protocol)},
	} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if a.ServicePort < b.ServicePort {
		return -1
	}
	if a.ServicePort > b.ServicePort {
		return 1
	}
	if a.ChildID.String() < b.ChildID.String() {
		return -1
	}
	if a.ChildID.String() > b.ChildID.String() {
		return 1
	}
	return 0
}

type exactIdentityKey struct {
	OrgID       uuid.UUID
	ClusterID   uuid.UUID
	Namespace   string
	ServiceUID  string
	Protocol    Protocol
	ServicePort int32
}

func identityKey(identity ExactChildIdentity) exactIdentityKey {
	return exactIdentityKey{
		OrgID: identity.OrgID, ClusterID: identity.ClusterID,
		Namespace: identity.Namespace, ServiceUID: identity.ServiceUID,
		Protocol: identity.Protocol, ServicePort: identity.ServicePort,
	}
}
