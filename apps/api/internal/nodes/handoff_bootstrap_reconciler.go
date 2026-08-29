package nodes

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

// HandoffFencedBasePrerequisite is deliberately a closed typed token. A bool
// or a legacy desired-state success cannot be converted into scheduler
// eligibility accidentally.
type HandoffFencedBasePrerequisite string

const HandoffFencedBaseReady HandoffFencedBasePrerequisite = "fenced-base-ready"

type HandoffBootstrapState string

const (
	HandoffBootstrapDisabled HandoffBootstrapState = "disabled"
	HandoffBootstrapPending  HandoffBootstrapState = "pending"
	HandoffBootstrapReady    HandoffBootstrapState = "ready"
)

var ErrHandoffBootstrapLeaderSession = errors.New("handoff bootstrap exact leader session is unavailable")

// HandoffBootstrapPlan is P2-produced immutable v3 intent for the current
// owner and every presently eligible standby. The reconciler never creates a
// manifest from desired-state success or fills an omitted standby itself.
type HandoffBootstrapPlan struct {
	Scope               k8s.HandoffPoolScope
	Generation          uint64
	ActiveNodeID        uuid.UUID
	EligibleStandbyIDs  []uuid.UUID
	CurrentOwnerServing k8s.P2HandoffDelivery
	StandbyPrepared     []k8s.P2HandoffDelivery
	// Full v3 envelopes are the only issue authority. The P2 projections above
	// are retained solely for exact ACK comparison and never used to recreate a
	// manifest.
	CurrentOwnerEnvelope PoolVIPOwnershipDeliveryEnvelopeV3
	StandbyEnvelopes     []PoolVIPOwnershipDeliveryEnvelopeV3
	ServiceUIDs          []HandoffBootstrapServiceUID
}

type HandoffBootstrapPlanSource interface {
	LoadHandoffBootstrapPlanWithLeadership(context.Context, time.Time, k8s.HandoffPoolScope, k8s.HandoffLeadershipEpoch, *pgxpool.Conn) (HandoffBootstrapPlan, bool, error)
}

type HandoffBootstrapEnvelopeIssuer interface {
	IssueHandoffBootstrapEnvelopeWithLeadership(context.Context, k8s.HandoffLeadershipEpoch, *pgxpool.Conn, PoolVIPOwnershipDeliveryEnvelopeV3) error
}

type HandoffBootstrapLeaderAttestationReader interface {
	LoadP2HandoffAppliedAttestationWithLeadership(context.Context, k8s.HandoffLeadershipEpoch, *pgxpool.Conn, k8s.P2HandoffDeliveryIdentity) (k8s.P2HandoffAppliedAttestation, bool, error)
}

// HandoffOwnershipModeTransition is intentionally external to P2. Even a
// completely acknowledged fenced base remains scheduler-ineligible until P3
// confirms its explicit ownership-mode transition on the same leader session.
type HandoffOwnershipModeTransition interface {
	// ArmHandoffOwnershipBaseWithLeadership issues (or replays) the exact
	// ordinary-base authority for every named member and returns ready only
	// after every durable exact arm receipt exists. P2 envelopes must not be
	// issued before this returns true.
	ArmHandoffOwnershipBaseWithLeadership(context.Context, time.Time, k8s.HandoffLeadershipEpoch, *pgxpool.Conn, HandoffBootstrapPlan) (HandoffBaseAuthorityArmSnapshot, bool, error)
	// ConfirmHandoffOwnershipModeTransitionWithLeadership re-locks the complete
	// bootstrap snapshot after all P2 ACKs have been observed and atomically
	// records actual fenced_ha on this same leader session.
	ConfirmHandoffOwnershipModeTransitionWithLeadership(context.Context, time.Time, k8s.HandoffLeadershipEpoch, *pgxpool.Conn, HandoffBootstrapPlan, HandoffBaseAuthorityArmSnapshot) (HandoffFencedBasePrerequisite, error)
}

// HandoffBaseAuthorityArmSnapshot is the exact durable authority evidence read
// in this reconcile. It is carried into the final transaction so a newer or
// different base delivery cannot be substituted between the arm and P2 ACK
// phases. A restarted process reconstructs it from the durable ledger.
type HandoffBaseAuthorityArmSnapshot struct {
	TransitionRevision uint64
	MembershipEpoch    uint64
	Members            []HandoffBaseAuthorityArmMember
}

type HandoffBaseAuthorityArmMember struct {
	NodeID            uuid.UUID
	AuthorityRevision uint64
	BaseVersion       uint64
	BaseHash          string
	PayloadDigest     string
}

type HandoffBootstrapConfig struct {
	Enabled   bool
	MaxAckAge time.Duration
	Scope     k8s.HandoffPoolScope
}

type HandoffBootstrapResult struct {
	State            HandoffBootstrapState
	Prerequisite     HandoffFencedBasePrerequisite
	RequiredStandbys int
	PreparedStandbys int
}

// HandoffBootstrapReconciler owns no loop. Its only active entrypoint requires
// the caller-held advisory-lock session and is safe to replay after restart:
// exact delivery IDs are idempotent and exact CP receipts are durable in the
// existing v3 ledger. It never mutates pool generation or active membership.
type HandoffBootstrapReconciler struct {
	config     HandoffBootstrapConfig
	source     HandoffBootstrapPlanSource
	issuer     HandoffBootstrapEnvelopeIssuer
	reader     HandoffBootstrapLeaderAttestationReader
	transition HandoffOwnershipModeTransition
}

func NewHandoffBootstrapReconciler(config HandoffBootstrapConfig, source HandoffBootstrapPlanSource, issuer HandoffBootstrapEnvelopeIssuer, reader HandoffBootstrapLeaderAttestationReader, transition HandoffOwnershipModeTransition) *HandoffBootstrapReconciler {
	return &HandoffBootstrapReconciler{config: config, source: source, issuer: issuer, reader: reader, transition: transition}
}

func (r *HandoffBootstrapReconciler) ReconcileWithLeadership(ctx context.Context, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (HandoffBootstrapResult, error) {
	if r == nil || !r.config.Enabled {
		return HandoffBootstrapResult{State: HandoffBootstrapDisabled}, nil
	}
	if ctx == nil || now.IsZero() || r.config.MaxAckAge <= 0 || conn == nil || epoch.BackendPID <= 0 || epoch.LockKey != leader.SchedulerLockKey ||
		!handoffActivationDependencyPresent(r.source) || !handoffActivationDependencyPresent(r.issuer) || !handoffActivationDependencyPresent(r.reader) {
		return HandoffBootstrapResult{State: HandoffBootstrapPending}, ErrHandoffBootstrapLeaderSession
	}
	plan, found, err := r.source.LoadHandoffBootstrapPlanWithLeadership(ctx, now.UTC(), r.config.Scope, epoch, conn)
	if err != nil || !found {
		return HandoffBootstrapResult{State: HandoffBootstrapPending}, err
	}
	if plan.Scope != r.config.Scope || !validHandoffBootstrapPlan(plan, now.UTC()) {
		return HandoffBootstrapResult{State: HandoffBootstrapPending}, nil
	}
	result := HandoffBootstrapResult{State: HandoffBootstrapPending, RequiredStandbys: len(plan.EligibleStandbyIDs)}
	if !handoffActivationDependencyPresent(r.transition) {
		return result, nil
	}
	baseSnapshot, baseReady, err := r.transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now.UTC(), epoch, conn, plan)
	if err != nil || !baseReady {
		return result, err
	}
	deliveries := make([]k8s.P2HandoffDelivery, 0, 1+len(plan.StandbyPrepared))
	deliveries = append(deliveries, plan.CurrentOwnerServing)
	deliveries = append(deliveries, plan.StandbyPrepared...)
	envelopes := make([]PoolVIPOwnershipDeliveryEnvelopeV3, 0, 1+len(plan.StandbyEnvelopes))
	envelopes = append(envelopes, plan.CurrentOwnerEnvelope)
	envelopes = append(envelopes, plan.StandbyEnvelopes...)
	for _, envelope := range envelopes {
		if err := r.issuer.IssueHandoffBootstrapEnvelopeWithLeadership(ctx, epoch, conn, envelope); err != nil {
			return result, err
		}
	}
	for i, delivery := range deliveries {
		attestation, found, err := r.reader.LoadP2HandoffAppliedAttestationWithLeadership(ctx, epoch, conn, delivery.Identity)
		if err != nil {
			return result, err
		}
		if !found || !exactBootstrapAttestation(now.UTC(), r.config.MaxAckAge, delivery, attestation) {
			return result, nil
		}
		if i > 0 {
			result.PreparedStandbys++
		}
	}
	prerequisite, err := r.transition.ConfirmHandoffOwnershipModeTransitionWithLeadership(ctx, now.UTC(), epoch, conn, plan, baseSnapshot)
	if err != nil {
		return result, err
	}
	if prerequisite != HandoffFencedBaseReady {
		return result, nil
	}
	result.State, result.Prerequisite = HandoffBootstrapReady, HandoffFencedBaseReady
	return result, nil
}

func validHandoffBootstrapPlan(plan HandoffBootstrapPlan, now time.Time) bool {
	if plan.Generation == 0 || plan.ActiveNodeID == uuid.Nil || len(plan.EligibleStandbyIDs) == 0 || !bootstrapDeliveryMatches(plan.CurrentOwnerServing, plan, plan.ActiveNodeID, k8s.P2HandoffServing, now) ||
		len(plan.StandbyPrepared) != len(plan.EligibleStandbyIDs) || len(plan.StandbyEnvelopes) != len(plan.EligibleStandbyIDs) ||
		!bootstrapEnvelopeMatchesDelivery(plan.CurrentOwnerEnvelope, plan.CurrentOwnerServing) || !validHandoffBootstrapServiceUIDs(plan) {
		return false
	}
	want := make(map[uuid.UUID]struct{}, len(plan.EligibleStandbyIDs))
	for _, id := range plan.EligibleStandbyIDs {
		if id == uuid.Nil || id == plan.ActiveNodeID {
			return false
		}
		if _, duplicate := want[id]; duplicate {
			return false
		}
		want[id] = struct{}{}
	}
	seen := make(map[uuid.UUID]struct{}, len(plan.StandbyPrepared))
	for index, delivery := range plan.StandbyPrepared {
		id := delivery.Identity.TargetNodeID
		if _, eligible := want[id]; !eligible {
			return false
		}
		if _, duplicate := seen[id]; duplicate || !bootstrapDeliveryMatches(delivery, plan, id, k8s.P2HandoffPrepared, now) ||
			!bootstrapEnvelopeMatchesDelivery(plan.StandbyEnvelopes[index], delivery) {
			return false
		}
		seen[id] = struct{}{}
	}
	return len(seen) == len(want)
}

func bootstrapEnvelopeMatchesDelivery(envelope PoolVIPOwnershipDeliveryEnvelopeV3, delivery k8s.P2HandoffDelivery) bool {
	if ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope) != nil || !envelope.ExpiresAt.Equal(delivery.LeaseExpiresAt) {
		return false
	}
	artifact, err := poolVIPOwnershipHandoffArtifactFromP2Identity(delivery.Identity)
	return err == nil && poolVIPOwnershipHandoffArtifact(envelope) == artifact
}

func validHandoffBootstrapServiceUIDs(plan HandoffBootstrapPlan) bool {
	services := make(map[string]struct{}, len(plan.CurrentOwnerEnvelope.Manifest.Services))
	for _, service := range plan.CurrentOwnerEnvelope.Manifest.Services {
		services[service.Namespace+"\x00"+service.Service] = struct{}{}
	}
	if len(services) == 0 || len(plan.ServiceUIDs) != len(services) {
		return false
	}
	seen := make(map[string]struct{}, len(plan.ServiceUIDs))
	for _, value := range plan.ServiceUIDs {
		key := value.Namespace + "\x00" + value.Service
		if !validK8sServiceUIDDNSLabel(value.Namespace) || !validK8sServiceUIDDNSLabel(value.Service) || !validOpaqueK8sServiceUID(value.UID) ||
			value.ObservationRevision == 0 || value.ActiveNodeID != plan.ActiveNodeID || value.PromotionGeneration != plan.Generation {
			return false
		}
		if _, ok := services[key]; !ok {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return len(seen) == len(services)
}

func bootstrapDeliveryMatches(delivery k8s.P2HandoffDelivery, plan HandoffBootstrapPlan, nodeID uuid.UUID, role k8s.P2HandoffRole, now time.Time) bool {
	i := delivery.Identity
	wantPhase := "serve"
	digestsValid := poolVIPOwnershipIdentityHexRE.MatchString(i.ManifestIdentity) && poolVIPOwnershipIdentityHexRE.MatchString(i.ExpectedRouteDigest) &&
		poolVIPOwnershipIdentityHexRE.MatchString(i.ExpectedVIPMapDigest)
	if role == k8s.P2HandoffPrepared {
		wantPhase = "prepare"
		digestsValid = poolVIPOwnershipIdentityHexRE.MatchString(i.ManifestIdentity) && i.ExpectedRouteDigest == k8s.P2HandoffCanonicalEmptyRouteDigest && i.ExpectedVIPMapDigest == ""
	}
	return i.Version == k8s.P2HandoffAttestationVersion && plan.Scope.OrgID != uuid.Nil && plan.Scope.SiteID != uuid.Nil && plan.Scope.PoolID != uuid.Nil && plan.Scope.ClusterID != uuid.Nil &&
		i.OrgID == plan.Scope.OrgID && i.SiteID == plan.Scope.SiteID && i.PoolID == plan.Scope.PoolID && i.ClusterID == plan.Scope.ClusterID &&
		i.ConnectorNodeID == nodeID && i.TargetNodeID == nodeID && i.OperationID != uuid.Nil && i.DeliveryID != uuid.Nil &&
		i.Role == role && i.DeliveryPhase == wantPhase && i.PromotionGeneration == plan.Generation && i.ManifestRevision > 0 && i.LeaseEpoch > 0 &&
		i.PriorLeaseEpoch == 0 && digestsValid && !delivery.LeaseExpiresAt.IsZero() && delivery.LeaseExpiresAt.Location() == time.UTC && delivery.LeaseExpiresAt.After(now)
}

func exactBootstrapAttestation(now time.Time, maxAge time.Duration, delivery k8s.P2HandoffDelivery, got k8s.P2HandoffAppliedAttestation) bool {
	i := delivery.Identity
	return got.Version == k8s.P2HandoffAttestationVersion && got.Identity == i && got.AppliedRole == i.Role &&
		got.AppliedManifestIdentity == i.ManifestIdentity && got.AppliedPromotionGeneration == i.PromotionGeneration &&
		got.AppliedManifestRevision == i.ManifestRevision && got.AppliedLeaseEpoch == i.LeaseEpoch &&
		got.AppliedRouteDigest == i.ExpectedRouteDigest && got.AppliedVIPMapDigest == i.ExpectedVIPMapDigest &&
		got.DeliveryExpiresAt.Equal(delivery.LeaseExpiresAt) && got.DeliveryExpiresAt.After(now) &&
		!got.CPReceiptAt.IsZero() && !got.CPReceiptAt.After(now) && got.CPReceiptAt.Before(got.DeliveryExpiresAt) && now.Sub(got.CPReceiptAt) < maxAge
}

func canonicalBootstrapStandbys(ids []uuid.UUID) []uuid.UUID {
	out := append([]uuid.UUID(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
