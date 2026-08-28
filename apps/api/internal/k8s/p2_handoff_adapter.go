package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// P2HandoffAttestationVersion is the applied-state contract version P1
// requires. Versions 1 and 2 are intentionally not convertible to handoff
// acknowledgements: neither binds the complete dataplane manifest and locally
// persisted CP lease expiry required by wire version 3.
const P2HandoffAttestationVersion = 3

// P2HandoffRole is the P2 delivery role for a P1 artifact. Withdrawal is
// deliberately distinct from P1's prepared_non_serving artifact role because
// it must attest removal of the old serving lease.
type P2HandoffRole string

const (
	P2HandoffPrepared   P2HandoffRole = "prepared_non_serving"
	P2HandoffWithdrawal P2HandoffRole = "withdrawal"
	P2HandoffServing    P2HandoffRole = "serving"
)

// P2HandoffArtifact identifies all immutable artifacts in a durable plan.
// OldServing is a provenance reference, not a transport action in this slice;
// it still has a deterministic operation/artifact identity so a future reader
// cannot confuse it with a candidate or withdrawal artifact.
type P2HandoffArtifact string

const (
	P2OldServingArtifact    P2HandoffArtifact = "old_serving"
	P2NewPreparedArtifact   P2HandoffArtifact = "new_prepared"
	P2OldWithdrawalArtifact P2HandoffArtifact = "old_withdrawal"
	P2NewServingArtifact    P2HandoffArtifact = "new_serving"
)

// P2HandoffDeliveryIdentity is the complete operation-keyed lookup and
// idempotency identity P1 expects P2 to preserve. ManifestIdentity remains
// opaque: P2 owns its digest representation, while P1 compares the already
// CP-validated value byte-for-byte.
type P2HandoffDeliveryIdentity struct {
	Version             int
	OrgID               uuid.UUID
	SiteID              uuid.UUID
	ClusterID           uuid.UUID
	PoolID              uuid.UUID
	ConnectorNodeID     uuid.UUID
	TargetNodeID        uuid.UUID
	OperationID         uuid.UUID
	ManifestIdentity    string
	Role                P2HandoffRole
	PromotionGeneration uint64
	ManifestRevision    uint64
	LeaseEpoch          uint64
	PriorLeaseEpoch     uint64
	// Expected digests are opaque P2-v3 provenance. They are included in the
	// operation-keyed identity so a retry cannot silently widen an artifact.
	ExpectedRouteDigest  string
	ExpectedVIPMapDigest string
	DeliveryPhase        string
	DeliveryID           uuid.UUID
}

// P2HandoffDelivery is an issuance request for P2. P1 never creates the wire
// manifest, applies it, or mints a nonce; P2 must retain its own nonce under
// this DeliveryID, persist this exact identity as one idempotent delivery, and
// bind it to the supplied leader session.
type P2HandoffDelivery struct {
	Identity       P2HandoffDeliveryIdentity
	LeaseExpiresAt time.Time
}

// P2HandoffDeliveryIssuer is the only outbound dependency. An implementation
// must issue through LeaderConn, the same leader session represented by Epoch;
// it must reject a stale session and accept a retry only when every field for
// DeliveryID is exact. This P1 package supplies no HTTP, database, or agent
// implementation.
type P2HandoffDeliveryIssuer interface {
	IssueP2HandoffDelivery(context.Context, HandoffLeadershipEpoch, *pgxpool.Conn, P2HandoffDelivery) error
}

// P2HandoffAppliedAttestation is P2's narrow, exact read model for a v3 agent
// apply/read-back acknowledgement. CPReceiptAt is CP-recorded. There is no
// agent-observed timestamp because it cannot establish freshness or eligibility.
type P2HandoffAppliedAttestation struct {
	Version           int
	Identity          P2HandoffDeliveryIdentity
	CPReceiptAt       time.Time
	DeliveryExpiresAt time.Time

	AppliedRole                P2HandoffRole
	AppliedManifestIdentity    string
	AppliedPromotionGeneration uint64
	AppliedManifestRevision    uint64
	AppliedLeaseEpoch          uint64
	// Applied digests are validated P2 read-back evidence, never a P1-derived
	// digest or an agent receipt-only claim.
	AppliedRouteDigest  string
	AppliedVIPMapDigest string
}

// P2HandoffAttestationReader looks up exactly one operation/artifact delivery.
// A receipt-only v1 projection does not satisfy this interface and therefore
// cannot accidentally advance a P1 handoff phase.
type P2HandoffAttestationReader interface {
	LoadP2HandoffAppliedAttestation(context.Context, P2HandoffDeliveryIdentity) (P2HandoffAppliedAttestation, bool, error)
}

// P2HandoffLeaderBoundAttestationReader is the scheduler-only applied-state
// reader. The exact advisory-lock-holding session is part of every read, so a
// pooled read made after leadership loss cannot be mistaken for phase
// authority. The unbound method remains for bootstrap/compatibility callers.
type P2HandoffLeaderBoundAttestationReader interface {
	P2HandoffAttestationReader
	LoadP2HandoffAppliedAttestationWithLeadership(context.Context, HandoffLeadershipEpoch, *pgxpool.Conn, P2HandoffDeliveryIdentity) (P2HandoffAppliedAttestation, bool, error)
}

// P2HandoffAcknowledgements is the only conversion output P1 needs to pass to
// its existing coordinator. Nil means P2 has no usable exact v3 attestation;
// it never means ready, serving, or eligible by itself.
type P2HandoffAcknowledgements struct {
	Prepared   *ArtifactAcknowledgement
	Withdrawal *ArtifactAcknowledgement
	Serving    *ArtifactAcknowledgement
}

var (
	ErrP2HandoffLeaderUnavailable = errors.New("P2 handoff issuance lacks a valid leader session")
	ErrP2HandoffAttestation       = errors.New("P2 handoff attestation is not an exact valid v3 applied state")
)

// P2HandoffAdapter is intentionally an unregistered transport and read
// adapter. It does not run a scheduler or modify a handoff operation; a future
// composition root must explicitly give it to the existing coordinator.
type P2HandoffAdapter struct {
	issuer P2HandoffDeliveryIssuer
	reader P2HandoffAttestationReader
	now    func() time.Time
}

var _ HandoffTransport = (*P2HandoffAdapter)(nil)

func NewP2HandoffAdapter(issuer P2HandoffDeliveryIssuer, reader P2HandoffAttestationReader) *P2HandoffAdapter {
	return &P2HandoffAdapter{issuer: issuer, reader: reader, now: time.Now}
}

func (a *P2HandoffAdapter) PrepareCandidate(ctx context.Context, delivery HandoffDelivery) error {
	return a.issue(ctx, delivery, P2HandoffPrepared)
}

func (a *P2HandoffAdapter) WithdrawOld(ctx context.Context, delivery HandoffDelivery) error {
	return a.issue(ctx, delivery, P2HandoffWithdrawal)
}

func (a *P2HandoffAdapter) EnableNew(ctx context.Context, delivery HandoffDelivery) error {
	return a.issue(ctx, delivery, P2HandoffServing)
}

func (a *P2HandoffAdapter) issue(ctx context.Context, delivery HandoffDelivery, role P2HandoffRole) error {
	if a == nil || a.issuer == nil || a.now == nil || !delivery.LeadershipEpoch.valid() || delivery.LeaderConn == nil {
		return ErrP2HandoffLeaderUnavailable
	}
	p2Delivery, err := p2HandoffDeliveryFromHandoffDelivery(delivery, role)
	if err != nil {
		return err
	}
	if !p2Delivery.LeaseExpiresAt.After(a.now().UTC()) {
		return fmt.Errorf("%w: delivery lease is expired", ErrP2HandoffAttestation)
	}
	return a.issuer.IssueP2HandoffDelivery(ctx, delivery.LeadershipEpoch, delivery.LeaderConn, p2Delivery)
}

// P2HandoffDeliveryForPlanArtifact maps every immutable plan artifact to one
// deterministic P2 identity. The returned value does not issue anything; only
// NewPrepared, OldWithdrawal, and NewServing correspond to coordinator
// transport actions. OldServing remains a reference for withdrawal provenance.
func P2HandoffDeliveryForPlanArtifact(plan DurableHandoffPlan, which P2HandoffArtifact) (P2HandoffDelivery, error) {
	if err := ValidateDurableHandoffPlan(plan); err != nil {
		return P2HandoffDelivery{}, err
	}
	p := plan.Plan
	var artifact ArtifactPrerequisite
	var role P2HandoffRole
	var priorLease uint64
	switch which {
	case P2OldServingArtifact:
		artifact, role = p.OldServing, P2HandoffServing
	case P2NewPreparedArtifact:
		artifact, role = p.NewPrepared, P2HandoffPrepared
	case P2OldWithdrawalArtifact:
		artifact, role, priorLease = p.OldWithdrawal, P2HandoffWithdrawal, p.OldServing.Lease.Epoch
	case P2NewServingArtifact:
		artifact, role = p.NewServing, P2HandoffServing
	default:
		return P2HandoffDelivery{}, fmt.Errorf("unknown P2 handoff artifact %q", which)
	}
	return p2HandoffDelivery(plan.Plan.OperationID, plan.Plan.Scope, artifact, role, priorLease)
}

// AcknowledgementsForPhase reads only the one exact v3 applied-state
// attestation that the durable phase can consume. In particular, a serving
// attestation is not even surfaced before the post-CAS await-serving phase;
// it therefore cannot bypass the old-owner withdrawal boundary. A malformed,
// replayed, expired, wrong-scope, or v1 value is an error rather than an empty
// acknowledgement, so a caller cannot silently convert it to phase progress.
func (a *P2HandoffAdapter) AcknowledgementsForPhase(ctx context.Context, plan DurableHandoffPlan, phase HandoffPhase, now time.Time, maxAckAge time.Duration) (P2HandoffAcknowledgements, error) {
	if a == nil || a.reader == nil || now.IsZero() || maxAckAge <= 0 {
		return P2HandoffAcknowledgements{}, fmt.Errorf("%w: reader, CP time, and acknowledgement age are required", ErrP2HandoffAttestation)
	}
	return a.acknowledgementsForPhase(ctx, plan, phase, now, maxAckAge, a.reader.LoadP2HandoffAppliedAttestation)
}

// AcknowledgementsForPhaseWithLeadership is the production scheduler read.
// It deliberately has no fallback to the generic reader: missing support or a
// stale leader session is a hard refusal, while v1/v2 remain readable only by
// their existing compatibility paths and can never become a v3 phase ACK.
func (a *P2HandoffAdapter) AcknowledgementsForPhaseWithLeadership(ctx context.Context, plan DurableHandoffPlan, phase HandoffPhase, now time.Time, maxAckAge time.Duration, epoch HandoffLeadershipEpoch, conn *pgxpool.Conn) (P2HandoffAcknowledgements, error) {
	var reader P2HandoffLeaderBoundAttestationReader
	var ok bool
	if a != nil {
		reader, ok = a.reader.(P2HandoffLeaderBoundAttestationReader)
	}
	if !ok || reader == nil || !epoch.valid() || conn == nil || now.IsZero() || maxAckAge <= 0 {
		return P2HandoffAcknowledgements{}, fmt.Errorf("%w: leader-bound reader, session, CP time, and acknowledgement age are required", ErrP2HandoffAttestation)
	}
	return a.acknowledgementsForPhase(ctx, plan, phase, now, maxAckAge, func(ctx context.Context, identity P2HandoffDeliveryIdentity) (P2HandoffAppliedAttestation, bool, error) {
		return reader.LoadP2HandoffAppliedAttestationWithLeadership(ctx, epoch, conn, identity)
	})
}

type p2HandoffAttestationLoad func(context.Context, P2HandoffDeliveryIdentity) (P2HandoffAppliedAttestation, bool, error)

func (a *P2HandoffAdapter) acknowledgementsForPhase(ctx context.Context, plan DurableHandoffPlan, phase HandoffPhase, now time.Time, maxAckAge time.Duration, load p2HandoffAttestationLoad) (P2HandoffAcknowledgements, error) {
	var out P2HandoffAcknowledgements
	var which P2HandoffArtifact
	var set func(*ArtifactAcknowledgement)
	switch phase {
	case HandoffAwaitPreparedAck:
		which, set = P2NewPreparedArtifact, func(ack *ArtifactAcknowledgement) { out.Prepared = ack }
	case HandoffAwaitWithdrawal, HandoffCASActive:
		which, set = P2OldWithdrawalArtifact, func(ack *ArtifactAcknowledgement) { out.Withdrawal = ack }
	case HandoffAwaitServingAck:
		which, set = P2NewServingArtifact, func(ack *ArtifactAcknowledgement) { out.Serving = ack }
	default:
		return out, nil
	}
	delivery, err := P2HandoffDeliveryForPlanArtifact(plan, which)
	if err != nil {
		return P2HandoffAcknowledgements{}, err
	}
	attestation, found, err := load(ctx, delivery.Identity)
	if err != nil {
		return P2HandoffAcknowledgements{}, err
	}
	if !found {
		return out, nil
	}
	ack, err := p2AttestationAcknowledgement(delivery, attestation, now, maxAckAge)
	if err != nil {
		return P2HandoffAcknowledgements{}, err
	}
	set(&ack)
	return out, nil
}

func p2HandoffDeliveryFromHandoffDelivery(delivery HandoffDelivery, role P2HandoffRole) (P2HandoffDelivery, error) {
	if delivery.OperationID == uuid.Nil || !delivery.Scope.valid() || !delivery.Artifact.valid() ||
		delivery.Artifact.Scope.OrgID != delivery.Scope.OrgID || delivery.Artifact.Scope.SiteID != delivery.Scope.SiteID ||
		delivery.Artifact.Scope.PoolID != delivery.Scope.PoolID || delivery.Artifact.Scope.ClusterID != delivery.Scope.ClusterID {
		return P2HandoffDelivery{}, fmt.Errorf("%w: handoff delivery scope or artifact provenance is invalid", ErrP2HandoffAttestation)
	}
	if !handoffDeliveryRoleMatchesArtifact(role, delivery.Artifact, delivery.PriorLeaseEpoch) {
		return P2HandoffDelivery{}, fmt.Errorf("%w: handoff delivery role and lease provenance conflict", ErrP2HandoffAttestation)
	}
	return p2HandoffDelivery(delivery.OperationID, delivery.Scope, delivery.Artifact, role, delivery.PriorLeaseEpoch)
}

func p2HandoffDelivery(operationID uuid.UUID, scope HandoffPoolScope, artifact ArtifactPrerequisite, role P2HandoffRole, priorLease uint64) (P2HandoffDelivery, error) {
	if operationID == uuid.Nil || !scope.valid() || !artifact.valid() ||
		artifact.Scope.OrgID != scope.OrgID || artifact.Scope.SiteID != scope.SiteID || artifact.Scope.PoolID != scope.PoolID || artifact.Scope.ClusterID != scope.ClusterID ||
		!handoffDeliveryRoleMatchesArtifact(role, artifact, priorLease) {
		return P2HandoffDelivery{}, fmt.Errorf("%w: operation, role, scope, or CP artifact provenance is invalid", ErrP2HandoffAttestation)
	}
	identity := P2HandoffDeliveryIdentity{Version: P2HandoffAttestationVersion, OrgID: scope.OrgID, SiteID: scope.SiteID, ClusterID: scope.ClusterID, PoolID: scope.PoolID,
		ConnectorNodeID: artifact.Scope.ConnectorID, TargetNodeID: artifact.Scope.ConnectorID, OperationID: operationID, ManifestIdentity: artifact.ManifestIdentity,
		Role: role, PromotionGeneration: artifact.PromotionGeneration, ManifestRevision: artifact.ManifestRevision, LeaseEpoch: artifact.Lease.Epoch, PriorLeaseEpoch: priorLease,
		ExpectedRouteDigest: artifact.ExpectedRouteDigest, ExpectedVIPMapDigest: artifact.ExpectedVIPMapDigest, DeliveryPhase: p2HandoffDeliveryPhase(role)}
	identity.DeliveryID = stableP2HandoffDeliveryID(identity)
	return P2HandoffDelivery{Identity: identity, LeaseExpiresAt: artifact.Lease.ExpiresAt.UTC()}, nil
}

func handoffDeliveryRoleMatchesArtifact(role P2HandoffRole, artifact ArtifactPrerequisite, priorLease uint64) bool {
	switch role {
	case P2HandoffPrepared:
		return artifact.Role == PreparedNonServing && priorLease == 0 && artifact.ExpectedRouteDigest == P2HandoffCanonicalEmptyRouteDigest && artifact.ExpectedVIPMapDigest == ""
	case P2HandoffWithdrawal:
		return artifact.Role == PreparedNonServing && priorLease > 0 && priorLease < artifact.Lease.Epoch && artifact.ExpectedRouteDigest == P2HandoffCanonicalEmptyRouteDigest && artifact.ExpectedVIPMapDigest == ""
	case P2HandoffServing:
		return artifact.Role == Serving && priorLease == 0 && validP2Digest(artifact.ExpectedRouteDigest) && validP2Digest(artifact.ExpectedVIPMapDigest)
	default:
		return false
	}
}

func stableP2HandoffDeliveryID(identity P2HandoffDeliveryIdentity) uuid.UUID {
	// JSON escaping keeps opaque manifest identity bytes unambiguous; a
	// delimiter-based name would let an embedded delimiter collide with a
	// different field sequence. DeliveryID is excluded by construction.
	identity.DeliveryID = uuid.Nil
	name, _ := json.Marshal(struct {
		Domain   string                    `json:"domain"`
		Identity P2HandoffDeliveryIdentity `json:"identity"`
	}{Domain: "tunnex.p1-p2-handoff-delivery/v3", Identity: identity})
	return uuid.NewSHA1(uuid.NameSpaceOID, name)
}

func p2HandoffDeliveryPhase(role P2HandoffRole) string {
	switch role {
	case P2HandoffPrepared:
		return "prepare"
	case P2HandoffWithdrawal:
		return "withdraw"
	case P2HandoffServing:
		return "serve"
	default:
		return ""
	}
}

func p2AttestationAcknowledgement(expected P2HandoffDelivery, got P2HandoffAppliedAttestation, now time.Time, maxAge time.Duration) (ArtifactAcknowledgement, error) {
	if got.Version != P2HandoffAttestationVersion || got.Identity != expected.Identity || got.CPReceiptAt.IsZero() || got.DeliveryExpiresAt.IsZero() ||
		!got.DeliveryExpiresAt.Equal(expected.LeaseExpiresAt) || !got.CPReceiptAt.Before(got.DeliveryExpiresAt) || !nowReceiptFresh(now, got.CPReceiptAt, maxAge) || !got.DeliveryExpiresAt.After(now) ||
		got.AppliedRole != expected.Identity.Role || got.AppliedManifestIdentity != expected.Identity.ManifestIdentity ||
		got.AppliedPromotionGeneration != expected.Identity.PromotionGeneration || got.AppliedManifestRevision != expected.Identity.ManifestRevision ||
		got.AppliedLeaseEpoch != expectedAppliedLeaseEpoch(expected.Identity) || got.AppliedRouteDigest != expected.Identity.ExpectedRouteDigest ||
		got.AppliedVIPMapDigest != expected.Identity.ExpectedVIPMapDigest || !p2IdentityDigestsValid(expected.Identity) {
		return ArtifactAcknowledgement{}, ErrP2HandoffAttestation
	}
	ack := ArtifactAcknowledgement{Artifact: artifactFromP2Identity(expected.Identity, expected.LeaseExpiresAt), ReceiptAt: got.CPReceiptAt.UTC()}
	switch expected.Identity.Role {
	case P2HandoffPrepared:
		ack.NonServingAttested = true
	case P2HandoffWithdrawal:
		ack.NonServingAttested = true
		ack.WithdrawalLeaseEpoch = expected.Identity.PriorLeaseEpoch
	case P2HandoffServing:
		ack.ServingAttested = true
	default:
		return ArtifactAcknowledgement{}, ErrP2HandoffAttestation
	}
	return ack, nil
}

func expectedAppliedLeaseEpoch(identity P2HandoffDeliveryIdentity) uint64 {
	if identity.Role == P2HandoffWithdrawal {
		return identity.PriorLeaseEpoch
	}
	return identity.LeaseEpoch
}

func artifactFromP2Identity(identity P2HandoffDeliveryIdentity, expiresAt time.Time) ArtifactPrerequisite {
	role := Serving
	if identity.Role == P2HandoffPrepared || identity.Role == P2HandoffWithdrawal {
		role = PreparedNonServing
	}
	return ArtifactPrerequisite{Scope: OwnershipScope{OrgID: identity.OrgID, SiteID: identity.SiteID, PoolID: identity.PoolID, ClusterID: identity.ClusterID, ConnectorID: identity.ConnectorNodeID},
		PromotionGeneration: identity.PromotionGeneration, ManifestRevision: identity.ManifestRevision, ManifestIdentity: identity.ManifestIdentity,
		ExpectedRouteDigest: identity.ExpectedRouteDigest, ExpectedVIPMapDigest: identity.ExpectedVIPMapDigest, IdentityValidated: true,
		Lease: CPOwnershipLease{Epoch: identity.LeaseEpoch, ExpiresAt: expiresAt.UTC(), CPIssuedValidated: true}, Role: role}
}

func p2IdentityDigestsValid(identity P2HandoffDeliveryIdentity) bool {
	switch identity.Role {
	case P2HandoffPrepared, P2HandoffWithdrawal:
		return identity.ExpectedRouteDigest == P2HandoffCanonicalEmptyRouteDigest && identity.ExpectedVIPMapDigest == ""
	case P2HandoffServing:
		return validP2Digest(identity.ExpectedRouteDigest) && validP2Digest(identity.ExpectedVIPMapDigest)
	default:
		return false
	}
}
