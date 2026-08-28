package nodes

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// PoolVIPOwnershipHandoffDeliveryStore is the narrow durable dependency a
// future coordinator needs. It deliberately has no scheduler/operation type,
// no in-memory fallback, and no agent transport concern.
type PoolVIPOwnershipHandoffDeliveryStore interface {
	IssuePoolVIPOwnershipHandoffDeliveryV3LeaderBound(context.Context, PoolVIPOwnershipHandoffLeaderSession, PoolVIPOwnershipDeliveryEnvelopeV3) error
	ReadPoolVIPOwnershipHandoffAppliedAttestationV3(context.Context, PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipHandoffAppliedAttestationRead, bool, error)
}

// PoolVIPOwnershipHandoffEnvelopeProvenance is the P2-owned source of a full
// v3 ownership envelope. A later composition bridge may supply a P1
// artifact identity, but it must never synthesize routes from that identity:
// this provider derives them from P2's validated ownership provenance. The
// bridge validates the returned envelope and exact non-secret identity again
// before it can reach the durable issue facade.
//
// This is intentionally an unregistered seam. It neither schedules delivery
// nor makes a receipt/read-back result a serving decision.
type PoolVIPOwnershipHandoffEnvelopeProvenance interface {
	PoolVIPOwnershipHandoffEnvelope(context.Context, PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipDeliveryEnvelopeV3, error)
}

// PoolVIPOwnershipHandoffLeaderBoundEnvelopeProvenance is the issuance-only
// variant. It must obtain the immutable envelope using the caller's exact
// advisory-lock session; a bridge must never read provenance through a general
// pool and then attempt to issue it on a different leader transaction.
type PoolVIPOwnershipHandoffLeaderBoundEnvelopeProvenance interface {
	PoolVIPOwnershipHandoffEnvelopeProvenance
	PoolVIPOwnershipHandoffEnvelopeWithLeadership(context.Context, PoolVIPOwnershipHandoffArtifact, k8s.HandoffLeadershipEpoch, *pgxpool.Conn) (PoolVIPOwnershipDeliveryEnvelopeV3, error)
}

// PoolVIPOwnershipHandoffOutcome is intentionally finite so a later durable
// coordinator can persist its own decision without parsing error text.
type PoolVIPOwnershipHandoffOutcome string

const (
	PoolVIPOwnershipHandoffPending         PoolVIPOwnershipHandoffOutcome = "pending"
	PoolVIPOwnershipHandoffApplied         PoolVIPOwnershipHandoffOutcome = "applied"
	PoolVIPOwnershipHandoffRefused         PoolVIPOwnershipHandoffOutcome = "refused"
	PoolVIPOwnershipHandoffConflict        PoolVIPOwnershipHandoffOutcome = "conflict"
	PoolVIPOwnershipHandoffStaleGeneration PoolVIPOwnershipHandoffOutcome = "stale_generation"
)

// PoolVIPOwnershipHandoffArtifact is the non-secret, non-endpoint projection
// of exactly one delivery. Only a v3 envelope may issue through the handoff
// facade or satisfy its provenance/read boundary. It is sufficient to issue
// or look up a durable artifact, but does not expose its delivery nonce or
// owned route addresses.
type PoolVIPOwnershipHandoffArtifact struct {
	OrgID, SiteID, ClusterID, PoolID                  string
	ConnectorNodeID, TargetNodeID, OperationID        string
	ManifestIdentity, Role, DeliveryPhase, DeliveryID string
	PromotionGeneration, ManifestRevision, LeaseEpoch uint64
	// PriorLeaseEpoch is required only for withdrawal, whose applied state must
	// prove removal of the old serving lease rather than its new non-serving one.
	PriorLeaseEpoch uint64
	// Expected digests are the non-secret, no-address P2 evidence P1 must carry
	// into a later conversion. They make an applied attestation independently
	// checkable without exposing raw routes, VIPs, or a delivery nonce.
	ExpectedRouteDigest, ExpectedVIPMapDigest string
}

// PoolVIPOwnershipHandoffIssueResult records an accepted durable issue as
// pending, or a typed fail-closed outcome. Refused is a local artifact-shape
// refusal; the agent protocol intentionally sends no negative applied ACK,
// so absent node evidence remains pending rather than fabricated refusal.
type PoolVIPOwnershipHandoffIssueResult struct {
	Outcome  PoolVIPOwnershipHandoffOutcome
	Artifact PoolVIPOwnershipHandoffArtifact
}

// PoolVIPOwnershipHandoffAttestationResult returns only the exact accepted
// v3 applied evidence needed by a later coordinator. Applied* values are the
// validated stored ACK evidence, never inferred from the requested artifact.
// ReceiptTime is CP time; no agent timestamp, endpoint address, route, nonce,
// or secret is projected.
type PoolVIPOwnershipHandoffAttestationResult struct {
	Outcome                    PoolVIPOwnershipHandoffOutcome
	Artifact                   PoolVIPOwnershipHandoffArtifact
	WireVersion                int
	AppliedRole                string
	AppliedManifestIdentity    string
	AppliedPromotionGeneration uint64
	AppliedManifestRevision    uint64
	AppliedLeaseEpoch          uint64
	ReceiptTime                time.Time
	ExpiresAt                  time.Time
	OwnedRouteDigest           string
	VIPMapDigest               string
}

// PoolVIPOwnershipHandoffDeliveryFacade is a production-shaped, unregistered
// composition seam over the durable v3 ledger. It does not poll, schedule, or
// decide serving readiness.
type PoolVIPOwnershipHandoffDeliveryFacade struct {
	store PoolVIPOwnershipHandoffDeliveryStore
}

func NewPoolVIPOwnershipHandoffDeliveryFacade(store PoolVIPOwnershipHandoffDeliveryStore) (*PoolVIPOwnershipHandoffDeliveryFacade, error) {
	if store == nil || nilPoolVIPOwnershipHandoffDeliveryStore(store) {
		return nil, fmt.Errorf("ownership handoff delivery store is required")
	}
	return &PoolVIPOwnershipHandoffDeliveryFacade{store: store}, nil
}

func nilPoolVIPOwnershipHandoffDeliveryStore(store PoolVIPOwnershipHandoffDeliveryStore) bool {
	v := reflect.ValueOf(store)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// Issue durably records exactly one prepared, serving, or withdrawal v3
// artifact. Concurrent identical callers and process-restart retries remain
// pending and idempotent; immutable replays and generation regressions are
// returned as finite outcomes before a new stale artifact can be written.
func (f *PoolVIPOwnershipHandoffDeliveryFacade) Issue(ctx context.Context, session PoolVIPOwnershipHandoffLeaderSession, envelope PoolVIPOwnershipDeliveryEnvelopeV3) (PoolVIPOwnershipHandoffIssueResult, error) {
	if f == nil || f.store == nil {
		return PoolVIPOwnershipHandoffIssueResult{}, fmt.Errorf("ownership handoff delivery facade is not configured")
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		return PoolVIPOwnershipHandoffIssueResult{Outcome: PoolVIPOwnershipHandoffRefused}, nil
	}
	artifact := poolVIPOwnershipHandoffArtifact(envelope)
	if err := f.store.IssuePoolVIPOwnershipHandoffDeliveryV3LeaderBound(ctx, session, envelope); err != nil {
		switch {
		case errors.Is(err, ErrPoolVIPOwnershipDeliveryImmutableConflict):
			return PoolVIPOwnershipHandoffIssueResult{Outcome: PoolVIPOwnershipHandoffConflict, Artifact: artifact}, nil
		case errors.Is(err, ErrPoolVIPOwnershipDeliveryStaleGeneration):
			return PoolVIPOwnershipHandoffIssueResult{Outcome: PoolVIPOwnershipHandoffStaleGeneration, Artifact: artifact}, nil
		default:
			return PoolVIPOwnershipHandoffIssueResult{}, err
		}
	}
	return PoolVIPOwnershipHandoffIssueResult{Outcome: PoolVIPOwnershipHandoffPending, Artifact: artifact}, nil
}

// Attestation verifies one exact artifact's durable v3 applied evidence. It
// never scans by node, pool, or latest generation. A missing exact receipt is
// pending; it is not a negative node result or a memory-derived answer.
func (f *PoolVIPOwnershipHandoffDeliveryFacade) Attestation(ctx context.Context, artifact PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipHandoffAttestationResult, error) {
	if f == nil || f.store == nil {
		return PoolVIPOwnershipHandoffAttestationResult{}, fmt.Errorf("ownership handoff delivery facade is not configured")
	}
	if err := validPoolVIPOwnershipHandoffArtifact(artifact); err != nil {
		return PoolVIPOwnershipHandoffAttestationResult{Outcome: PoolVIPOwnershipHandoffRefused}, nil
	}
	attestation, found, err := f.store.ReadPoolVIPOwnershipHandoffAppliedAttestationV3(ctx, artifact)
	if err != nil {
		return PoolVIPOwnershipHandoffAttestationResult{}, err
	}
	if !found {
		return PoolVIPOwnershipHandoffAttestationResult{Outcome: PoolVIPOwnershipHandoffPending, Artifact: artifact}, nil
	}
	if !poolVIPOwnershipHandoffReadMatchesArtifact(artifact, attestation) {
		return PoolVIPOwnershipHandoffAttestationResult{Outcome: PoolVIPOwnershipHandoffRefused, Artifact: artifact}, nil
	}
	return PoolVIPOwnershipHandoffAttestationResult{
		Outcome:                    PoolVIPOwnershipHandoffApplied,
		Artifact:                   artifact,
		WireVersion:                attestation.WireVersion,
		AppliedRole:                attestation.AppliedRole,
		AppliedManifestIdentity:    attestation.AppliedManifestIdentity,
		AppliedPromotionGeneration: attestation.AppliedPromotionGeneration,
		AppliedManifestRevision:    attestation.AppliedManifestRevision,
		AppliedLeaseEpoch:          attestation.AppliedLeaseEpoch,
		ReceiptTime:                attestation.ReceiptTime.UTC(),
		ExpiresAt:                  attestation.ExpiresAt.UTC(),
		OwnedRouteDigest:           attestation.OwnedRouteDigest,
		VIPMapDigest:               attestation.VIPMapDigest,
	}, nil
}

func poolVIPOwnershipHandoffArtifact(envelope PoolVIPOwnershipDeliveryEnvelopeV3) PoolVIPOwnershipHandoffArtifact {
	return PoolVIPOwnershipHandoffArtifact{
		OrgID: envelope.OrgID, SiteID: envelope.SiteID, ClusterID: envelope.ClusterID, PoolID: envelope.PoolID,
		ConnectorNodeID: envelope.ConnectorNodeID, TargetNodeID: envelope.TargetNodeID, OperationID: envelope.OperationID,
		ManifestIdentity: envelope.ManifestIdentity, Role: envelope.Role, DeliveryPhase: envelope.DeliveryPhase, DeliveryID: envelope.DeliveryID,
		PromotionGeneration: envelope.PromotionGeneration, ManifestRevision: envelope.ManifestRevision, LeaseEpoch: envelope.LeaseEpoch,
		PriorLeaseEpoch: envelope.PriorLeaseEpoch, ExpectedRouteDigest: envelope.ExpectedRouteDigest, ExpectedVIPMapDigest: envelope.ExpectedVIPMapDigest,
	}
}

func validPoolVIPOwnershipHandoffArtifact(artifact PoolVIPOwnershipHandoffArtifact) error {
	if err := validPoolVIPOwnershipAppliedAttestationScope(poolVIPOwnershipHandoffAttestationScope(artifact)); err != nil {
		return err
	}
	emptyRouteDigest, err := PoolVIPOwnershipOwnedRouteDigest(nil)
	if err != nil || !poolVIPOwnershipIdentityHexRE.MatchString(artifact.ExpectedRouteDigest) {
		return fmt.Errorf("invalid ownership handoff expected route digest")
	}
	switch artifact.Role {
	case policyspec.PoolVIPOwnershipServing:
		if artifact.PriorLeaseEpoch != 0 || artifact.ExpectedRouteDigest == emptyRouteDigest || !poolVIPOwnershipIdentityHexRE.MatchString(artifact.ExpectedVIPMapDigest) {
			return fmt.Errorf("invalid serving ownership handoff artifact")
		}
	case policyspec.PoolVIPOwnershipPreparedNonServing:
		if artifact.PriorLeaseEpoch != 0 || artifact.ExpectedRouteDigest != emptyRouteDigest || artifact.ExpectedVIPMapDigest != "" {
			return fmt.Errorf("invalid prepared ownership handoff artifact")
		}
	case policyspec.PoolVIPOwnershipWithdrawal:
		if artifact.PriorLeaseEpoch == 0 || artifact.PriorLeaseEpoch >= artifact.LeaseEpoch || artifact.ExpectedRouteDigest != emptyRouteDigest || artifact.ExpectedVIPMapDigest != "" {
			return fmt.Errorf("invalid withdrawal ownership handoff artifact")
		}
	default:
		return fmt.Errorf("invalid ownership handoff role")
	}
	return nil
}

func poolVIPOwnershipHandoffAttestationScope(artifact PoolVIPOwnershipHandoffArtifact) PoolVIPOwnershipAppliedAttestationScope {
	return PoolVIPOwnershipAppliedAttestationScope{
		OrgID: artifact.OrgID, SiteID: artifact.SiteID, ClusterID: artifact.ClusterID, PoolID: artifact.PoolID,
		ConnectorNodeID: artifact.ConnectorNodeID, TargetNodeID: artifact.TargetNodeID, OperationID: artifact.OperationID,
		ManifestIdentity: artifact.ManifestIdentity, Role: artifact.Role, DeliveryPhase: artifact.DeliveryPhase, DeliveryID: artifact.DeliveryID,
		PromotionGeneration: artifact.PromotionGeneration, ManifestRevision: artifact.ManifestRevision, LeaseEpoch: artifact.LeaseEpoch,
	}
}

// poolVIPOwnershipHandoffReadMatchesArtifact is the final P2-side boundary
// before a later coordinator can observe "applied". Postgres already validates
// the stored ACK against its issued envelope; this duplicate projection check
// makes the narrow interface fail closed for any alternate store implementation
// and rejects v1/receipt-only reads outright.
func poolVIPOwnershipHandoffReadMatchesArtifact(artifact PoolVIPOwnershipHandoffArtifact, read PoolVIPOwnershipHandoffAppliedAttestationRead) bool {
	if read.WireVersion != PoolVIPOwnershipDeliveryHandoffVersion || read.ReceiptTime.IsZero() || read.ExpiresAt.IsZero() || !read.ReceiptTime.Before(read.ExpiresAt) ||
		read.AppliedRole != artifact.Role || read.AppliedManifestIdentity != artifact.ManifestIdentity ||
		read.AppliedPromotionGeneration != artifact.PromotionGeneration || read.AppliedManifestRevision != artifact.ManifestRevision ||
		read.OwnedRouteDigest != artifact.ExpectedRouteDigest || read.VIPMapDigest != artifact.ExpectedVIPMapDigest {
		return false
	}
	wantLease := artifact.LeaseEpoch
	if artifact.Role == policyspec.PoolVIPOwnershipWithdrawal {
		wantLease = artifact.PriorLeaseEpoch
	}
	return read.AppliedLeaseEpoch == wantLease
}
