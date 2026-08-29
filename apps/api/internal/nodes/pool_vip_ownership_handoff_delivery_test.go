package nodes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestPoolVIPOwnershipHandoffLeaderSessionRejectsNil(t *testing.T) {
	if err := validPoolVIPOwnershipHandoffLeaderSession(context.Background(), PoolVIPOwnershipHandoffLeaderSession{}); !errors.Is(err, ErrPoolVIPOwnershipHandoffLeaderSession) {
		t.Fatalf("nil leader session must fail closed, got %v", err)
	}
	if err := validPoolVIPOwnershipHandoffLeaderSession(context.Background(), PoolVIPOwnershipHandoffLeaderSession{Epoch: PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: 1}}); !errors.Is(err, ErrPoolVIPOwnershipHandoffLeaderSession) {
		t.Fatalf("zero advisory lock key must fail closed, got %v", err)
	}
}

func TestPoolVIPOwnershipHandoffArtifactRequiresExactV3Evidence(t *testing.T) {
	envelope, _ := ownershipDeliveryV3(t)
	artifact := poolVIPOwnershipHandoffArtifact(envelope)
	if err := validPoolVIPOwnershipHandoffArtifact(artifact); err != nil {
		t.Fatalf("v3 serving artifact must be valid: %v", err)
	}
	artifact.ExpectedVIPMapDigest = ""
	if err := validPoolVIPOwnershipHandoffArtifact(artifact); err == nil {
		t.Fatal("serving artifact without VIP evidence must fail closed")
	}
	artifact = poolVIPOwnershipHandoffArtifact(envelope)
	artifact.ExpectedRouteDigest, _ = PoolVIPOwnershipOwnedRouteDigest(nil)
	if err := validPoolVIPOwnershipHandoffArtifact(artifact); err == nil {
		t.Fatal("serving handoff artifact with canonical empty route digest must fail closed")
	}
}

func TestPoolVIPOwnershipHandoffDeliveryFacadeUsesFiniteExactOutcomes(t *testing.T) {
	envelope, _ := ownershipDeliveryV3(t)
	artifact := poolVIPOwnershipHandoffArtifact(envelope)
	store := &fakePoolVIPOwnershipHandoffStore{}
	session := PoolVIPOwnershipHandoffLeaderSession{Epoch: PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: 1, AdvisoryLockKey: 7}}
	facade, err := NewPoolVIPOwnershipHandoffDeliveryFacade(store)
	if err != nil {
		t.Fatal(err)
	}

	if got, err := facade.Issue(t.Context(), session, envelope); err != nil || got.Outcome != PoolVIPOwnershipHandoffPending || got.Artifact != artifact || store.issued.Version != PoolVIPOwnershipDeliveryHandoffVersion {
		t.Fatalf("accepted issue = %+v, %v", got, err)
	}
	invalid := envelope
	invalid.Role = policyspec.PoolVIPOwnershipPreparedNonServing
	if got, err := facade.Issue(t.Context(), session, invalid); err != nil || got.Outcome != PoolVIPOwnershipHandoffRefused {
		t.Fatalf("invalid artifact issue = %+v, %v", got, err)
	}
	store.issueErr = ErrPoolVIPOwnershipDeliveryImmutableConflict
	if got, err := facade.Issue(t.Context(), session, envelope); err != nil || got.Outcome != PoolVIPOwnershipHandoffConflict {
		t.Fatalf("immutable replay = %+v, %v", got, err)
	}
	store.issueErr = ErrPoolVIPOwnershipDeliveryStaleGeneration
	if got, err := facade.Issue(t.Context(), session, envelope); err != nil || got.Outcome != PoolVIPOwnershipHandoffStaleGeneration {
		t.Fatalf("stale generation = %+v, %v", got, err)
	}
	store.issueErr = nil

	if got, err := facade.Attestation(t.Context(), artifact); err != nil || got.Outcome != PoolVIPOwnershipHandoffPending || got.Artifact != artifact {
		t.Fatalf("missing exact attestation = %+v, %v", got, err)
	}
	// Deliberate red: a digest-only/v2-shaped response must not become applied
	// just because a store reports it found. A future coordinator may advance
	// only from exact v3 applied-manifest evidence.
	store.found = true
	store.artifact = artifact
	store.attestation = exactPoolVIPOwnershipHandoffRead(envelope, time.Now().UTC().Add(-time.Minute))
	store.attestation.WireVersion = PoolVIPOwnershipDeliveryAttestationVersion
	if got, err := facade.Attestation(t.Context(), artifact); err != nil || got.Outcome != PoolVIPOwnershipHandoffRefused {
		t.Fatalf("digest-only v2 attestation must be refused: %+v, %v", got, err)
	}
	receipt := envelope.ExpiresAt.Add(-time.Minute)
	store.attestation = exactPoolVIPOwnershipHandoffRead(envelope, receipt)
	if err := validPoolVIPOwnershipHandoffArtifact(artifact); err != nil {
		t.Fatalf("valid handoff artifact refused: %v", err)
	}
	got, err := facade.Attestation(t.Context(), artifact)
	if err != nil || got.Outcome != PoolVIPOwnershipHandoffApplied || got.WireVersion != PoolVIPOwnershipDeliveryHandoffVersion || got.AppliedRole != store.attestation.AppliedRole || got.AppliedManifestIdentity != store.attestation.AppliedManifestIdentity || got.AppliedPromotionGeneration != store.attestation.AppliedPromotionGeneration || got.AppliedManifestRevision != store.attestation.AppliedManifestRevision || got.AppliedLeaseEpoch != store.attestation.AppliedLeaseEpoch || !got.ReceiptTime.Equal(receipt) || !got.ExpiresAt.Equal(envelope.ExpiresAt) || got.OwnedRouteDigest != envelope.ExpectedRouteDigest || got.VIPMapDigest != envelope.ExpectedVIPMapDigest {
		t.Fatalf("exact applied attestation = %+v, %v", got, err)
	}
	// Deliberate red: an alternate store cannot relabel a valid receipt by
	// changing an applied field or any digest, even if its lookup key matches.
	store.attestation.AppliedLeaseEpoch++
	if got, err := facade.Attestation(t.Context(), artifact); err != nil || got.Outcome != PoolVIPOwnershipHandoffRefused {
		t.Fatalf("applied lease mismatch must be refused: %+v, %v", got, err)
	}
	store.attestation.AppliedLeaseEpoch = envelope.LeaseEpoch
	store.attestation.OwnedRouteDigest = strings.Repeat("e", 64)
	if got, err := facade.Attestation(t.Context(), artifact); err != nil || got.Outcome != PoolVIPOwnershipHandoffRefused {
		t.Fatalf("digest-mismatched attestation must be refused: %+v, %v", got, err)
	}
	store.attestation.OwnedRouteDigest = envelope.ExpectedRouteDigest
	// The projection deliberately cannot expose raw owned routes or the delivery
	// nonce. Digests and CP receipt time are enough for a later coordinator.
	if strings.Contains(got.OwnedRouteDigest, "10.44") || strings.Contains(got.VIPMapDigest, envelope.DeliveryNonce) {
		t.Fatalf("attestation projection leaked route or nonce: %+v", got)
	}
	wrongOrg := artifact
	wrongOrg.OrgID = "00000000-0000-4000-8000-000000000010"
	if got, err := facade.Attestation(t.Context(), wrongOrg); err != nil || got.Outcome != PoolVIPOwnershipHandoffPending {
		t.Fatalf("wrong-org artifact must never satisfy: %+v, %v", got, err)
	}
	wrongRole := artifact
	wrongRole.Role, wrongRole.DeliveryPhase = policyspec.PoolVIPOwnershipWithdrawal, poolVIPOwnershipPhaseWithdraw
	if got, err := facade.Attestation(t.Context(), wrongRole); err != nil || got.Outcome != PoolVIPOwnershipHandoffRefused {
		t.Fatalf("malformed wrong-role artifact must be refused: %+v, %v", got, err)
	}
	wrongGeneration := artifact
	wrongGeneration.PromotionGeneration++
	if got, err := facade.Attestation(t.Context(), wrongGeneration); err != nil || got.Outcome != PoolVIPOwnershipHandoffPending {
		t.Fatalf("wrong-generation artifact must never satisfy: %+v, %v", got, err)
	}
	wrongLease := artifact
	wrongLease.LeaseEpoch++
	if got, err := facade.Attestation(t.Context(), wrongLease); err != nil || got.Outcome != PoolVIPOwnershipHandoffPending {
		t.Fatalf("wrong-lease artifact must never satisfy: %+v, %v", got, err)
	}
}

func TestNewPoolVIPOwnershipHandoffDeliveryFacadeRejectsMissingStore(t *testing.T) {
	if facade, err := NewPoolVIPOwnershipHandoffDeliveryFacade(nil); err == nil || facade != nil {
		t.Fatalf("nil store facade=%+v err=%v", facade, err)
	}
	var typedNil *fakePoolVIPOwnershipHandoffStore
	if facade, err := NewPoolVIPOwnershipHandoffDeliveryFacade(typedNil); err == nil || facade != nil {
		t.Fatalf("typed-nil store facade=%+v err=%v", facade, err)
	}
}

type fakePoolVIPOwnershipHandoffStore struct {
	issueErr    error
	issued      PoolVIPOwnershipDeliveryEnvelopeV3
	artifact    PoolVIPOwnershipHandoffArtifact
	attestation PoolVIPOwnershipHandoffAppliedAttestationRead
	found       bool
}

func (s *fakePoolVIPOwnershipHandoffStore) IssuePoolVIPOwnershipHandoffDeliveryV3LeaderBound(_ context.Context, _ PoolVIPOwnershipHandoffLeaderSession, envelope PoolVIPOwnershipDeliveryEnvelopeV3) error {
	s.issued = envelope
	return s.issueErr
}

func (s *fakePoolVIPOwnershipHandoffStore) ReadPoolVIPOwnershipHandoffAppliedAttestationV3(_ context.Context, artifact PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipHandoffAppliedAttestationRead, bool, error) {
	if !s.found || s.artifact != artifact {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, nil
	}
	return s.attestation, true, nil
}

func exactPoolVIPOwnershipHandoffRead(envelope PoolVIPOwnershipDeliveryEnvelopeV3, receipt time.Time) PoolVIPOwnershipHandoffAppliedAttestationRead {
	return PoolVIPOwnershipHandoffAppliedAttestationRead{
		WireVersion: PoolVIPOwnershipDeliveryHandoffVersion, AppliedRole: envelope.Role, AppliedManifestIdentity: envelope.ManifestIdentity,
		AppliedPromotionGeneration: envelope.PromotionGeneration, AppliedManifestRevision: envelope.ManifestRevision, AppliedLeaseEpoch: envelope.LeaseEpoch,
		ReceiptTime: receipt, ExpiresAt: envelope.ExpiresAt, OwnedRouteDigest: envelope.ExpectedRouteDigest, VIPMapDigest: envelope.ExpectedVIPMapDigest,
	}
}

var _ PoolVIPOwnershipHandoffDeliveryStore = (*fakePoolVIPOwnershipHandoffStore)(nil)
