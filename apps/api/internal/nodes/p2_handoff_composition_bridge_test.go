package nodes

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

func TestHandoffSchedulerDefaultOffCompositionBuildsCompleteInertGraph(t *testing.T) {
	pool := &pgxpool.Pool{}
	store := &p2CompositionStore{}
	composition, err := NewHandoffSchedulerDefaultOffComposition(pool, &leader.Elector{}, p2CompositionPolicy{}, k8s.NewService(pool), store)
	if err != nil {
		t.Fatal(err)
	}
	if composition == nil || composition.Runtime == nil || composition.P2 == nil || composition.Bootstrap == nil || composition.Activation == nil {
		t.Fatalf("incomplete default-off composition: %+v", composition)
	}
	if status := composition.Runtime.Status(); status.State != HandoffSchedulerDisabled || len(status.Reasons) != 0 {
		t.Fatalf("default-off status=%+v", status)
	}
	if status := composition.Runtime.Start(t.Context()); status.State != HandoffSchedulerDisabled {
		t.Fatalf("default-off start=%+v", status)
	}
	if bootstrap, err := composition.Bootstrap.ReconcileWithLeadership(t.Context(), time.Now().UTC(), k8s.HandoffLeadershipEpoch{}, nil); err != nil || bootstrap.State != HandoffBootstrapDisabled {
		t.Fatalf("default-off bootstrap=%+v err=%v", bootstrap, err)
	}
	if composition.Activation.Start(t.Context()) || composition.Activation.Running() {
		t.Fatal("default-off HA activation started")
	}
	if composition.Runtime.activation.Running() || store.issueCalls != 0 || store.readCalls != 0 {
		t.Fatalf("construction/start performed work: running=%t issue=%d read=%d", composition.Runtime.activation.Running(), store.issueCalls, store.readCalls)
	}
	if err := composition.Runtime.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestHandoffSchedulerDefaultOffCompositionRejectsIncompleteServerComponents(t *testing.T) {
	pool := &pgxpool.Pool{}
	valid := func() (*HandoffSchedulerDefaultOffComposition, error) {
		return NewHandoffSchedulerDefaultOffComposition(pool, &leader.Elector{}, p2CompositionPolicy{}, k8s.NewService(pool), &p2CompositionStore{})
	}
	if got, err := valid(); err != nil || got == nil {
		t.Fatalf("valid composition=%+v err=%v", got, err)
	}
	if got, err := NewHandoffSchedulerDefaultOffComposition(nil, &leader.Elector{}, p2CompositionPolicy{}, k8s.NewService(pool), &p2CompositionStore{}); err == nil || got != nil {
		t.Fatalf("nil pool composition=%+v err=%v", got, err)
	}
	if got, err := NewHandoffSchedulerDefaultOffComposition(pool, nil, p2CompositionPolicy{}, k8s.NewService(pool), &p2CompositionStore{}); err == nil || got != nil {
		t.Fatalf("nil elector composition=%+v err=%v", got, err)
	}
	if got, err := NewHandoffSchedulerDefaultOffComposition(pool, &leader.Elector{}, nil, k8s.NewService(pool), &p2CompositionStore{}); err == nil || got != nil {
		t.Fatalf("nil policy composition=%+v err=%v", got, err)
	}
	if got, err := NewHandoffSchedulerDefaultOffComposition(pool, &leader.Elector{}, p2CompositionPolicy{}, k8s.NewService(&pgxpool.Pool{}), &p2CompositionStore{}); err == nil || got != nil {
		t.Fatalf("wrong coordinator pool composition=%+v err=%v", got, err)
	}
}

func TestPoolVIPOwnershipP2HandoffBridgeUsesCallerLeaderSessionAndExactV3Provenance(t *testing.T) {
	envelope, _ := ownershipDeliveryV3(t)
	delivery := p2CompositionDelivery(t, envelope)
	conn := &pgxpool.Conn{}
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 41, LockKey: leader.SchedulerLockKey}
	store := &p2CompositionStore{}
	provenance := &p2CompositionProvenance{envelope: envelope}
	bridge, err := NewPoolVIPOwnershipP2HandoffBridge(store, provenance)
	if err != nil {
		t.Fatal(err)
	}

	if err := bridge.IssueP2HandoffDelivery(t.Context(), epoch, conn, delivery); err != nil {
		t.Fatal(err)
	}
	if provenance.calls != 1 || provenance.conn != conn || provenance.epoch != epoch {
		t.Fatalf("provenance did not use caller session: calls=%d conn=%p epoch=%+v", provenance.calls, provenance.conn, provenance.epoch)
	}
	if store.issueCalls != 1 || store.session.Conn != conn || store.session.Epoch.BackendPID != epoch.BackendPID || store.session.Epoch.AdvisoryLockKey != epoch.LockKey || store.envelope.DeliveryID != envelope.DeliveryID {
		t.Fatalf("store did not receive exact caller session/envelope: calls=%d session=%+v envelope=%+v", store.issueCalls, store.session, store.envelope)
	}

	wrongEpoch := epoch
	wrongEpoch.LockKey++
	if err := bridge.IssueP2HandoffDelivery(t.Context(), wrongEpoch, conn, delivery); !errors.Is(err, ErrPoolVIPOwnershipP2HandoffBridge) {
		t.Fatalf("wrong advisory lock was accepted: %v", err)
	}
	if err := bridge.IssueP2HandoffDelivery(t.Context(), epoch, nil, delivery); !errors.Is(err, ErrPoolVIPOwnershipP2HandoffBridge) {
		t.Fatalf("nil leader connection was accepted: %v", err)
	}
	if provenance.calls != 1 || store.issueCalls != 1 {
		t.Fatalf("invalid leader input reached P2: provenance=%d issue=%d", provenance.calls, store.issueCalls)
	}

	provenance.envelope.ExpiresAt = provenance.envelope.ExpiresAt.Add(time.Second)
	provenance.envelope.Manifest.LeaseExpiresAt = provenance.envelope.ExpiresAt
	if err := bridge.IssueP2HandoffDelivery(t.Context(), epoch, conn, delivery); !errors.Is(err, ErrPoolVIPOwnershipP2HandoffBridge) {
		t.Fatalf("expiry-mismatched provenance was accepted: %v", err)
	}
	if store.issueCalls != 1 {
		t.Fatalf("mismatched provenance reached durable issue: %d", store.issueCalls)
	}
}

func TestPoolVIPOwnershipP2HandoffBridgeProjectsOnlyExactAppliedV3(t *testing.T) {
	envelope, _ := ownershipDeliveryV3(t)
	delivery := p2CompositionDelivery(t, envelope)
	store := &p2CompositionStore{}
	bridge, err := NewPoolVIPOwnershipP2HandoffBridge(store, &p2CompositionProvenance{envelope: envelope})
	if err != nil {
		t.Fatal(err)
	}

	if got, found, err := bridge.LoadP2HandoffAppliedAttestation(t.Context(), delivery.Identity); err != nil || found || got != (k8s.P2HandoffAppliedAttestation{}) {
		t.Fatalf("missing attestation=%+v found=%t err=%v", got, found, err)
	}
	store.found = true
	store.artifact = poolVIPOwnershipHandoffArtifact(envelope)
	store.attestation = exactPoolVIPOwnershipHandoffRead(envelope, envelope.ExpiresAt.Add(-time.Minute))
	got, found, err := bridge.LoadP2HandoffAppliedAttestation(t.Context(), delivery.Identity)
	if err != nil || !found || got.Version != k8s.P2HandoffAttestationVersion || got.Identity != delivery.Identity ||
		!got.CPReceiptAt.Equal(store.attestation.ReceiptTime) || !got.DeliveryExpiresAt.Equal(envelope.ExpiresAt) ||
		got.AppliedRole != delivery.Identity.Role || got.AppliedManifestIdentity != delivery.Identity.ManifestIdentity ||
		got.AppliedPromotionGeneration != delivery.Identity.PromotionGeneration || got.AppliedManifestRevision != delivery.Identity.ManifestRevision ||
		got.AppliedLeaseEpoch != delivery.Identity.LeaseEpoch || got.AppliedRouteDigest != delivery.Identity.ExpectedRouteDigest || got.AppliedVIPMapDigest != delivery.Identity.ExpectedVIPMapDigest {
		t.Fatalf("exact v3 projection=%+v found=%t err=%v", got, found, err)
	}
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 47, LockKey: leader.SchedulerLockKey}
	conn := &pgxpool.Conn{}
	got, found, err = bridge.LoadP2HandoffAppliedAttestationWithLeadership(t.Context(), epoch, conn, delivery.Identity)
	if err != nil || !found || got.Identity != delivery.Identity || store.session.Conn != conn || store.session.Epoch.BackendPID != epoch.BackendPID || store.session.Epoch.AdvisoryLockKey != epoch.LockKey {
		t.Fatalf("leader-bound v3 projection=%+v found=%t err=%v session=%+v", got, found, err, store.session)
	}

	wrongVersion := delivery.Identity
	wrongVersion.Version = 2
	if _, found, err := bridge.LoadP2HandoffAppliedAttestation(t.Context(), wrongVersion); !errors.Is(err, ErrPoolVIPOwnershipP2HandoffBridge) || found {
		t.Fatalf("v2 identity was accepted: found=%t err=%v", found, err)
	}
	nilTarget := delivery.Identity
	nilTarget.TargetNodeID = uuid.Nil
	if _, found, err := bridge.LoadP2HandoffAppliedAttestation(t.Context(), nilTarget); !errors.Is(err, ErrPoolVIPOwnershipP2HandoffBridge) || found {
		t.Fatalf("nil target identity was accepted: found=%t err=%v", found, err)
	}
}

func TestNewPoolVIPOwnershipP2HandoffBridgeRejectsMissingDependencies(t *testing.T) {
	if got, err := NewPoolVIPOwnershipP2HandoffBridge(nil, &p2CompositionProvenance{}); err == nil || got != nil {
		t.Fatalf("nil store bridge=%+v err=%v", got, err)
	}
	if got, err := NewPoolVIPOwnershipP2HandoffBridge(&p2CompositionStore{}, nil); err == nil || got != nil {
		t.Fatalf("nil provenance bridge=%+v err=%v", got, err)
	}
	var typedNil *p2CompositionProvenance
	if got, err := NewPoolVIPOwnershipP2HandoffBridge(&p2CompositionStore{}, typedNil); err == nil || got != nil {
		t.Fatalf("typed-nil provenance bridge=%+v err=%v", got, err)
	}
}

type p2CompositionPolicy struct{}

func (p2CompositionPolicy) HandoffPolicyAcknowledgements(context.Context, uuid.UUID, uuid.UUID, []uuid.UUID) (map[uuid.UUID]k8s.PolicyAcknowledgement, error) {
	return nil, nil
}

type p2CompositionProvenance struct {
	envelope PoolVIPOwnershipDeliveryEnvelopeV3
	calls    int
	epoch    k8s.HandoffLeadershipEpoch
	conn     *pgxpool.Conn
}

func (p *p2CompositionProvenance) PoolVIPOwnershipHandoffEnvelope(context.Context, PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipDeliveryEnvelopeV3, error) {
	return PoolVIPOwnershipDeliveryEnvelopeV3{}, errors.New("unbound provenance read is forbidden")
}

func (p *p2CompositionProvenance) PoolVIPOwnershipHandoffEnvelopeWithLeadership(_ context.Context, _ PoolVIPOwnershipHandoffArtifact, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (PoolVIPOwnershipDeliveryEnvelopeV3, error) {
	p.calls++
	p.epoch, p.conn = epoch, conn
	return p.envelope, nil
}

type p2CompositionStore struct {
	issueCalls  int
	readCalls   int
	session     PoolVIPOwnershipHandoffLeaderSession
	envelope    PoolVIPOwnershipDeliveryEnvelopeV3
	artifact    PoolVIPOwnershipHandoffArtifact
	attestation PoolVIPOwnershipHandoffAppliedAttestationRead
	found       bool
}

func (s *p2CompositionStore) IssuePoolVIPOwnershipHandoffDeliveryV3LeaderBound(_ context.Context, session PoolVIPOwnershipHandoffLeaderSession, envelope PoolVIPOwnershipDeliveryEnvelopeV3) error {
	s.issueCalls++
	s.session, s.envelope = session, envelope
	return nil
}

func (s *p2CompositionStore) IssueHandoffBootstrapEnvelopeWithLeadership(_ context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, envelope PoolVIPOwnershipDeliveryEnvelopeV3) error {
	s.issueCalls++
	s.session = PoolVIPOwnershipHandoffLeaderSession{Epoch: PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey}, Conn: conn}
	s.envelope = envelope
	return nil
}

func (s *p2CompositionStore) ReadPoolVIPOwnershipHandoffAppliedAttestationV3(_ context.Context, artifact PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipHandoffAppliedAttestationRead, bool, error) {
	s.readCalls++
	if !s.found || artifact != s.artifact {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, nil
	}
	return s.attestation, true, nil
}

func (s *p2CompositionStore) ReadPoolVIPOwnershipHandoffAppliedAttestationV3LeaderBound(ctx context.Context, session PoolVIPOwnershipHandoffLeaderSession, artifact PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipHandoffAppliedAttestationRead, bool, error) {
	s.session = session
	return s.ReadPoolVIPOwnershipHandoffAppliedAttestationV3(ctx, artifact)
}

func p2CompositionDelivery(t *testing.T, envelope PoolVIPOwnershipDeliveryEnvelopeV3) k8s.P2HandoffDelivery {
	t.Helper()
	parse := func(value string) uuid.UUID {
		id, err := uuid.Parse(value)
		if err != nil {
			t.Fatalf("parse %q: %v", value, err)
		}
		return id
	}
	return k8s.P2HandoffDelivery{Identity: k8s.P2HandoffDeliveryIdentity{
		Version: envelope.Version, OrgID: parse(envelope.OrgID), SiteID: parse(envelope.SiteID), ClusterID: parse(envelope.ClusterID), PoolID: parse(envelope.PoolID),
		ConnectorNodeID: parse(envelope.ConnectorNodeID), TargetNodeID: parse(envelope.TargetNodeID), OperationID: parse(envelope.OperationID),
		ManifestIdentity: envelope.ManifestIdentity, Role: k8s.P2HandoffRole(envelope.Role), PromotionGeneration: envelope.PromotionGeneration,
		ManifestRevision: envelope.ManifestRevision, LeaseEpoch: envelope.LeaseEpoch, PriorLeaseEpoch: envelope.PriorLeaseEpoch,
		ExpectedRouteDigest: envelope.ExpectedRouteDigest, ExpectedVIPMapDigest: envelope.ExpectedVIPMapDigest,
		DeliveryPhase: envelope.DeliveryPhase, DeliveryID: parse(envelope.DeliveryID),
	}, LeaseExpiresAt: envelope.ExpiresAt}
}
