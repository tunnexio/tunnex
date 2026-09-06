package nodes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

// ErrPoolVIPOwnershipP2HandoffBridge is intentionally content-free at the
// scheduler boundary. Detailed P2 identities and manifests must not escape in
// lifecycle or operator-status errors.
var ErrPoolVIPOwnershipP2HandoffBridge = errors.New("pool VIP ownership P2 handoff bridge refused the operation")

// PoolVIPOwnershipP2HandoffBridge is the narrow production adapter between
// P1's operation-keyed contract and P2's immutable v3 provenance/ledger. It
// owns no goroutine and caches no leadership state. Issue is called only with
// the exact connection supplied by LeaderHandoffFence.WithEpoch; both the
// provenance reader and durable writer independently re-confirm that session.
type PoolVIPOwnershipP2HandoffBridge struct {
	provenance PoolVIPOwnershipHandoffLeaderBoundEnvelopeProvenance
	store      PoolVIPOwnershipHandoffDeliveryStore
	delivery   *PoolVIPOwnershipHandoffDeliveryFacade
}

func NewPoolVIPOwnershipP2HandoffBridge(store PoolVIPOwnershipHandoffDeliveryStore, provenance PoolVIPOwnershipHandoffLeaderBoundEnvelopeProvenance) (*PoolVIPOwnershipP2HandoffBridge, error) {
	delivery, err := NewPoolVIPOwnershipHandoffDeliveryFacade(store)
	if err != nil {
		return nil, err
	}
	if !handoffActivationDependencyPresent(provenance) {
		return nil, fmt.Errorf("ownership handoff v3 provenance is required")
	}
	return &PoolVIPOwnershipP2HandoffBridge{provenance: provenance, store: store, delivery: delivery}, nil
}

var _ k8s.P2HandoffDeliveryIssuer = (*PoolVIPOwnershipP2HandoffBridge)(nil)
var _ k8s.P2HandoffAttestationReader = (*PoolVIPOwnershipP2HandoffBridge)(nil)
var _ k8s.P2HandoffLeaderBoundAttestationReader = (*PoolVIPOwnershipP2HandoffBridge)(nil)
var _ HandoffBootstrapLeaderAttestationReader = (*PoolVIPOwnershipP2HandoffBridge)(nil)

type poolVIPOwnershipLeaderBoundAttestationStore interface {
	ReadPoolVIPOwnershipHandoffAppliedAttestationV3LeaderBound(context.Context, PoolVIPOwnershipHandoffLeaderSession, PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipHandoffAppliedAttestationRead, bool, error)
}

func (b *PoolVIPOwnershipP2HandoffBridge) IssueP2HandoffDelivery(ctx context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, delivery k8s.P2HandoffDelivery) error {
	if b == nil || b.delivery == nil || !handoffActivationDependencyPresent(b.provenance) || conn == nil ||
		epoch.BackendPID <= 0 || epoch.LockKey != leader.SchedulerLockKey {
		return ErrPoolVIPOwnershipP2HandoffBridge
	}
	artifact, err := poolVIPOwnershipHandoffArtifactFromP2Identity(delivery.Identity)
	if err != nil || delivery.LeaseExpiresAt.IsZero() || delivery.LeaseExpiresAt.Location() != time.UTC {
		return ErrPoolVIPOwnershipP2HandoffBridge
	}
	envelope, err := b.provenance.PoolVIPOwnershipHandoffEnvelopeWithLeadership(ctx, artifact, epoch, conn)
	if err != nil {
		return fmt.Errorf("%w: v3 provenance unavailable", ErrPoolVIPOwnershipP2HandoffBridge)
	}
	if ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope) != nil ||
		poolVIPOwnershipHandoffArtifact(envelope) != artifact || !envelope.ExpiresAt.Equal(delivery.LeaseExpiresAt) {
		return ErrPoolVIPOwnershipP2HandoffBridge
	}
	result, err := b.delivery.Issue(ctx, PoolVIPOwnershipHandoffLeaderSession{
		Epoch: PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey},
		Conn:  conn,
	}, envelope)
	if err != nil {
		return err
	}
	if result.Outcome != PoolVIPOwnershipHandoffPending || result.Artifact != artifact {
		return ErrPoolVIPOwnershipP2HandoffBridge
	}
	return nil
}

func (b *PoolVIPOwnershipP2HandoffBridge) LoadP2HandoffAppliedAttestation(ctx context.Context, identity k8s.P2HandoffDeliveryIdentity) (k8s.P2HandoffAppliedAttestation, bool, error) {
	if b == nil || b.delivery == nil {
		return k8s.P2HandoffAppliedAttestation{}, false, ErrPoolVIPOwnershipP2HandoffBridge
	}
	artifact, err := poolVIPOwnershipHandoffArtifactFromP2Identity(identity)
	if err != nil {
		return k8s.P2HandoffAppliedAttestation{}, false, ErrPoolVIPOwnershipP2HandoffBridge
	}
	result, err := b.delivery.Attestation(ctx, artifact)
	if err != nil {
		return k8s.P2HandoffAppliedAttestation{}, false, err
	}
	switch result.Outcome {
	case PoolVIPOwnershipHandoffPending:
		return k8s.P2HandoffAppliedAttestation{}, false, nil
	case PoolVIPOwnershipHandoffApplied:
		return k8s.P2HandoffAppliedAttestation{
			Version: result.WireVersion, Identity: identity, CPReceiptAt: result.ReceiptTime, DeliveryExpiresAt: result.ExpiresAt,
			AppliedRole: k8s.P2HandoffRole(result.AppliedRole), AppliedManifestIdentity: result.AppliedManifestIdentity,
			AppliedPromotionGeneration: result.AppliedPromotionGeneration, AppliedManifestRevision: result.AppliedManifestRevision,
			AppliedLeaseEpoch: result.AppliedLeaseEpoch, AppliedRouteDigest: result.OwnedRouteDigest, AppliedVIPMapDigest: result.VIPMapDigest,
		}, true, nil
	default:
		return k8s.P2HandoffAppliedAttestation{}, false, ErrPoolVIPOwnershipP2HandoffBridge
	}
}

func (b *PoolVIPOwnershipP2HandoffBridge) LoadP2HandoffAppliedAttestationWithLeadership(ctx context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, identity k8s.P2HandoffDeliveryIdentity) (k8s.P2HandoffAppliedAttestation, bool, error) {
	if b == nil || conn == nil || epoch.BackendPID <= 0 || epoch.LockKey != leader.SchedulerLockKey {
		return k8s.P2HandoffAppliedAttestation{}, false, ErrPoolVIPOwnershipP2HandoffBridge
	}
	store, ok := b.store.(poolVIPOwnershipLeaderBoundAttestationStore)
	if !ok || !handoffActivationDependencyPresent(store) {
		return k8s.P2HandoffAppliedAttestation{}, false, ErrPoolVIPOwnershipP2HandoffBridge
	}
	artifact, err := poolVIPOwnershipHandoffArtifactFromP2Identity(identity)
	if err != nil {
		return k8s.P2HandoffAppliedAttestation{}, false, ErrPoolVIPOwnershipP2HandoffBridge
	}
	read, found, err := store.ReadPoolVIPOwnershipHandoffAppliedAttestationV3LeaderBound(ctx, PoolVIPOwnershipHandoffLeaderSession{
		Epoch: PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey}, Conn: conn,
	}, artifact)
	if err != nil || !found {
		return k8s.P2HandoffAppliedAttestation{}, false, err
	}
	if !poolVIPOwnershipHandoffReadMatchesArtifact(artifact, read) {
		return k8s.P2HandoffAppliedAttestation{}, false, ErrPoolVIPOwnershipP2HandoffBridge
	}
	return k8s.P2HandoffAppliedAttestation{
		Version: read.WireVersion, Identity: identity, CPReceiptAt: read.ReceiptTime, DeliveryExpiresAt: read.ExpiresAt,
		AppliedRole: k8s.P2HandoffRole(read.AppliedRole), AppliedManifestIdentity: read.AppliedManifestIdentity,
		AppliedPromotionGeneration: read.AppliedPromotionGeneration, AppliedManifestRevision: read.AppliedManifestRevision,
		AppliedLeaseEpoch: read.AppliedLeaseEpoch, AppliedRouteDigest: read.OwnedRouteDigest, AppliedVIPMapDigest: read.VIPMapDigest,
	}, true, nil
}

func poolVIPOwnershipHandoffArtifactFromP2Identity(identity k8s.P2HandoffDeliveryIdentity) (PoolVIPOwnershipHandoffArtifact, error) {
	if identity.Version != k8s.P2HandoffAttestationVersion || identity.OrgID == uuid.Nil || identity.SiteID == uuid.Nil ||
		identity.ClusterID == uuid.Nil || identity.PoolID == uuid.Nil || identity.ConnectorNodeID == uuid.Nil ||
		identity.TargetNodeID == uuid.Nil || identity.OperationID == uuid.Nil || identity.DeliveryID == uuid.Nil {
		return PoolVIPOwnershipHandoffArtifact{}, ErrPoolVIPOwnershipP2HandoffBridge
	}
	artifact := PoolVIPOwnershipHandoffArtifact{
		OrgID: identity.OrgID.String(), SiteID: identity.SiteID.String(), ClusterID: identity.ClusterID.String(), PoolID: identity.PoolID.String(),
		ConnectorNodeID: identity.ConnectorNodeID.String(), TargetNodeID: identity.TargetNodeID.String(), OperationID: identity.OperationID.String(),
		ManifestIdentity: identity.ManifestIdentity, Role: string(identity.Role), DeliveryPhase: identity.DeliveryPhase, DeliveryID: identity.DeliveryID.String(),
		PromotionGeneration: identity.PromotionGeneration, ManifestRevision: identity.ManifestRevision, LeaseEpoch: identity.LeaseEpoch,
		PriorLeaseEpoch: identity.PriorLeaseEpoch, ExpectedRouteDigest: identity.ExpectedRouteDigest, ExpectedVIPMapDigest: identity.ExpectedVIPMapDigest,
	}
	if err := validPoolVIPOwnershipHandoffArtifact(artifact); err != nil {
		return PoolVIPOwnershipHandoffArtifact{}, ErrPoolVIPOwnershipP2HandoffBridge
	}
	return artifact, nil
}

// HandoffSchedulerDefaultOffComposition proves that the current server's
// shared pool, leader elector, node-policy evidence service, Kubernetes
// service, and mTLS delivery ledger can construct the current scheduler graph
// and both P2 dependencies. The per-pool/per-generation durable provenance is
// checked again inside operation creation and exact phase reads; there is no
// process-global fenced-base readiness token. This constructor does not call
// Runtime.Start or issue a delivery. A later opt-in must replace these inert
// reference timings with validated operator configuration and explicitly
// construct an Enabled runtime.
type HandoffSchedulerDefaultOffComposition struct {
	Runtime    *HandoffSchedulerServerRuntime
	P2         *PoolVIPOwnershipP2HandoffBridge
	Bootstrap  *HandoffBootstrapReconciler
	Activation *HandoffHAActivationRuntime
}

func NewHandoffSchedulerDefaultOffComposition(pool *pgxpool.Pool, elector *leader.Elector, policy HandoffPolicyAcknowledgementSource, coordinator *k8s.Service, store PoolVIPOwnershipHandoffDeliveryStore) (*HandoffSchedulerDefaultOffComposition, error) {
	return newHandoffSchedulerComposition(false, pool, elector, policy, coordinator, store, nil, nil)
}

// NewHandoffSchedulerProductionComposition is the only constructor that can
// enable P3. The deployment gate is explicit and still defaults false in
// config; organization opt-in cannot manufacture any missing dependency.
func NewHandoffSchedulerProductionComposition(enabled bool, pool *pgxpool.Pool, elector *leader.Elector, policy HandoffPolicyAcknowledgementSource, coordinator *k8s.Service, store PoolVIPOwnershipHandoffDeliveryStore, base HandoffBaseStateSource, authority KubernetesOwnershipBaseAuthorityIssuer) (*HandoffSchedulerDefaultOffComposition, error) {
	return newHandoffSchedulerComposition(enabled, pool, elector, policy, coordinator, store, base, authority)
}

func newHandoffSchedulerComposition(enabled bool, pool *pgxpool.Pool, elector *leader.Elector, policy HandoffPolicyAcknowledgementSource, coordinator *k8s.Service, store PoolVIPOwnershipHandoffDeliveryStore, base HandoffBaseStateSource, authority KubernetesOwnershipBaseAuthorityIssuer) (*HandoffSchedulerDefaultOffComposition, error) {
	if pool == nil || elector == nil || !handoffActivationDependencyPresent(policy) || coordinator == nil || !coordinator.HandoffCoordinatorServiceReady(pool) {
		return nil, fmt.Errorf("handoff scheduler server components are incomplete")
	}
	if enabled && (!handoffActivationDependencyPresent(base) || !handoffActivationDependencyPresent(authority)) {
		return nil, fmt.Errorf("handoff HA base-authority dependencies are incomplete")
	}
	provenance := NewPostgresPoolVIPOwnershipFreshHandoffProvenance(pool, nil)
	bridge, err := NewPoolVIPOwnershipP2HandoffBridge(store, provenance)
	if err != nil {
		return nil, err
	}
	bootstrapIssuer, ok := store.(HandoffBootstrapEnvelopeIssuer)
	if !ok || !handoffActivationDependencyPresent(bootstrapIssuer) {
		return nil, fmt.Errorf("topology-fenced bootstrap issuer is required")
	}
	const (
		// In-cluster gateways report every five seconds. Ten seconds permits one
		// missed report without a false stale verdict while retaining the pure
		// model's three-tick hysteresis inside the 30-second HA recovery budget.
		referenceReportFreshness = 10 * time.Second
		referenceAckFreshness    = time.Minute
		referenceClockSkew       = time.Second
	)
	history := NewPostgresHandoffHealthHistory(pool, policy, referenceReportFreshness)
	plans := NewPostgresHandoffPlanResolverWithLeadershipProvenance(pool, provenance)
	source := NewPostgresHandoffTickSource(pool, policy, history, plans, HandoffTickSourceConfig{
		ReportFreshness: referenceReportFreshness, MaxAckAge: referenceAckFreshness, ClockSkewMargin: referenceClockSkew,
	})
	serverConfig := HandoffSchedulerServerConfig{
		Enabled: enabled, Cadence: 5 * time.Second, PerTickTimeout: 4 * time.Second, MaxBackoff: time.Minute,
		LeaderProbeInterval: time.Second, StopTimeout: time.Second, SerialBatchSize: 32,
	}
	dependencies := HandoffSchedulerServerDependencies{
		Pool: pool, Elector: elector, HealthObserver: history, MigrationGate: NewPostgresHandoffSchedulerMigrationGate(pool), TickSource: source,
		P2Issuer: bridge, P2Reader: bridge, OperationProvenance: provenance, CoordinatorService: coordinator,
	}
	// The real runtime remains immutable/default-OFF, but validate against the
	// enabled contract so disabled construction hides no missing current P2/CP
	// component. Only the named external P3 prerequisite may remain blocked.
	if reasons := handoffSchedulerBlockReasons(HandoffSchedulerActivationConfig{
		Enabled: true, Pool: dependencies.Pool, Elector: dependencies.Elector, HealthObserver: dependencies.HealthObserver,
		MigrationGate: dependencies.MigrationGate, TickSource: dependencies.TickSource, P2Issuer: dependencies.P2Issuer,
		P2Reader: dependencies.P2Reader, OperationProvenance: dependencies.OperationProvenance, CoordinatorService: dependencies.CoordinatorService,
		Timing: HandoffSchedulerTiming{Cadence: serverConfig.Cadence, PerTickTimeout: serverConfig.PerTickTimeout, MaxBackoff: serverConfig.MaxBackoff, SerialBatchSize: serverConfig.SerialBatchSize},
	}); len(reasons) != 0 {
		return nil, fmt.Errorf("handoff scheduler dependency graph is incomplete")
	}
	runtime := NewHandoffSchedulerServerRuntime(serverConfig, dependencies)
	bootstrapSource := NewPostgresHandoffBootstrapPlanSource(pool, HandoffBootstrapPlanSourceConfig{LeaseTTL: 30 * time.Second})
	var transition HandoffOwnershipModeTransition
	if enabled {
		transition, err = NewPostgresHandoffOwnershipModeTransition(pool, base, authority, HandoffHATransitionConfig{MaxAckAge: referenceAckFreshness, AuthorityTTL: 5 * time.Minute, ClockSkewMargin: referenceClockSkew})
		if err != nil {
			return nil, err
		}
	}
	bootstrap := NewHandoffBootstrapReconciler(HandoffBootstrapConfig{}, bootstrapSource, bootstrapIssuer, bridge, transition)
	activation := NewHandoffHAActivationRuntime(HandoffHAActivationRuntimeConfig{Enabled: enabled, Cadence: 5 * time.Second, MaxAckAge: referenceAckFreshness}, pool, elector, bootstrapSource, bootstrapIssuer, bridge, transition)
	return &HandoffSchedulerDefaultOffComposition{Runtime: runtime, P2: bridge, Bootstrap: bootstrap, Activation: activation}, nil
}
