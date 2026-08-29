package nodes

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

func TestP2AttestingHandoffRunnerReloadsExactDurablePhaseAfterRestart(t *testing.T) {
	now := time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC)
	plan := attestingRunnerPlan(now)
	prepared, err := k8s.P2HandoffDeliveryForPlanArtifact(plan, k8s.P2NewPreparedArtifact)
	if err != nil {
		t.Fatal(err)
	}
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 31, LockKey: 37}
	conn := &pgxpool.Conn{}
	reader := &attestingRunnerReader{epoch: epoch, conn: conn, items: map[uuid.UUID]k8s.P2HandoffAppliedAttestation{
		prepared.Identity.DeliveryID: attestingRunnerApplied(prepared, now.Add(-time.Second)),
	}}
	req := k8s.HandoffCoordinatorRequest{Plan: plan, CurrentPhase: k8s.HandoffAwaitPreparedAck, Now: now, MaxAckAge: time.Minute}

	for restart := range 2 {
		coordinator := &attestingRunnerCoordinator{}
		runner := newP2AttestingHandoffRunner(coordinator, k8s.NewP2HandoffAdapter(nil, reader))
		if _, err := runner.TickWithLeadership(context.Background(), req, epoch, conn); err != nil {
			t.Fatalf("restart %d: %v", restart, err)
		}
		if coordinator.calls != 1 || coordinator.request.PreparedAck == nil || coordinator.request.WithdrawalAck != nil || coordinator.request.ServingAck != nil {
			t.Fatalf("restart %d request=%+v", restart, coordinator.request)
		}
	}
	if reader.boundCalls != 2 || reader.unboundCalls != 0 {
		t.Fatalf("durable phase reads bound=%d generic=%d", reader.boundCalls, reader.unboundCalls)
	}
}

func TestP2AttestingHandoffRunnerDoesNotSurfaceWrongPhaseOrSourceAck(t *testing.T) {
	now := time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC)
	plan := attestingRunnerPlan(now)
	serving, err := k8s.P2HandoffDeliveryForPlanArtifact(plan, k8s.P2NewServingArtifact)
	if err != nil {
		t.Fatal(err)
	}
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 41, LockKey: 43}
	conn := &pgxpool.Conn{}
	reader := &attestingRunnerReader{epoch: epoch, conn: conn, items: map[uuid.UUID]k8s.P2HandoffAppliedAttestation{
		serving.Identity.DeliveryID: attestingRunnerApplied(serving, now.Add(-time.Second)),
	}}
	coordinator := &attestingRunnerCoordinator{}
	runner := newP2AttestingHandoffRunner(coordinator, k8s.NewP2HandoffAdapter(nil, reader))
	req := k8s.HandoffCoordinatorRequest{Plan: plan, CurrentPhase: k8s.HandoffAwaitWithdrawal, Now: now, MaxAckAge: time.Minute}
	if _, err := runner.TickWithLeadership(context.Background(), req, epoch, conn); err != nil {
		t.Fatal(err)
	}
	if coordinator.request.PreparedAck != nil || coordinator.request.WithdrawalAck != nil || coordinator.request.ServingAck != nil || reader.last.Role != k8s.P2HandoffWithdrawal {
		t.Fatalf("wrong-phase evidence surfaced: request=%+v lookup=%+v", coordinator.request, reader.last)
	}

	req.ServingAck = &k8s.ArtifactAcknowledgement{}
	if _, err := runner.TickWithLeadership(context.Background(), req, epoch, conn); err == nil || coordinator.calls != 1 {
		t.Fatalf("source-supplied acknowledgement accepted: calls=%d err=%v", coordinator.calls, err)
	}
}

func attestingRunnerPlan(now time.Time) k8s.DurableHandoffPlan {
	active, candidate := uuid.New(), uuid.New()
	intent := HandoffTickIntent{
		OperationID:      uuid.New(),
		Scope:            k8s.HandoffPoolScope{OrgID: uuid.New(), SiteID: uuid.New(), PoolID: uuid.New(), ClusterID: uuid.New()},
		ExpectedActiveID: active, CandidateID: candidate, ExpectedGeneration: 7, TargetGeneration: 8,
	}
	return testHandoffPlan(intent, now)
}

func attestingRunnerApplied(delivery k8s.P2HandoffDelivery, receipt time.Time) k8s.P2HandoffAppliedAttestation {
	appliedLease := delivery.Identity.LeaseEpoch
	if delivery.Identity.Role == k8s.P2HandoffWithdrawal {
		appliedLease = delivery.Identity.PriorLeaseEpoch
	}
	return k8s.P2HandoffAppliedAttestation{
		Version: k8s.P2HandoffAttestationVersion, Identity: delivery.Identity, CPReceiptAt: receipt, DeliveryExpiresAt: delivery.LeaseExpiresAt,
		AppliedRole: delivery.Identity.Role, AppliedManifestIdentity: delivery.Identity.ManifestIdentity,
		AppliedPromotionGeneration: delivery.Identity.PromotionGeneration, AppliedManifestRevision: delivery.Identity.ManifestRevision,
		AppliedLeaseEpoch: appliedLease, AppliedRouteDigest: delivery.Identity.ExpectedRouteDigest, AppliedVIPMapDigest: delivery.Identity.ExpectedVIPMapDigest,
	}
}

type attestingRunnerCoordinator struct {
	calls   int
	request k8s.HandoffCoordinatorRequest
}

func (c *attestingRunnerCoordinator) TickWithLeadership(_ context.Context, req k8s.HandoffCoordinatorRequest, _ k8s.HandoffLeadershipEpoch, _ *pgxpool.Conn) (k8s.HandoffCoordinatorResult, error) {
	c.calls++
	c.request = req
	return k8s.HandoffCoordinatorResult{}, nil
}

type attestingRunnerReader struct {
	epoch        k8s.HandoffLeadershipEpoch
	conn         *pgxpool.Conn
	items        map[uuid.UUID]k8s.P2HandoffAppliedAttestation
	last         k8s.P2HandoffDeliveryIdentity
	boundCalls   int
	unboundCalls int
}

func (r *attestingRunnerReader) LoadP2HandoffAppliedAttestation(_ context.Context, identity k8s.P2HandoffDeliveryIdentity) (k8s.P2HandoffAppliedAttestation, bool, error) {
	r.unboundCalls++
	v, ok := r.items[identity.DeliveryID]
	return v, ok, nil
}

func (r *attestingRunnerReader) LoadP2HandoffAppliedAttestationWithLeadership(_ context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, identity k8s.P2HandoffDeliveryIdentity) (k8s.P2HandoffAppliedAttestation, bool, error) {
	if epoch != r.epoch || conn != r.conn {
		return k8s.P2HandoffAppliedAttestation{}, false, k8s.ErrHandoffLeadershipUnavailable
	}
	r.boundCalls++
	r.last = identity
	v, ok := r.items[identity.DeliveryID]
	return v, ok, nil
}
