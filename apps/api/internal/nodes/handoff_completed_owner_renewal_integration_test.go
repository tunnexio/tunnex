package nodes

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// The former owner stops acknowledging only after an accepted fenced baseline.
// The handoff uses the real P1 coordinator, P2 bridge, provenance, delivery and
// receipt stores. Agent application is represented by exact test ACKs; no
// withdrawal ACK is supplied. Only the existing scheduler-clock argument and
// ordinary-base compiler seam are controlled, so no lease wait or host is needed.
func newCompletedOwnerRenewalFixture(t *testing.T) (*wakeVersionRenewalFixture, k8s.DurableHandoffPlan, time.Time) {
	t.Helper()
	f := newWakeVersionRenewalFixture(t)
	oldOwner, newOwner, otherStandby := f.fixture.active, f.fixture.standbyA, f.fixture.standbyB
	deliveries := NewPostgresPoolVIPOwnershipDeliveryStore(f.pool)
	for _, node := range []uuid.UUID{oldOwner, newOwner, otherStandby} {
		ackCompletedOwnerDelivery(t, f, deliveries, node)
	}
	provenance := NewPostgresPoolVIPOwnershipFreshHandoffProvenance(f.pool, nil)
	bridge, err := NewPoolVIPOwnershipP2HandoffBridge(deliveries, provenance)
	if err != nil {
		t.Fatal(err)
	}
	adapter := k8s.NewP2HandoffAdapter(bridge, bridge)
	coordinator := k8s.NewHandoffCoordinator(k8s.NewService(f.pool), adapter).WithHandoffOperationProvenanceFence(provenance)
	var membershipEpoch uint64
	if err := f.pool.QueryRow(f.ctx, `SELECT membership_epoch FROM k8s_connector_pool_health_states WHERE org_id=$1 AND pool_id=$2`, f.fixture.scope.OrgID, f.fixture.scope.PoolID).Scan(&membershipEpoch); err != nil {
		t.Fatal(err)
	}
	members := []uuid.UUID{oldOwner, newOwner, otherStandby}
	sort.Slice(members, func(i, j int) bool { return members[i].String() < members[j].String() })
	intent := HandoffTickIntent{OperationID: uuid.New(), Scope: f.fixture.scope, ExpectedActiveID: oldOwner, CandidateID: newOwner,
		ExpectedGeneration: 1, TargetGeneration: 2, ObservedMembershipEpoch: &membershipEpoch, OrderedCandidateIDs: members,
		Decision: k8s.Decision{Transition: k8s.Promoted, FromID: oldOwner.String(), ToID: newOwner.String(), Pool: k8s.ConnectorPool{ActiveID: newOwner.String(), Generation: 2}}}
	plan, found, err := provenance.BuildAndClaimFreshHandoffPlanWithLeadership(f.ctx, intent, f.epoch, f.conn)
	if err != nil || !found {
		t.Fatalf("real fresh handoff claim found=%t err=%v", found, err)
	}
	q := sqlc.New(f.pool)
	operation := func() sqlc.K8sConnectorHandoffOperation {
		t.Helper()
		op, err := q.GetK8sConnectorHandoffOperation(f.ctx, sqlc.GetK8sConnectorHandoffOperationParams{OperationID: intent.OperationID, OrgID: intent.Scope.OrgID, SiteID: intent.Scope.SiteID, PoolID: intent.Scope.PoolID})
		if err != nil {
			t.Fatal(err)
		}
		return op
	}
	tick := func(now time.Time, want k8s.HandoffPhase) {
		t.Helper()
		op := operation()
		acks, err := adapter.AcknowledgementsForPhaseWithLeadership(f.ctx, plan, k8s.HandoffPhase(op.Phase), now, 5*time.Minute, f.epoch, f.conn)
		if err != nil {
			t.Fatal(err)
		}
		if acks.Withdrawal != nil {
			t.Fatal("absent old owner unexpectedly supplied a withdrawal ACK")
		}
		result, err := coordinator.TickWithLeadership(f.ctx, k8s.HandoffCoordinatorRequest{Plan: plan, CurrentPhase: k8s.HandoffPhase(op.Phase), Now: now,
			MaxAckAge: 5 * time.Minute, ClockSkewMargin: time.Second, ObservedMembershipEpoch: &membershipEpoch,
			PreparedAck: acks.Prepared, ServingAck: acks.Serving}, f.epoch, f.conn)
		if err != nil || result.Conflict || result.Phase != want {
			t.Fatalf("durable phase %s -> %s: result=%+v err=%v", op.Phase, want, result, err)
		}
	}
	tick(f.now, k8s.HandoffAwaitPreparedAck)
	ackCompletedOwnerDelivery(t, f, deliveries, newOwner)
	tick(f.now, k8s.HandoffAwaitWithdrawal)
	// Use the production evaluator's explicit CP-time seam. This is expiry
	// evaluation proof, not a claim that real database wall time has elapsed.
	completedAt := plan.Plan.OldServing.Lease.ExpiresAt.Add(time.Second)
	tick(completedAt, k8s.HandoffCASActive)
	tick(completedAt, k8s.HandoffEnableServing)
	tick(completedAt, k8s.HandoffAwaitServingAck)
	ackCompletedOwnerDelivery(t, f, deliveries, newOwner)
	tick(completedAt, k8s.HandoffFinalize)
	tick(completedAt, k8s.HandoffComplete)
	op := operation()
	if !op.WithdrawalExpiryReceivedAt.Valid || op.WithdrawalAckReceivedAt.Valid || !op.CasAuditApplied || !op.CasAuditID.Valid || !op.ServingAckReceivedAt.Valid ||
		op.OldNodeID != oldOwner || op.NewNodeID != newOwner || op.TargetGeneration != 2 {
		t.Fatalf("completed handoff lacks exact expiry/CAS/serving proof: %+v", op)
	}
	// The newly selected connector reports the same real Service incarnation
	// through the normal observation validator/store, not a rewritten ledger.
	agent := K8sServiceUIDObservationAgent{NodeID: newOwner, OrgID: f.fixture.scope.OrgID}
	report := testK8sServiceUIDObservationReport(1, K8sServiceUIDObservation{Namespace: "default", Service: "api", UID: "uid-api-v1", State: "live"})
	_, err = NewPostgresK8sServiceUIDObservationStore(f.pool).UpdateK8sServiceUIDObservations(f.ctx, agent, report, f.now,
		func(scope K8sServiceUIDObservationScope, state K8sServiceUIDObservationState, receipt time.Time) (K8sServiceUIDObservationValidation, error) {
			return ValidateK8sServiceUIDObservations(receipt, agent, scope, report, state)
		})
	if err != nil {
		t.Fatalf("new selected connector Service UID observation: %v", err)
	}
	return f, plan, completedAt
}

func TestHandoffCompletedExpiredOwnerDoesNotBlockNewOwnerRenewal(t *testing.T) {
	f, _, completedAt := newCompletedOwnerRenewalFixture(t)
	oldOwner, newOwner, otherStandby := f.fixture.active, f.fixture.standbyA, f.fixture.standbyB
	// Only the absent former owner's canonical content changes; all nodes see
	// a normal wake. Generation/classification changes still require B and C's
	// exact full-base ACKs before any renewed serving delivery can be issued.
	f.base.Version++
	base := HandoffBaseStateSourceFunc(func(_ context.Context, _ uuid.UUID, node uuid.UUID) (DesiredState, error) {
		value := f.baseFor(node)
		if node == oldOwner {
			value.MTU--
		}
		return value, nil
	})
	transition, err := NewPostgresHandoffOwnershipModeTransition(f.pool, base, f.store, HandoffHATransitionConfig{MaxAckAge: time.Minute, AuthorityTTL: 5 * time.Minute, ClockSkewMargin: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f.runtime.transition = transition
	before := completedOwnerServingExpiry(t, f, newOwner)
	f.reconcile(t, completedAt)
	f.ackPending(t, newOwner, otherStandby)
	for bucket := 1; bucket <= 3; bucket++ {
		f.reconcile(t, completedAt.Add(time.Duration(bucket)*wakeVersionRenewalLeaseTTL))
		if got := completedOwnerServingExpiry(t, f, newOwner); !got.After(before) {
			t.Errorf("completed handoff healthy new owner did not renew at bucket %d while expired former owner alone lacks changed-base ACK: expiry=%s previous=%s", bucket, got.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano))
		} else {
			before = got
		}
	}
	pending, found, err := f.store.LoadPendingKubernetesOwnershipBaseAuthority(f.ctx, KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: oldOwner, OrgID: f.fixture.scope.OrgID, SiteID: f.fixture.scope.SiteID})
	oldHash, hashErr := KubernetesOwnershipBaseStateHash(f.baseFor(oldOwner))
	if err != nil || !found || hashErr != nil || pending.BaseHash == oldHash {
		t.Fatalf("former owner must retain a genuinely changed, unACKed full-base authority: found=%t hashChanged=%t err=%v/%v", found, pending.BaseHash != oldHash, err, hashErr)
	}
	var newOldServing int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM pool_vip_ownership_deliveries WHERE org_id=$1 AND pool_id=$2 AND target_node_id=$3 AND role='serving' AND promotion_generation >= 2`, f.fixture.scope.OrgID, f.fixture.scope.PoolID, oldOwner).Scan(&newOldServing); err != nil || newOldServing != 0 {
		t.Fatalf("former owner acquired serving authority after handoff: count=%d err=%v", newOldServing, err)
	}
}

func ackCompletedOwnerDelivery(t *testing.T, f *wakeVersionRenewalFixture, store *PostgresPoolVIPOwnershipDeliveryStore, node uuid.UUID) {
	t.Helper()
	_, envelope, err := scanPoolVIPOwnershipDeliveryV3(f.pool.QueryRow(f.ctx, poolVIPOwnershipDeliveryV3Select+` WHERE wire_version=3 AND org_id=$1 AND pool_id=$2 AND target_node_id=$3 ORDER BY manifest_revision DESC LIMIT 1`, f.fixture.scope.OrgID, f.fixture.scope.PoolID, node))
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Role == "withdrawal" {
		t.Fatal("test must never acknowledge the absent owner's withdrawal")
	}
	agent := PoolVIPOwnershipAgentIdentity{NodeID: node, OrgID: f.fixture.scope.OrgID}
	ack := ownershipAckV3(envelope)
	if _, err := store.UpdatePoolVIPOwnershipAckV3(f.ctx, agent, ack, f.now, validateOwnershipDeliveryAckV3(agent, ack, f.now)); err != nil {
		t.Fatalf("exact P2 %s ACK: %v", envelope.Role, err)
	}
}

func completedOwnerServingExpiry(t *testing.T, f *wakeVersionRenewalFixture, node uuid.UUID) time.Time {
	t.Helper()
	var expires time.Time
	if err := f.pool.QueryRow(f.ctx, `SELECT max(expires_at) FROM pool_vip_ownership_deliveries WHERE org_id=$1 AND pool_id=$2 AND target_node_id=$3 AND wire_version=3 AND role='serving'`, f.fixture.scope.OrgID, f.fixture.scope.PoolID, node).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	return expires
}
