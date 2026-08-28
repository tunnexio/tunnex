package nodes

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

func TestHandoffBootstrapDefaultOffIsInert(t *testing.T) {
	f := &handoffBootstrapFake{}
	r := NewHandoffBootstrapReconciler(HandoffBootstrapConfig{}, f, f, f, f)
	got, err := r.ReconcileWithLeadership(t.Context(), time.Now().UTC(), k8s.HandoffLeadershipEpoch{}, nil)
	if err != nil || got.State != HandoffBootstrapDisabled || f.calls != 0 {
		t.Fatalf("disabled reconcile=%+v err=%v calls=%d", got, err, f.calls)
	}
}

func TestHandoffBootstrapRequiresCurrentServingAndEveryPreparedV3Ack(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	plan := handoffBootstrapPlan(t, now)
	if !validHandoffBootstrapPlan(plan, now) {
		t.Fatalf("test bootstrap plan is invalid: %+v", plan)
	}
	conn := &pgxpool.Conn{}
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 91, LockKey: leader.SchedulerLockKey}
	f := &handoffBootstrapFake{plan: plan, found: true, attestations: map[uuid.UUID]k8s.P2HandoffAppliedAttestation{}}
	r := NewHandoffBootstrapReconciler(HandoffBootstrapConfig{Enabled: true, MaxAckAge: time.Minute, Scope: plan.Scope}, f, f, f, f)

	// Legacy/mixed-version evidence is durable but never fenced-base authority.
	f.attestations[plan.CurrentOwnerServing.Identity.DeliveryID] = bootstrapAttestation(plan.CurrentOwnerServing, now.Add(-time.Second))
	f.attestations[plan.StandbyPrepared[0].Identity.DeliveryID] = bootstrapAttestation(plan.StandbyPrepared[0], now.Add(-time.Second))
	v2 := bootstrapAttestation(plan.StandbyPrepared[1], now.Add(-time.Second))
	v2.Version = 2
	f.attestations[plan.StandbyPrepared[1].Identity.DeliveryID] = v2
	got, err := r.ReconcileWithLeadership(t.Context(), now, epoch, conn)
	if err != nil || got.State != HandoffBootstrapPending || got.Prerequisite != "" || got.PreparedStandbys != 1 || f.transitionCalls != 0 || f.armCalls != 1 {
		t.Fatalf("mixed-version reconcile=%+v err=%v transition=%d", got, err, f.transitionCalls)
	}
	if len(f.issued) != 3 || f.lastConn != conn || f.lastEpoch != epoch {
		t.Fatalf("exact session/deliveries not propagated: issued=%d conn=%p epoch=%+v", len(f.issued), f.lastConn, f.lastEpoch)
	}

	f.attestations[plan.StandbyPrepared[1].Identity.DeliveryID] = bootstrapAttestation(plan.StandbyPrepared[1], now.Add(-time.Second))
	f.prerequisite = HandoffFencedBaseReady
	got, err = r.ReconcileWithLeadership(t.Context(), now, epoch, conn)
	if err != nil || got.State != HandoffBootstrapReady || got.Prerequisite != HandoffFencedBaseReady || got.PreparedStandbys != 2 || f.transitionCalls != 1 {
		t.Fatalf("exact v3 reconcile=%+v err=%v transition=%d", got, err, f.transitionCalls)
	}
}

func TestHandoffBootstrapDoesNotIssueP2BeforeEveryBaseAuthorityReceipt(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	plan := handoffBootstrapPlan(t, now)
	f := &handoffBootstrapFake{plan: plan, found: true, armPending: true}
	r := NewHandoffBootstrapReconciler(HandoffBootstrapConfig{Enabled: true, MaxAckAge: time.Minute, Scope: plan.Scope}, f, f, f, f)
	got, err := r.ReconcileWithLeadership(t.Context(), now, k8s.HandoffLeadershipEpoch{BackendPID: 90, LockKey: leader.SchedulerLockKey}, &pgxpool.Conn{})
	if err != nil || got.State != HandoffBootstrapPending || f.armCalls != 1 || f.issueCalls != 0 || f.readCalls != 0 || f.transitionCalls != 0 {
		t.Fatalf("authority-pending reconcile=%+v err=%v arm=%d issue=%d read=%d transition=%d", got, err, f.armCalls, f.issueCalls, f.readCalls, f.transitionCalls)
	}
}

func TestHandoffBootstrapRestartReconstructsOnlyFromDurableLedger(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	plan := handoffBootstrapPlan(t, now)
	conn := &pgxpool.Conn{}
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 92, LockKey: leader.SchedulerLockKey}
	durable := &handoffBootstrapFake{plan: plan, found: true, attestations: map[uuid.UUID]k8s.P2HandoffAppliedAttestation{}, prerequisite: HandoffFencedBaseReady}
	first := NewHandoffBootstrapReconciler(HandoffBootstrapConfig{Enabled: true, MaxAckAge: time.Minute, Scope: plan.Scope}, durable, durable, durable, durable)
	if got, err := first.ReconcileWithLeadership(t.Context(), now, epoch, conn); err != nil || got.State != HandoffBootstrapPending {
		t.Fatalf("first reconcile=%+v err=%v", got, err)
	}
	for _, delivery := range append([]k8s.P2HandoffDelivery{plan.CurrentOwnerServing}, plan.StandbyPrepared...) {
		durable.attestations[delivery.Identity.DeliveryID] = bootstrapAttestation(delivery, now.Add(-time.Second))
	}
	// A fresh process has no local progress. It becomes ready only by replaying
	// exact IDs and reading the durable CP receipts above.
	restarted := NewHandoffBootstrapReconciler(HandoffBootstrapConfig{Enabled: true, MaxAckAge: time.Minute, Scope: plan.Scope}, durable, durable, durable, durable)
	got, err := restarted.ReconcileWithLeadership(t.Context(), now, epoch, conn)
	if err != nil || got.State != HandoffBootstrapReady || got.Prerequisite != HandoffFencedBaseReady || len(durable.uniqueIssued) != 3 {
		t.Fatalf("restart reconcile=%+v err=%v unique=%d", got, err, len(durable.uniqueIssued))
	}
}

func TestHandoffBootstrapLeaderLossStopsBeforeReadOrTransition(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	f := &handoffBootstrapFake{plan: handoffBootstrapPlan(t, now), found: true, attestations: map[uuid.UUID]k8s.P2HandoffAppliedAttestation{}, issueFailAt: 2}
	r := NewHandoffBootstrapReconciler(HandoffBootstrapConfig{Enabled: true, MaxAckAge: time.Minute, Scope: f.plan.Scope}, f, f, f, f)
	conn := &pgxpool.Conn{}
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 93, LockKey: leader.SchedulerLockKey}
	got, err := r.ReconcileWithLeadership(t.Context(), now, epoch, conn)
	if !errors.Is(err, ErrHandoffBootstrapLeaderSession) || got.State != HandoffBootstrapPending || f.issueCalls != 2 || f.readCalls != 0 || f.transitionCalls != 0 {
		t.Fatalf("leader loss reconcile=%+v err=%v issue=%d read=%d transition=%d", got, err, f.issueCalls, f.readCalls, f.transitionCalls)
	}
	wrong := epoch
	wrong.LockKey++
	before := f.calls
	if _, err := r.ReconcileWithLeadership(t.Context(), now, wrong, conn); !errors.Is(err, ErrHandoffBootstrapLeaderSession) || f.calls != before {
		t.Fatalf("wrong lock reached dependencies: err=%v calls=%d/%d", err, before, f.calls)
	}
}

type handoffBootstrapFake struct {
	plan            HandoffBootstrapPlan
	found           bool
	attestations    map[uuid.UUID]k8s.P2HandoffAppliedAttestation
	prerequisite    HandoffFencedBasePrerequisite
	calls           int
	issueCalls      int
	issueFailAt     int
	readCalls       int
	transitionCalls int
	armCalls        int
	armPending      bool
	issued          []PoolVIPOwnershipDeliveryEnvelopeV3
	uniqueIssued    map[uuid.UUID]struct{}
	lastEpoch       k8s.HandoffLeadershipEpoch
	lastConn        *pgxpool.Conn
}

func (f *handoffBootstrapFake) record(epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) {
	f.calls++
	f.lastEpoch, f.lastConn = epoch, conn
}

func (f *handoffBootstrapFake) LoadHandoffBootstrapPlanWithLeadership(_ context.Context, _ time.Time, _ k8s.HandoffPoolScope, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (HandoffBootstrapPlan, bool, error) {
	f.record(epoch, conn)
	return f.plan, f.found, nil
}

func (f *handoffBootstrapFake) IssueHandoffBootstrapEnvelopeWithLeadership(_ context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, envelope PoolVIPOwnershipDeliveryEnvelopeV3) error {
	f.record(epoch, conn)
	f.issueCalls++
	if f.issueFailAt == f.issueCalls {
		return ErrHandoffBootstrapLeaderSession
	}
	f.issued = append(f.issued, envelope)
	if f.uniqueIssued == nil {
		f.uniqueIssued = map[uuid.UUID]struct{}{}
	}
	f.uniqueIssued[uuid.MustParse(envelope.DeliveryID)] = struct{}{}
	return nil
}

func (f *handoffBootstrapFake) LoadP2HandoffAppliedAttestationWithLeadership(_ context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, identity k8s.P2HandoffDeliveryIdentity) (k8s.P2HandoffAppliedAttestation, bool, error) {
	f.record(epoch, conn)
	f.readCalls++
	value, ok := f.attestations[identity.DeliveryID]
	return value, ok, nil
}

func (f *handoffBootstrapFake) ArmHandoffOwnershipBaseWithLeadership(_ context.Context, _ time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, plan HandoffBootstrapPlan) (HandoffBaseAuthorityArmSnapshot, bool, error) {
	f.record(epoch, conn)
	f.armCalls++
	// Existing unit fixtures model already-received authority unless a test
	// explicitly asks to hold bootstrap before P2 issuance.
	return HandoffBaseAuthorityArmSnapshot{TransitionRevision: 1, Members: []HandoffBaseAuthorityArmMember{{NodeID: plan.ActiveNodeID, AuthorityRevision: 1, BaseVersion: 1}}}, !f.armPending, nil
}

func (f *handoffBootstrapFake) ConfirmHandoffOwnershipModeTransitionWithLeadership(_ context.Context, _ time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, _ HandoffBootstrapPlan, _ HandoffBaseAuthorityArmSnapshot) (HandoffFencedBasePrerequisite, error) {
	f.record(epoch, conn)
	f.transitionCalls++
	return f.prerequisite, nil
}

func handoffBootstrapPlan(t *testing.T, now time.Time) HandoffBootstrapPlan {
	t.Helper()
	active := uuid.MustParse("00000000-0000-4000-8000-000000000030")
	standbys := []uuid.UUID{uuid.MustParse("00000000-0000-4000-8000-000000000031"), uuid.MustParse("00000000-0000-4000-8000-000000000032")}
	port := int32(443)
	scope := k8s.HandoffPoolScope{OrgID: uuid.MustParse("00000000-0000-4000-8000-000000000011"), SiteID: uuid.MustParse("00000000-0000-4000-8000-000000000012"),
		ClusterID: uuid.MustParse("00000000-0000-4000-8000-000000000013"), PoolID: uuid.MustParse("00000000-0000-4000-8000-000000000014")}
	topology := handoffBootstrapTopology{Scope: scope, Generation: 7, ActiveNodeID: active, ClusterName: "cluster", DNSZone: "k8s.example", DNSVIP: "100.64.0.2",
		ServiceCIDR: "10.96.0.0/12", DevicePoolCIDR: "10.44.0.0/16", EdgeWGPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Counters: map[uuid.UUID]handoffBootstrapCounter{},
		Services: []handoffBootstrapService{{ID: uuid.MustParse("00000000-0000-4000-8000-000000000020"), Namespace: "default", Name: "api", VIP: "100.64.0.10", Protocol: "tcp", PortLow: &port, PortHigh: &port, UID: "uid-api", ObservationRevision: 9}}}
	keys := []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}
	for i, id := range append([]uuid.UUID{active}, standbys...) {
		topology.Members = append(topology.Members, handoffBootstrapMember{NodeID: id, SiteID: scope.SiteID, WGPublicKey: keys[i], Endpoint: fmt.Sprintf("10.0.0.%d:51820", i+1)})
		topology.Counters[id] = handoffBootstrapCounter{ManifestRevision: uint64(20 + i), LeaseEpoch: uint64(30 + i)}
	}
	plan, err := buildHandoffBootstrapPlan(topology, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func bootstrapAttestation(delivery k8s.P2HandoffDelivery, receipt time.Time) k8s.P2HandoffAppliedAttestation {
	i := delivery.Identity
	return k8s.P2HandoffAppliedAttestation{Version: k8s.P2HandoffAttestationVersion, Identity: i, CPReceiptAt: receipt, DeliveryExpiresAt: delivery.LeaseExpiresAt,
		AppliedRole: i.Role, AppliedManifestIdentity: i.ManifestIdentity, AppliedPromotionGeneration: i.PromotionGeneration,
		AppliedManifestRevision: i.ManifestRevision, AppliedLeaseEpoch: i.LeaseEpoch, AppliedRouteDigest: i.ExpectedRouteDigest, AppliedVIPMapDigest: i.ExpectedVIPMapDigest}
}
