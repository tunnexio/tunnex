package nodes

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

func TestOrdinaryBaseAuthorityRequiresExactAcceptedPoolSet(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	for _, tc := range []struct {
		name       string
		accepted   []uuid.UUID
		classified map[uuid.UUID]struct{}
		want       bool
	}{
		{name: "exact", accepted: []uuid.UUID{a, b}, classified: map[uuid.UUID]struct{}{b: {}, a: {}}, want: true},
		{name: "omitted armed", accepted: []uuid.UUID{a, b}, classified: map[uuid.UUID]struct{}{a: {}}},
		{name: "extra unarmed", accepted: []uuid.UUID{a}, classified: map[uuid.UUID]struct{}{a: {}, b: {}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameAcceptedKubernetesOwnershipClassificationPools(tc.accepted, tc.classified); got != tc.want {
				t.Fatalf("pool-set match=%v want=%v", got, tc.want)
			}
		})
	}
}

type ordinaryBaseMaintenanceFake struct {
	*handoffBootstrapFake
	maintenanceCalls int
	maintenancePlans []HandoffBootstrapPlan
	maintenanceReady bool
	maintenanceErr   error
}

func (f *ordinaryBaseMaintenanceFake) MaintainHandoffOrdinaryBaseAuthorityWithLeadership(_ context.Context, _ time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, plans []HandoffBootstrapPlan) (bool, error) {
	f.maintenanceCalls++
	f.lastEpoch, f.lastConn = epoch, conn
	f.maintenancePlans = append([]HandoffBootstrapPlan(nil), plans...)
	return f.maintenanceReady, f.maintenanceErr
}

func TestFencedPoolReconcileMaintainsOrdinaryBaseBeforeLeaseRenewal(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	plan := handoffBootstrapPlan(t, now)
	base := &handoffBootstrapFake{plan: plan, found: true}
	fake := &ordinaryBaseMaintenanceFake{handoffBootstrapFake: base, maintenanceReady: true}
	runtime := &HandoffHAActivationRuntime{source: fake, issuer: fake, transition: fake}
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 73, LockKey: leader.SchedulerLockKey}
	conn := &pgxpool.Conn{}

	if err := runtime.reconcileFencedPools(t.Context(), now, epoch, conn, []k8s.HandoffPoolScope{plan.Scope}); err != nil {
		t.Fatalf("reconcile fenced pool: %v", err)
	}
	if fake.maintenanceCalls != 1 || !reflect.DeepEqual(fake.maintenancePlans, []HandoffBootstrapPlan{plan}) {
		t.Fatalf("ordinary-base maintenance calls=%d plans=%+v", fake.maintenanceCalls, fake.maintenancePlans)
	}
	if fake.issueCalls != 1+len(plan.StandbyEnvelopes) {
		t.Fatalf("lease issues=%d, want owner plus every standby", fake.issueCalls)
	}
	if fake.lastEpoch != epoch || fake.lastConn != conn {
		t.Fatalf("reconcile escaped exact leader session: epoch=%+v conn=%p", fake.lastEpoch, fake.lastConn)
	}
}

func TestFencedPoolReconcileWaitsForOrdinaryBaseAckBeforeLeaseRenewal(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	plan := handoffBootstrapPlan(t, now)
	base := &handoffBootstrapFake{plan: plan, found: true}
	fake := &ordinaryBaseMaintenanceFake{handoffBootstrapFake: base}
	runtime := &HandoffHAActivationRuntime{source: fake, issuer: fake, transition: fake}

	if err := runtime.reconcileFencedPools(t.Context(), now, k8s.HandoffLeadershipEpoch{BackendPID: 75, LockKey: leader.SchedulerLockKey}, &pgxpool.Conn{}, []k8s.HandoffPoolScope{plan.Scope}); err != nil {
		t.Fatalf("reconcile fenced pool: %v", err)
	}
	if fake.maintenanceCalls != 1 || fake.issueCalls != 0 {
		t.Fatalf("pending authority must gate lease renewal: maintenance=%d issues=%d", fake.maintenanceCalls, fake.issueCalls)
	}
}

func TestFencedPoolReconcileDoesNotRenewLeaseWhenOrdinaryBaseAuthorityFails(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	plan := handoffBootstrapPlan(t, now)
	base := &handoffBootstrapFake{plan: plan, found: true}
	fake := &ordinaryBaseMaintenanceFake{handoffBootstrapFake: base, maintenanceErr: ErrKubernetesOwnershipBaseAuthorityConflict}
	runtime := &HandoffHAActivationRuntime{source: fake, issuer: fake, transition: fake}
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 74, LockKey: leader.SchedulerLockKey}

	err := runtime.reconcileFencedPools(t.Context(), now, epoch, &pgxpool.Conn{}, []k8s.HandoffPoolScope{plan.Scope})
	if !errors.Is(err, ErrKubernetesOwnershipBaseAuthorityConflict) || fake.issueCalls != 0 {
		t.Fatalf("authority failure must precede lease renewal: err=%v issues=%d", err, fake.issueCalls)
	}
}
