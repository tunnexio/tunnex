package k8s

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestHandoffCoordinatorCrashRestartPhases(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	fixture := seedHandoffCoordinatorFixture(t, ctx, pool)
	transport := &recordingHandoffTransport{}

	// Each call uses a new coordinator object: no in-memory phase or receipt
	// state is retained across a simulated process crash/restart.
	steps := []struct {
		name     string
		ack      func(HandoffCoordinatorRequest) HandoffCoordinatorRequest
		phase    HandoffPhase
		action   HandoffAction
		calls    int
		terminal bool
	}{
		{name: "prepare candidate", phase: HandoffAwaitPreparedAck, action: HandoffDeliverPrepared, calls: 1},
		{name: "restart waits for prepared acknowledgement", phase: HandoffAwaitPreparedAck, action: HandoffRefuse, calls: 1},
		{name: "prepared acknowledgement delivers withdrawal", ack: func(r HandoffCoordinatorRequest) HandoffCoordinatorRequest {
			a := preparedAck(r.Plan.Plan.NewPrepared, r.Now.Add(-time.Second))
			r.PreparedAck = &a
			return r
		}, phase: HandoffAwaitWithdrawal, action: HandoffDeliverWithdrawal, calls: 2},
		{name: "duplicate prepared acknowledgement is inert", ack: func(r HandoffCoordinatorRequest) HandoffCoordinatorRequest {
			a := preparedAck(r.Plan.Plan.NewPrepared, r.Now.Add(-time.Second))
			r.PreparedAck = &a
			return r
		}, phase: HandoffAwaitWithdrawal, action: HandoffRefuse, calls: 2},
		{name: "withdrawal acknowledgement records CAS readiness", ack: func(r HandoffCoordinatorRequest) HandoffCoordinatorRequest {
			a := coordinatorWithdrawalAck(r.Plan.Plan, r.Now.Add(-time.Second))
			r.WithdrawalAck = &a
			return r
		}, phase: HandoffCASActive, action: HandoffRecordCASReady, calls: 2},
		{name: "CAS is the only active owner change", phase: HandoffEnableServing, action: HandoffApplyCAS, calls: 2},
		{name: "restart enables new serving artifact", phase: HandoffAwaitServingAck, action: HandoffDeliverServing, calls: 3},
		{name: "serving acknowledgement finalizes", ack: func(r HandoffCoordinatorRequest) HandoffCoordinatorRequest {
			a := ArtifactAcknowledgement{Artifact: r.Plan.Plan.NewServing, ReceiptAt: r.Now.Add(-time.Second), ServingAttested: true}
			r.ServingAck = &a
			return r
		}, phase: HandoffFinalize, action: HandoffFinalizeSuccess, calls: 3},
		{name: "finalize completes", phase: HandoffComplete, action: HandoffFinalizeSuccess, calls: 3, terminal: true},
		{name: "terminal retry never reopens", phase: HandoffComplete, action: HandoffAlreadyComplete, calls: 3, terminal: true},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			req := fixture.request
			if step.ack != nil {
				req = step.ack(req)
			}
			coordinator := NewHandoffCoordinator(NewService(pool), transport)
			result, err := coordinator.Tick(ctx, req)
			if err != nil {
				t.Fatalf("tick: %v", err)
			}
			if result.Phase != step.phase || result.Action != step.action || result.Terminal != step.terminal {
				t.Fatalf("result=%+v, want phase=%s action=%s terminal=%t", result, step.phase, step.action, step.terminal)
			}
			if got := transport.count(); got != step.calls {
				t.Fatalf("transport calls=%d, want %d", got, step.calls)
			}
		})
	}
	state, err := fixture.service.q.GetK8sConnectorPoolForOrg(ctx, sqlc.GetK8sConnectorPoolForOrgParams{OrgID: fixture.orgID, ID: fixture.poolID})
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveNodeID != fixture.newNodeID || state.Generation != 2 || state.PreferredNodeID != fixture.oldNodeID {
		t.Fatalf("only CAS may update active/generation and preserve preferred: %+v", state)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.connector_pool.handoff_applied'`, fixture.orgID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("handoff CAS audit count=%d, want 1", audits)
	}
}

func TestHandoffCoordinatorConcurrentStartHasOneOperationAndDelivery(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	fixture := seedHandoffCoordinatorFixture(t, ctx, pool)
	transport := &recordingHandoffTransport{}
	start := make(chan struct{})
	results := make(chan HandoffCoordinatorResult, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := NewHandoffCoordinator(NewService(pool), transport).Tick(ctx, fixture.request)
			results <- result
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	applied, waiting := 0, 0
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent tick: %v", err)
		}
	}
	for result := range results {
		if result.Applied {
			applied++
		}
		if result.Waiting || result.Conflict {
			waiting++
		}
	}
	if applied != 1 || waiting != 1 || transport.count() != 1 {
		t.Fatalf("one active operation/delivery required: applied=%d waiting-or-conflict=%d calls=%d", applied, waiting, transport.count())
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_connector_handoff_operations WHERE pool_id=$1 AND phase NOT IN ('complete','failed')`, fixture.poolID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("nonterminal operations=%d, want 1", count)
	}
}

func TestHandoffCoordinatorFailedOperationNeverReopens(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	fixture := seedHandoffCoordinatorFixture(t, ctx, pool)
	transport := &recordingHandoffTransport{}
	coordinator := NewHandoffCoordinator(fixture.service, transport)
	if _, err := coordinator.Tick(ctx, fixture.request); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_connector_handoff_operations SET phase='failed', failure_reason='test terminal state' WHERE id=$1`, fixture.request.Plan.Plan.OperationID); err != nil {
		t.Fatal(err)
	}
	result, err := NewHandoffCoordinator(NewService(pool), transport).Tick(ctx, fixture.request)
	if err != nil || !result.Terminal || result.Phase != "failed" || transport.count() != 1 {
		t.Fatalf("failed operation reopened: result=%+v err=%v calls=%d", result, err, transport.count())
	}
}

type handoffCoordinatorFixture struct {
	service               *Service
	orgID, siteID, poolID uuid.UUID
	oldNodeID, newNodeID  uuid.UUID
	request               HandoffCoordinatorRequest
}

func seedHandoffCoordinatorFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) handoffCoordinatorFixture {
	t.Helper()
	orgID, siteID := seedOrgSite(t, pool)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", orgID) })
	oldNodeID, newNodeID, clusterID := uuid.New(), uuid.New(), uuid.New()
	for name, nodeID := range map[string]uuid.UUID{"old": oldNodeID, "new": newNodeID} {
		if _, err := pool.Exec(ctx, `INSERT INTO nodes (id, org_id, name, cert_serial, site_id, status) VALUES ($1,$2,$3,$4,$5,'active')`, nodeID, orgID, name, "handoff-coordinator-"+name+"-"+nodeID.String()[:8], siteID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_clusters (id, org_id, site_id, name, vip_range) VALUES ($1,$2,$3,'handoff-coordinator','100.121.0.0/24')`, clusterID, orgID, siteID); err != nil {
		t.Fatal(err)
	}
	service := NewService(pool)
	created, err := service.q.CreateK8sConnectorPool(ctx, sqlc.CreateK8sConnectorPoolParams{ClusterID: clusterID, OrgID: orgID, PreferredNodeID: oldNodeID, ActiveNodeID: oldNodeID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.q.AddK8sConnectorPoolMember(ctx, sqlc.AddK8sConnectorPoolMemberParams{PoolID: created.ID, OrgID: orgID, NodeID: newNodeID, AdminPriority: 1}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope := HandoffPoolScope{OrgID: orgID, SiteID: siteID, PoolID: created.ID, ClusterID: clusterID}
	old := coordinatorArtifact(scope, oldNodeID, 1, 10, 1, Serving, "old-serving", now.Add(time.Minute))
	prepared := coordinatorArtifact(scope, newNodeID, 2, 11, 2, PreparedNonServing, "new-prepared", now.Add(5*time.Minute))
	serving := coordinatorArtifact(scope, newNodeID, 2, 12, 2, Serving, "new-serving", now.Add(5*time.Minute))
	withdrawal := coordinatorArtifact(scope, oldNodeID, 2, 11, 2, PreparedNonServing, "old-withdrawal", now.Add(5*time.Minute))
	plan := DurableHandoffPlan{Plan: HandoffPlan{OperationID: uuid.New(), Scope: scope, ExpectedActiveID: oldNodeID, CandidateID: newNodeID, ExpectedGeneration: 1, TargetGeneration: 2,
		Decision:    Decision{Transition: Promoted, FromID: oldNodeID.String(), ToID: newNodeID.String(), Reason: "deterministic health selection", Pool: ConnectorPool{ActiveID: newNodeID.String(), Generation: 2}},
		NewPrepared: prepared, NewServing: serving, OldServing: old, OldWithdrawal: withdrawal}, OldLeaseIdentity: "old-lease", TargetLeaseIdentity: "target-lease"}
	return handoffCoordinatorFixture{service: service, orgID: orgID, siteID: siteID, poolID: created.ID, oldNodeID: oldNodeID, newNodeID: newNodeID,
		request: HandoffCoordinatorRequest{Plan: plan, Now: now, ReportFreshness: time.Minute, MaxAckAge: time.Minute, ClockSkewMargin: time.Second,
			HealthState: HandoffHealthState{StaleTicks: 2, CandidateHealthyTicks: map[uuid.UUID]int{newNodeID: 2}}, Evidence: map[uuid.UUID]ConnectorEvidence{oldNodeID: coordinatorEvidence(oldNodeID, orgID, siteID, now.Add(-2*time.Minute), now), newNodeID: coordinatorEvidence(newNodeID, orgID, siteID, now, now)}}}
}

func coordinatorArtifact(scope HandoffPoolScope, connectorID uuid.UUID, generation, revision, epoch uint64, role OwnershipRole, identity string, expires time.Time) ArtifactPrerequisite {
	routeDigest, vipMapDigest := P2HandoffCanonicalEmptyRouteDigest, ""
	if role == Serving {
		routeDigest = "3333333333333333333333333333333333333333333333333333333333333333"
		vipMapDigest = "4444444444444444444444444444444444444444444444444444444444444444"
	}
	return ArtifactPrerequisite{Scope: OwnershipScope{OrgID: scope.OrgID, SiteID: scope.SiteID, PoolID: scope.PoolID, ClusterID: scope.ClusterID, ConnectorID: connectorID}, PromotionGeneration: generation, ManifestRevision: revision, ManifestIdentity: identity, ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: vipMapDigest, IdentityValidated: true, Lease: CPOwnershipLease{Epoch: epoch, ExpiresAt: expires, CPIssuedValidated: true}, Role: role}
}

func coordinatorEvidence(id, org, site uuid.UUID, seen, reported time.Time) ConnectorEvidence {
	return ConnectorEvidence{ID: id.String(), OrgID: org.String(), SiteID: site.String(), Status: "active", WGPublicKeyReady: true, EndpointReady: true, LastSeenAt: seen, PolicyReportedAt: reported, AppliedPolicyHash: "policy", K8sEndpointViewKnown: true, Policy: PolicyAcknowledgement{ExpectedKnown: true, ExpectedHash: "policy", HealthKnown: true}}
}

func coordinatorWithdrawalAck(plan HandoffPlan, received time.Time) ArtifactAcknowledgement {
	return ArtifactAcknowledgement{Artifact: plan.OldWithdrawal, ReceiptAt: received, NonServingAttested: true, WithdrawalLeaseEpoch: plan.OldServing.Lease.Epoch}
}

type recordingHandoffTransport struct {
	mu         sync.Mutex
	deliveries []HandoffDelivery
}

func (t *recordingHandoffTransport) PrepareCandidate(_ context.Context, d HandoffDelivery) error {
	t.record(d)
	return nil
}
func (t *recordingHandoffTransport) WithdrawOld(_ context.Context, d HandoffDelivery) error {
	t.record(d)
	return nil
}
func (t *recordingHandoffTransport) EnableNew(_ context.Context, d HandoffDelivery) error {
	t.record(d)
	return nil
}
func (t *recordingHandoffTransport) record(d HandoffDelivery) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deliveries = append(t.deliveries, d)
}
func (t *recordingHandoffTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.deliveries)
}
