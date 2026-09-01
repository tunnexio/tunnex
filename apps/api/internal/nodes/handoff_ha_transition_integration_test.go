package nodes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

func TestPostgresHandoffHATransitionArmsEveryMemberBeforeP2(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run HA transition PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := newHandoffEndToEndTestDB(t, ctx, admin)
	fixture := seedHandoffBootstrapIntegration(t, ctx, pool)
	if err := db.MigrateTo(pool.Config().ConnString(), 130); err != nil {
		t.Fatal(err)
	}
	const membershipEpoch int64 = 0
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_connector_pool_health_states
		(org_id,site_id,cluster_id,pool_id,membership_epoch,observed_active_node_id,observed_generation)
		VALUES($1,$2,$3,$4,$5,$6,1)`, fixture.scope.OrgID, fixture.scope.SiteID, fixture.scope.ClusterID, fixture.scope.PoolID, membershipEpoch, fixture.active); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_ha_settings(org_id,enabled,actor_system,cause) VALUES($1,true,'test','integration activation')`, fixture.scope.OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_connector_pool_ha_transitions
		(pool_id,org_id,site_id,cluster_id,requested_mode,actual_mode,active_node_id,promotion_generation,membership_epoch,actor_system,cause)
		VALUES($1,$2,$3,$4,'fenced_ha','bootstrap_pending',$5,1,$6,'test','integration activation')`, fixture.scope.PoolID, fixture.scope.OrgID, fixture.scope.SiteID, fixture.scope.ClusterID, fixture.active, membershipEpoch); err != nil {
		t.Fatal(err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	var pid int32
	var granted bool
	if err := conn.QueryRow(ctx, `SELECT pg_backend_pid(),pg_try_advisory_lock($1)`, leader.SchedulerLockKey).Scan(&pid, &granted); err != nil || !granted {
		t.Fatalf("leader lock pid=%d granted=%t err=%v", pid, granted, err)
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, leader.SchedulerLockKey) //nolint:errcheck
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: pid, LockKey: leader.SchedulerLockKey}
	now := time.Now().UTC().Truncate(time.Microsecond)
	plan, found, err := NewPostgresHandoffBootstrapPlanSource(pool, HandoffBootstrapPlanSourceConfig{LeaseTTL: 5 * time.Minute}).LoadHandoffBootstrapPlanWithLeadership(ctx, now, fixture.scope, epoch, conn)
	if err != nil || !found {
		t.Fatalf("plan found=%t err=%v", found, err)
	}
	base := HandoffBaseStateSourceFunc(func(_ context.Context, orgID, nodeID uuid.UUID) (DesiredState, error) {
		return DesiredState{ProtocolVersion: 9, NodeID: nodeID.String(), InterfaceAddress: "10.44.0.1/16", MTU: 1420, ListenPort: 51820, Version: 17, Peers: []Peer{}}, nil
	})
	store := NewPostgresKubernetesOwnershipBaseAuthorityStore(pool)
	transition, err := NewPostgresHandoffOwnershipModeTransition(pool, base, store, HandoffHATransitionConfig{MaxAckAge: time.Minute, AuthorityTTL: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, ready, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now, epoch, conn, plan)
	if err != nil || ready || len(snapshot.Members) != 3 {
		t.Fatalf("first arm ready=%t snapshot=%+v err=%v", ready, snapshot, err)
	}
	for _, member := range snapshot.Members {
		agent := KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: member.NodeID, OrgID: fixture.scope.OrgID, SiteID: fixture.scope.SiteID}
		pending, found, err := store.LoadPendingKubernetesOwnershipBaseAuthority(ctx, agent)
		if err != nil || !found {
			t.Fatalf("pending %s found=%t err=%v", member.NodeID, found, err)
		}
		ack := KubernetesOwnershipBaseAuthorityAck{WireVersion: 1, AuthorityRevision: pending.AuthorityRevision, NodeID: pending.NodeID, OrgID: pending.OrgID, SiteID: pending.SiteID,
			BaseVersion: pending.BaseVersion, BaseHash: pending.BaseHash, AuthorityDigest: member.PayloadDigest, AppliedAt: now.Format(time.RFC3339Nano)}
		if _, err := store.AcknowledgeKubernetesOwnershipBaseAuthority(ctx, agent, ack, now); err != nil {
			t.Fatalf("ack %s: %v", member.NodeID, err)
		}
	}
	restarted, ready, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now, epoch, conn, plan)
	if err != nil || !ready || len(restarted.Members) != 3 || restarted.TransitionRevision != snapshot.TransitionRevision {
		t.Fatalf("durable arm ready=%t snapshot=%+v err=%v", ready, restarted, err)
	}
	var deliveries int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_base_authority_deliveries WHERE org_id=$1`, fixture.scope.OrgID).Scan(&deliveries); err != nil || deliveries != 3 {
		t.Fatalf("idempotent arm deliveries=%d err=%v", deliveries, err)
	}
	deliveryStore := NewPostgresPoolVIPOwnershipDeliveryStore(pool)
	envelopes := append([]PoolVIPOwnershipDeliveryEnvelopeV3{plan.CurrentOwnerEnvelope}, plan.StandbyEnvelopes...)
	for _, envelope := range envelopes {
		if err := deliveryStore.IssueHandoffBootstrapEnvelopeWithLeadership(ctx, epoch, conn, envelope); err != nil {
			t.Fatalf("issue P2 %s: %v", envelope.TargetNodeID, err)
		}
		target := uuid.MustParse(envelope.TargetNodeID)
		agent := PoolVIPOwnershipAgentIdentity{NodeID: target, OrgID: fixture.scope.OrgID}
		ack := ownershipAckV3(envelope)
		if _, err := deliveryStore.UpdatePoolVIPOwnershipAckV3(ctx, agent, ack, now, validateOwnershipDeliveryAckV3(agent, ack, now)); err != nil {
			t.Fatalf("ack P2 %s: %v", target, err)
		}
	}
	prerequisite, err := transition.ConfirmHandoffOwnershipModeTransitionWithLeadership(ctx, now, epoch, conn, plan, restarted)
	if err != nil || prerequisite != HandoffFencedBaseReady {
		t.Fatalf("confirm prerequisite=%q err=%v", prerequisite, err)
	}
	var actual, reason string
	var achieved *int64
	if err := pool.QueryRow(ctx, `SELECT actual_mode,reason_code,achieved_authority_revision FROM k8s_connector_pool_ha_transitions WHERE pool_id=$1`, fixture.scope.PoolID).Scan(&actual, &reason, &achieved); err != nil || actual != "fenced_ha" || reason != "fenced_base_ready" || achieved == nil {
		t.Fatalf("achieved actual=%q reason=%q authority=%v err=%v", actual, reason, achieved, err)
	}
	var oldRequested, newRequested, oldActual, newActual string
	var auditedEpoch, oldRevision, newRevision int64
	if err := pool.QueryRow(ctx, `SELECT metadata->>'old_requested_mode',metadata->>'new_requested_mode',
		metadata->>'old_actual_mode',metadata->>'new_actual_mode',(metadata->>'membership_epoch')::bigint,
		(metadata->>'old_transition_revision')::bigint,(metadata->>'new_transition_revision')::bigint
		FROM audit_logs WHERE org_id=$1 AND action='k8s.connector_pool_ha_activated' AND target_id=$2`, fixture.scope.OrgID, fixture.scope.PoolID.String()).Scan(
		&oldRequested, &newRequested, &oldActual, &newActual, &auditedEpoch, &oldRevision, &newRevision); err != nil {
		t.Fatal(err)
	}
	if oldRequested != "fenced_ha" || newRequested != "fenced_ha" || oldActual != "bootstrap_pending" || newActual != "fenced_ha" ||
		auditedEpoch != membershipEpoch || oldRevision != int64(restarted.TransitionRevision) || newRevision != int64(restarted.TransitionRevision) {
		t.Fatalf("inexact transition audit old/new requested=%s/%s actual=%s/%s epoch=%d revision=%d/%d", oldRequested, newRequested, oldActual, newActual, auditedEpoch, oldRevision, newRevision)
	}
}

func TestPostgresHandoffHATransitionRetriesStaleAndExpiredAuthorityAtNewRevisions(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run HA transition PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := newHandoffEndToEndTestDB(t, ctx, admin)
	fixture := seedHandoffBootstrapIntegration(t, ctx, pool)
	if err := db.MigrateTo(pool.Config().ConnString(), 130); err != nil {
		t.Fatal(err)
	}
	const membershipEpoch int64 = 0
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_connector_pool_health_states
		(org_id,site_id,cluster_id,pool_id,membership_epoch,observed_active_node_id,observed_generation)
		VALUES($1,$2,$3,$4,$5,$6,1)`, fixture.scope.OrgID, fixture.scope.SiteID, fixture.scope.ClusterID, fixture.scope.PoolID, membershipEpoch, fixture.active); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_ha_settings(org_id,enabled,actor_system,cause) VALUES($1,true,'test','retry proof')`, fixture.scope.OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_connector_pool_ha_transitions
		(pool_id,org_id,site_id,cluster_id,requested_mode,actual_mode,active_node_id,promotion_generation,membership_epoch,actor_system,cause)
		VALUES($1,$2,$3,$4,'fenced_ha','bootstrap_pending',$5,1,$6,'test','retry proof')`, fixture.scope.PoolID, fixture.scope.OrgID, fixture.scope.SiteID, fixture.scope.ClusterID, fixture.active, membershipEpoch); err != nil {
		t.Fatal(err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	var pid int32
	var granted bool
	if err := conn.QueryRow(ctx, `SELECT pg_backend_pid(),pg_try_advisory_lock($1)`, leader.SchedulerLockKey).Scan(&pid, &granted); err != nil || !granted {
		t.Fatalf("leader lock pid=%d granted=%t err=%v", pid, granted, err)
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, leader.SchedulerLockKey) //nolint:errcheck
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: pid, LockKey: leader.SchedulerLockKey}
	now := time.Now().UTC().Truncate(time.Microsecond)
	plan, found, err := NewPostgresHandoffBootstrapPlanSource(pool, HandoffBootstrapPlanSourceConfig{LeaseTTL: 5 * time.Minute}).LoadHandoffBootstrapPlanWithLeadership(ctx, now, fixture.scope, epoch, conn)
	if err != nil || !found {
		t.Fatalf("plan found=%t err=%v", found, err)
	}
	baseVersion := uint64(17)
	base := HandoffBaseStateSourceFunc(func(_ context.Context, _ uuid.UUID, nodeID uuid.UUID) (DesiredState, error) {
		return DesiredState{ProtocolVersion: 9, NodeID: nodeID.String(), InterfaceAddress: "10.44.0.1/16", MTU: 1420, ListenPort: 51820, Version: baseVersion, Peers: []Peer{}}, nil
	})
	store := NewPostgresKubernetesOwnershipBaseAuthorityStore(pool)
	transition, err := NewPostgresHandoffOwnershipModeTransition(pool, base, store, HandoffHATransitionConfig{MaxAckAge: time.Minute, AuthorityTTL: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	store.leaderBoundPreWriteHook = func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT pg_advisory_unlock($1)`, leader.SchedulerLockKey)
		return err
	}
	if _, _, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now, epoch, conn, plan); !errors.Is(err, ErrPoolVIPOwnershipHandoffLeaderSession) {
		t.Fatalf("leader loss before authority write err=%v", err)
	}
	var deliveriesBeforeLeaderReacquire int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_base_authority_deliveries WHERE org_id=$1`, fixture.scope.OrgID).Scan(&deliveriesBeforeLeaderReacquire); err != nil || deliveriesBeforeLeaderReacquire != 0 {
		t.Fatalf("leader-lost authority writes=%d err=%v", deliveriesBeforeLeaderReacquire, err)
	}
	store.leaderBoundPreWriteHook = nil
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, leader.SchedulerLockKey).Scan(&granted); err != nil || !granted {
		t.Fatalf("leader reacquire granted=%t err=%v", granted, err)
	}
	mutatedTopology := false
	store.leaderBoundPreWriteHook = func(ctx context.Context, tx pgx.Tx) error {
		if mutatedTopology {
			return nil
		}
		mutatedTopology = true
		_, err := tx.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET promotion_generation=2 WHERE pool_id=$1`, fixture.scope.PoolID)
		return err
	}
	if _, _, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now, epoch, conn, plan); !errors.Is(err, ErrHandoffHATransitionRefused) {
		t.Fatalf("post-snapshot topology mutation was accepted: %v", err)
	}
	store.leaderBoundPreWriteHook = nil
	var rolledBackGeneration, rolledBackDeliveries int64
	if err := pool.QueryRow(ctx, `SELECT promotion_generation FROM k8s_connector_pool_ha_transitions WHERE pool_id=$1`, fixture.scope.PoolID).Scan(&rolledBackGeneration); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_base_authority_deliveries WHERE org_id=$1`, fixture.scope.OrgID).Scan(&rolledBackDeliveries); err != nil {
		t.Fatal(err)
	}
	if rolledBackGeneration != 1 || rolledBackDeliveries != 0 {
		t.Fatalf("topology race was not atomic: generation=%d deliveries=%d", rolledBackGeneration, rolledBackDeliveries)
	}
	first, ready, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now, epoch, conn, plan)
	if err != nil || ready || first.TransitionRevision != 1 || len(first.Members) != 3 {
		t.Fatalf("first arm ready=%t snapshot=%+v err=%v", ready, first, err)
	}
	baseVersion++
	if _, _, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now, epoch, conn, plan); !errors.Is(err, ErrHandoffHATransitionRefused) {
		t.Fatalf("changed base superseded same transition revision: %v", err)
	}
	baseVersion--
	if _, err := pool.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET promotion_generation=2 WHERE pool_id=$1`, fixture.scope.PoolID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now, epoch, conn, plan); !errors.Is(err, ErrHandoffHATransitionRefused) {
		t.Fatalf("stale transition generation was accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET promotion_generation=1,active_node_id=$2 WHERE pool_id=$1`, fixture.scope.PoolID, fixture.standbyA); err != nil {
		t.Fatal(err)
	}
	if _, _, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now, epoch, conn, plan); !errors.Is(err, ErrHandoffHATransitionRefused) {
		t.Fatalf("stale transition active node was accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET active_node_id=$2 WHERE pool_id=$1`, fixture.scope.PoolID, fixture.active); err != nil {
		t.Fatal(err)
	}

	// A receipt at the exact freshness boundary remains valid; once it is older,
	// the leader advances the whole transition and old receipts satisfy nothing.
	for _, member := range first.Members {
		agent := KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: member.NodeID, OrgID: fixture.scope.OrgID, SiteID: fixture.scope.SiteID}
		pending, found, err := store.LoadPendingKubernetesOwnershipBaseAuthority(ctx, agent)
		if err != nil || !found {
			t.Fatalf("old pending %s found=%t err=%v", member.NodeID, found, err)
		}
		ack := KubernetesOwnershipBaseAuthorityAck{WireVersion: 1, AuthorityRevision: pending.AuthorityRevision, NodeID: pending.NodeID, OrgID: pending.OrgID, SiteID: pending.SiteID,
			BaseVersion: pending.BaseVersion, BaseHash: pending.BaseHash, AuthorityDigest: member.PayloadDigest, AppliedAt: now.Format(time.RFC3339Nano)}
		if _, err := store.AcknowledgeKubernetesOwnershipBaseAuthority(ctx, agent, ack, now); err != nil {
			t.Fatalf("old ACK %s: %v", member.NodeID, err)
		}
	}
	var staleDeliveryID uuid.UUID
	var staleDeliveryDigest string
	var staleDeliveryPayload []byte
	var staleDeliveryExpiry, staleReceiptTime time.Time
	if err := pool.QueryRow(ctx, `SELECT d.id,d.payload_digest,d.payload,d.expires_at,r.receipt_time
		FROM k8s_base_authority_deliveries d JOIN k8s_base_authority_ack_receipts r ON r.delivery_id=d.id
		WHERE d.org_id=$1 AND d.node_id=$2 AND d.transition_revision=1`, fixture.scope.OrgID, first.Members[0].NodeID).Scan(
		&staleDeliveryID, &staleDeliveryDigest, &staleDeliveryPayload, &staleDeliveryExpiry, &staleReceiptTime); err != nil {
		t.Fatal(err)
	}
	fresh, ready, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now.Add(time.Minute), epoch, conn, plan)
	if err != nil || !ready || fresh.TransitionRevision != 1 {
		t.Fatalf("fresh boundary ready=%t snapshot=%+v err=%v", ready, fresh, err)
	}
	stale, ready, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, now.Add(2*time.Minute), epoch, conn, plan)
	if err != nil || ready || stale.TransitionRevision != 2 || len(stale.Members) != 3 {
		t.Fatalf("stale retry ready=%t snapshot=%+v err=%v", ready, stale, err)
	}
	var staleOldRevision, staleNewRevision int64
	var staleReason string
	if err := pool.QueryRow(ctx, `SELECT (metadata->>'old_transition_revision')::bigint,
		(metadata->>'new_transition_revision')::bigint,metadata->>'reason'
		FROM audit_logs WHERE org_id=$1 AND action='k8s.connector_pool_ha_base_authority_retried'
		 AND metadata->>'reason'=$2`, fixture.scope.OrgID, handoffHAAuthorityStaleReceiptRetryReason).Scan(
		&staleOldRevision, &staleNewRevision, &staleReason); err != nil {
		t.Fatal(err)
	}
	if staleOldRevision != 1 || staleNewRevision != 2 || staleReason != handoffHAAuthorityStaleReceiptRetryReason {
		t.Fatalf("stale retry audit old/new=%d/%d reason=%q", staleOldRevision, staleNewRevision, staleReason)
	}

	// Two fresh revision-2 receipts cannot satisfy revision 3. The remaining
	// delivery is made expired/unacknowledged as a database fixture; production
	// recovery must preserve it and create revision-3 deliveries for everyone.
	freshReceiptNow := time.Now().UTC().Truncate(time.Microsecond)
	for _, member := range stale.Members[1:] {
		agent := KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: member.NodeID, OrgID: fixture.scope.OrgID, SiteID: fixture.scope.SiteID}
		pending, found, err := store.LoadPendingKubernetesOwnershipBaseAuthority(ctx, agent)
		if err != nil || !found || pending.AuthorityRevision != member.AuthorityRevision {
			t.Fatalf("revision-2 pending %s found=%t authority=%d/%d err=%v", member.NodeID, found, pending.AuthorityRevision, member.AuthorityRevision, err)
		}
		ack := KubernetesOwnershipBaseAuthorityAck{WireVersion: 1, AuthorityRevision: pending.AuthorityRevision, NodeID: pending.NodeID, OrgID: pending.OrgID, SiteID: pending.SiteID,
			BaseVersion: pending.BaseVersion, BaseHash: pending.BaseHash, AuthorityDigest: member.PayloadDigest, AppliedAt: freshReceiptNow.Format(time.RFC3339Nano)}
		if _, err := store.AcknowledgeKubernetesOwnershipBaseAuthority(ctx, agent, ack, freshReceiptNow); err != nil {
			t.Fatalf("revision-2 ACK %s: %v", member.NodeID, err)
		}
	}
	var oldID uuid.UUID
	var oldDigest string
	var oldPayload []byte
	var oldExpiry time.Time
	if err := pool.QueryRow(ctx, `UPDATE k8s_base_authority_deliveries
		SET created_at=clock_timestamp()-interval '2 seconds',expires_at=clock_timestamp()-interval '1 second'
		WHERE org_id=$1 AND node_id=$2 AND transition_revision=2
		RETURNING id,payload_digest,payload,expires_at`, fixture.scope.OrgID, stale.Members[0].NodeID).Scan(&oldID, &oldDigest, &oldPayload, &oldExpiry); err != nil {
		t.Fatal(err)
	}

	retryNow := time.Now().UTC()
	retried, ready, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, retryNow, epoch, conn, plan)
	if err != nil || ready || retried.TransitionRevision != 3 || len(retried.Members) != 3 {
		t.Fatalf("retry arm ready=%t snapshot=%+v err=%v", ready, retried, err)
	}
	// Same-revision replay must reuse the exact persisted expiries rather than
	// mutate them or advance again.
	replayed, ready, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, retryNow.Add(time.Second), epoch, conn, plan)
	if err != nil || ready || replayed.TransitionRevision != 3 {
		t.Fatalf("revision-3 replay ready=%t snapshot=%+v err=%v", ready, replayed, err)
	}
	var revision, deliveries, p2Deliveries int64
	var reasonCode string
	if err := pool.QueryRow(ctx, `SELECT transition_revision,reason_code FROM k8s_connector_pool_ha_transitions WHERE pool_id=$1`, fixture.scope.PoolID).Scan(&revision, &reasonCode); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_base_authority_deliveries WHERE org_id=$1`, fixture.scope.OrgID).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pool_vip_ownership_deliveries WHERE org_id=$1 AND pool_id=$2 AND wire_version=3`, fixture.scope.OrgID, fixture.scope.PoolID).Scan(&p2Deliveries); err != nil {
		t.Fatal(err)
	}
	if revision != 3 || reasonCode != handoffHAAuthorityRetryReasonCode || deliveries != 9 || p2Deliveries != 0 {
		t.Fatalf("retry state revision=%d reason=%q authority=%d p2=%d", revision, reasonCode, deliveries, p2Deliveries)
	}
	var preservedDigest string
	var preservedPayload []byte
	var preservedExpiry time.Time
	if err := pool.QueryRow(ctx, `SELECT payload_digest,payload,expires_at FROM k8s_base_authority_deliveries WHERE id=$1`, oldID).Scan(&preservedDigest, &preservedPayload, &preservedExpiry); err != nil {
		t.Fatal(err)
	}
	if preservedDigest != oldDigest || string(preservedPayload) != string(oldPayload) || !preservedExpiry.Equal(oldExpiry) {
		t.Fatal("expired revision-2 delivery was mutated during retry")
	}
	var preservedStaleDigest string
	var preservedStalePayload []byte
	var preservedStaleExpiry, preservedStaleReceipt time.Time
	if err := pool.QueryRow(ctx, `SELECT d.payload_digest,d.payload,d.expires_at,r.receipt_time
		FROM k8s_base_authority_deliveries d JOIN k8s_base_authority_ack_receipts r ON r.delivery_id=d.id WHERE d.id=$1`, staleDeliveryID).Scan(
		&preservedStaleDigest, &preservedStalePayload, &preservedStaleExpiry, &preservedStaleReceipt); err != nil {
		t.Fatal(err)
	}
	if preservedStaleDigest != staleDeliveryDigest || string(preservedStalePayload) != string(staleDeliveryPayload) ||
		!preservedStaleExpiry.Equal(staleDeliveryExpiry) || !preservedStaleReceipt.Equal(staleReceiptTime) {
		t.Fatal("stale revision-1 delivery or receipt was mutated during retry")
	}
	var oldRevision, newRevision int64
	var retryReason string
	if err := pool.QueryRow(ctx, `SELECT (metadata->>'old_transition_revision')::bigint,
		(metadata->>'new_transition_revision')::bigint,metadata->>'reason'
		FROM audit_logs WHERE org_id=$1 AND action='k8s.connector_pool_ha_base_authority_retried' AND target_id=$2
		 AND metadata->>'reason'=$3`, fixture.scope.OrgID, fixture.scope.PoolID.String(), handoffHAAuthorityExpiredUnacknowledgedRetryReason).Scan(&oldRevision, &newRevision, &retryReason); err != nil {
		t.Fatal(err)
	}
	if oldRevision != 2 || newRevision != 3 || retryReason != handoffHAAuthorityExpiredUnacknowledgedRetryReason {
		t.Fatalf("retry audit old/new=%d/%d reason=%q", oldRevision, newRevision, retryReason)
	}
}
