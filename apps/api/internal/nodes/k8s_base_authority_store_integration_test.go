package nodes

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestKubernetesOwnershipAuthorityMaintenanceAndAckLockOrder(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run base-authority PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dsn := newOwnershipDeliveryIntegrationDatabase(t, ctx, admin)
	if err := db.MigrateTo(dsn, 130); err != nil {
		t.Fatalf("migrate through 0130: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, _, _, target, _, scope := seedOwnershipDeliveryNodes(t, ctx, pool)
	authority := validKubernetesOwnershipAuthorityFixture()
	authority.AuthorityRevision = 0
	authority.NodeID, authority.OrgID, authority.SiteID = target.String(), org.String(), scope.siteID.String()
	authority.Classifications[0].Scope = KubernetesOwnershipPoolScope{
		OrgID: org.String(), SiteID: scope.siteID.String(), ClusterID: scope.clusterID.String(), PoolID: scope.poolID.String(),
	}
	issued, err := NewPostgresKubernetesOwnershipBaseAuthorityStore(pool).IssueKubernetesOwnershipBaseAuthority(ctx, KubernetesOwnershipBaseAuthorityIssue{
		Authority: authority,
		Pools: []KubernetesOwnershipBaseAuthorityPoolGeneration{{
			Scope: authority.Classifications[0].Scope, PromotionGeneration: 1,
		}},
		TransitionRevision: 1,
		ExpiresAt:          time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		t.Fatalf("issue authority fixture: %v", err)
	}

	ackConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ackConn.Release()
	ackTx, err := ackConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ackTx.Rollback(context.Background()) //nolint:errcheck
	var deliveryID string
	if err := ackTx.QueryRow(ctx, `SELECT id::text FROM k8s_base_authority_deliveries WHERE id=$1 FOR UPDATE`, issued.DeliveryID).Scan(&deliveryID); err != nil {
		t.Fatalf("lock ACK delivery: %v", err)
	}

	maintenanceConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenanceConn.Release()
	maintenanceTx, err := maintenanceConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenanceTx.Rollback(context.Background()) //nolint:errcheck
	var maintenancePID int32
	if err := maintenanceTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&maintenancePID); err != nil {
		t.Fatal(err)
	}
	maintenanceResult := make(chan error, 1)
	go func() {
		_, err := loadAcceptedKubernetesOwnershipClassificationPools(ctx, maintenanceTx, org, scope.siteID, target)
		maintenanceResult <- err
	}()
	waitForKubernetesOwnershipLockWait(t, ctx, pool, maintenancePID)

	// The maintenance transaction is waiting on the delivery held above. It
	// must not own node-state yet, so the ACK half can take that row and commit.
	if _, err := ackTx.Exec(ctx, `SET LOCAL lock_timeout='2s'`); err != nil {
		t.Fatal(err)
	}
	var acceptedRevision int64
	if err := ackTx.QueryRow(ctx, `SELECT accepted_authority_revision
		FROM k8s_base_authority_node_states
		WHERE org_id=$1 AND site_id=$2 AND node_id=$3 FOR UPDATE`, org, scope.siteID, target).Scan(&acceptedRevision); err != nil {
		t.Fatalf("ACK could not lock node state after delivery: %v", err)
	}
	if err := ackTx.Commit(ctx); err != nil {
		t.Fatalf("commit simulated ACK lock order: %v", err)
	}
	select {
	case err := <-maintenanceResult:
		if err != nil {
			t.Fatalf("maintenance resumed after ACK commit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance remained blocked after ACK commit")
	}
	if err := maintenanceTx.Commit(ctx); err != nil {
		t.Fatalf("commit maintenance lock-order probe: %v", err)
	}
}

func waitForKubernetesOwnershipLockWait(t *testing.T, ctx context.Context, pool *pgxpool.Pool, pid int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false)
			FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
			t.Fatalf("inspect maintenance lock wait: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("maintenance transaction did not reach the delivery lock wait")
}

func TestPostgresKubernetesOwnershipBaseAuthorityStore(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run base-authority PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn := newOwnershipDeliveryIntegrationDatabase(t, ctx, admin)
	if err := db.MigrateTo(dsn, 130); err != nil {
		t.Fatalf("migrate through 0130: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, _, _, target, otherTarget, scope := seedOwnershipDeliveryNodes(t, ctx, pool)
	store := NewPostgresKubernetesOwnershipBaseAuthorityStore(pool)
	authority := validKubernetesOwnershipAuthorityFixture()
	authority.AuthorityRevision = 0
	authority.NodeID, authority.OrgID, authority.SiteID = target.String(), org.String(), scope.siteID.String()
	authority.Classifications[0].Scope = KubernetesOwnershipPoolScope{OrgID: org.String(), SiteID: scope.siteID.String(), ClusterID: scope.clusterID.String(), PoolID: scope.poolID.String()}
	issue := KubernetesOwnershipBaseAuthorityIssue{Authority: authority,
		Pools:              []KubernetesOwnershipBaseAuthorityPoolGeneration{{Scope: authority.Classifications[0].Scope, PromotionGeneration: 1}},
		TransitionRevision: 1, ExpiresAt: time.Now().Add(time.Hour).UTC()}
	first, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, issue)
	if err != nil || first.Duplicate || first.Authority.AuthorityRevision != 1 {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	replay, err := NewPostgresKubernetesOwnershipBaseAuthorityStore(pool).IssueKubernetesOwnershipBaseAuthority(ctx, issue)
	if err != nil || !replay.Duplicate || replay.DeliveryID != first.DeliveryID || replay.PayloadDigest != first.PayloadDigest {
		t.Fatalf("replay=%+v first=%+v err=%v", replay, first, err)
	}
	changed := issue
	changed.Authority.Classifications = append([]KubernetesOwnershipPoolClassification(nil), issue.Authority.Classifications...)
	changed.Authority.Classifications[0].Disposition = KubernetesOwnershipPoolDispositionMaintainFence
	if _, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, changed); !errors.Is(err, ErrKubernetesOwnershipBaseAuthorityConflict) {
		t.Fatalf("changed replay err=%v", err)
	}
	changedBase := issue
	changedBase.Authority.BaseVersion++
	if _, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, changedBase); !errors.Is(err, ErrKubernetesOwnershipBaseAuthorityConflict) {
		t.Fatalf("changed-base same-transition replay err=%v", err)
	}
	blockedOrdinary := changed
	blockedOrdinary.OrdinaryBaseUpdate = true
	blockedOrdinary.TransitionRevision = 0
	blockedOrdinary.Authority.BaseVersion++
	blockedOrdinary.Authority.BaseHash = strings.Repeat("b", 64)
	if _, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, blockedOrdinary); !errors.Is(err, ErrKubernetesOwnershipBaseAuthorityConflict) {
		t.Fatalf("ordinary base superseded unacknowledged transition authority: %v", err)
	}
	// A new transition revision supersedes (but deliberately does not delete)
	// the unacknowledged first attempt. Once this latest transition delivery is
	// ACKed, the historical unacknowledged row must not block ordinary updates.
	retryIssue := issue
	retryIssue.TransitionRevision = 2
	retryIssue.ExpiresAt = time.Now().Add(2 * time.Hour).UTC()
	retry, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, retryIssue)
	if err != nil || retry.Duplicate || retry.Authority.AuthorityRevision != 2 {
		t.Fatalf("transition retry=%+v err=%v", retry, err)
	}
	agent := KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: target, OrgID: org, SiteID: scope.siteID}
	pending, found, err := store.LoadPendingKubernetesOwnershipBaseAuthority(ctx, agent)
	if err != nil || !found || pending.AuthorityRevision != 2 {
		t.Fatalf("pending=%+v found=%v err=%v", pending, found, err)
	}
	if _, found, err := store.LoadPendingKubernetesOwnershipBaseAuthority(ctx, KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: otherTarget, OrgID: org, SiteID: scope.siteID}); err != nil || found {
		t.Fatalf("cross-node pending found=%v err=%v", found, err)
	}
	ack := KubernetesOwnershipBaseAuthorityAck{WireVersion: 1, AuthorityRevision: pending.AuthorityRevision, NodeID: pending.NodeID, OrgID: pending.OrgID,
		SiteID: pending.SiteID, BaseVersion: pending.BaseVersion, BaseHash: pending.BaseHash, AuthorityDigest: retry.PayloadDigest,
		AppliedAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
	duplicate, err := store.AcknowledgeKubernetesOwnershipBaseAuthority(ctx, agent, ack, time.Now().UTC())
	if err != nil || duplicate {
		t.Fatalf("first ACK duplicate=%v err=%v", duplicate, err)
	}
	duplicate, err = NewPostgresKubernetesOwnershipBaseAuthorityStore(pool).AcknowledgeKubernetesOwnershipBaseAuthority(ctx, agent, ack, time.Now().UTC())
	if err != nil || !duplicate {
		t.Fatalf("replay ACK duplicate=%v err=%v", duplicate, err)
	}
	changedAck := ack
	changedAck.AppliedAt = time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339Nano)
	if _, err := store.AcknowledgeKubernetesOwnershipBaseAuthority(ctx, agent, changedAck, time.Now().UTC()); !errors.Is(err, ErrKubernetesOwnershipBaseAuthorityConflict) {
		t.Fatalf("changed ACK replay err=%v", err)
	}
	if _, found, err := store.LoadPendingKubernetesOwnershipBaseAuthority(ctx, agent); err != nil || found {
		t.Fatalf("ACKed delivery remained pending: found=%v err=%v", found, err)
	}
	var accepted int64
	var digest string
	if err := pool.QueryRow(ctx, `SELECT accepted_authority_revision,accepted_payload_digest FROM k8s_base_authority_node_states WHERE org_id=$1 AND node_id=$2`, org, target).Scan(&accepted, &digest); err != nil || accepted != 2 || digest != retry.PayloadDigest {
		t.Fatalf("accepted=%d digest=%s err=%v", accepted, digest, err)
	}
	var receipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_base_authority_ack_receipts WHERE org_id=$1 AND node_id=$2`, org, target).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("receipts=%d err=%v", receipts, err)
	}

	// An achieved fenced pool needs a newer scope-complete maintain_fence
	// authority for every changed ordinary base. Ordinary deliveries use a
	// durable NULL transition revision, deliberately disjoint from the strict
	// bootstrap replay above where a changed same-revision base is a conflict.
	ordinary := issue
	ordinary.OrdinaryBaseUpdate = true
	ordinary.TransitionRevision = 0
	ordinary.Authority.Classifications = append([]KubernetesOwnershipPoolClassification(nil), issue.Authority.Classifications...)
	ordinary.Authority.Classifications[0].Disposition = KubernetesOwnershipPoolDispositionMaintainFence
	ordinary.Authority.BaseVersion++
	ordinary.Authority.BaseHash = strings.Repeat("b", 64)
	ordinary.ExpiresAt = time.Now().Add(time.Hour).UTC()
	second, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, ordinary)
	if err != nil || second.Duplicate || second.Authority.AuthorityRevision != 3 {
		t.Fatalf("ordinary-base second=%+v err=%v", second, err)
	}
	secondReplay, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, ordinary)
	if err != nil || !secondReplay.Duplicate || secondReplay.DeliveryID != second.DeliveryID {
		t.Fatalf("ordinary-base replay=%+v second=%+v err=%v", secondReplay, second, err)
	}
	thirdIssue := ordinary
	thirdIssue.Authority.BaseVersion++
	thirdIssue.Authority.BaseHash = strings.Repeat("c", 64)
	third, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, thirdIssue)
	if err != nil || third.Duplicate || third.Authority.AuthorityRevision != 4 {
		t.Fatalf("ordinary-base third=%+v err=%v", third, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_base_authority_deliveries
		SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour'
		WHERE id=$1`, third.DeliveryID); err != nil {
		t.Fatalf("expire unacknowledged ordinary authority: %v", err)
	}
	thirdRetry, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, thirdIssue)
	if err != nil || thirdRetry.Duplicate || thirdRetry.Authority.AuthorityRevision != 5 || thirdRetry.DeliveryID == third.DeliveryID {
		t.Fatalf("expired ordinary-base retry=%+v prior=%+v err=%v", thirdRetry, third, err)
	}
	pending, found, err = store.LoadPendingKubernetesOwnershipBaseAuthority(ctx, agent)
	if err != nil || !found || pending.AuthorityRevision != 5 || pending.BaseHash != thirdIssue.Authority.BaseHash ||
		len(pending.Classifications) != 1 || pending.Classifications[0].Disposition != KubernetesOwnershipPoolDispositionMaintainFence {
		t.Fatalf("ordinary-base pending=%+v found=%v err=%v", pending, found, err)
	}
	ordinaryAck := KubernetesOwnershipBaseAuthorityAck{WireVersion: 1, AuthorityRevision: pending.AuthorityRevision, NodeID: pending.NodeID, OrgID: pending.OrgID,
		SiteID: pending.SiteID, BaseVersion: pending.BaseVersion, BaseHash: pending.BaseHash, AuthorityDigest: thirdRetry.PayloadDigest,
		AppliedAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
	if duplicate, err := store.AcknowledgeKubernetesOwnershipBaseAuthority(ctx, agent, ordinaryAck, time.Now().UTC()); err != nil || duplicate {
		t.Fatalf("ordinary-base ack duplicate=%v err=%v", duplicate, err)
	}
	ackedReplay, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, thirdIssue)
	if err != nil || !ackedReplay.Duplicate || ackedReplay.DeliveryID != thirdRetry.DeliveryID {
		t.Fatalf("acked ordinary-base replay=%+v retry=%+v err=%v", ackedReplay, thirdRetry, err)
	}
	transitionReplay, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, retryIssue)
	if err != nil || !transitionReplay.Duplicate || transitionReplay.DeliveryID != retry.DeliveryID {
		t.Fatalf("transition replay after ordinary rows=%+v first=%+v err=%v", transitionReplay, retry, err)
	}
	changedTransition := retryIssue
	changedTransition.Authority.BaseHash = strings.Repeat("d", 64)
	if _, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, changedTransition); !errors.Is(err, ErrKubernetesOwnershipBaseAuthorityConflict) {
		t.Fatalf("changed transition replay after ordinary rows err=%v", err)
	}
	invalidOrdinary := ordinary
	invalidOrdinary.Authority.Classifications = append([]KubernetesOwnershipPoolClassification(nil), ordinary.Authority.Classifications...)
	invalidOrdinary.Authority.Classifications[0].Disposition = KubernetesOwnershipPoolDispositionArmFence
	if _, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, invalidOrdinary); !errors.Is(err, ErrKubernetesOwnershipBaseAuthorityInvalid) {
		t.Fatalf("ordinary-base arm_fence accepted: %v", err)
	}
}
