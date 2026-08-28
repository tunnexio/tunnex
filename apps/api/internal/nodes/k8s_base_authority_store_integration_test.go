package nodes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestPostgresKubernetesOwnershipBaseAuthorityStore(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run base-authority PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn := newOwnershipDeliveryIntegrationDatabase(t, ctx, admin)
	if err := db.MigrateTo(dsn, 120); err != nil {
		t.Fatalf("migrate through 0120: %v", err)
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
	agent := KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: target, OrgID: org, SiteID: scope.siteID}
	pending, found, err := store.LoadPendingKubernetesOwnershipBaseAuthority(ctx, agent)
	if err != nil || !found || pending.AuthorityRevision != 1 {
		t.Fatalf("pending=%+v found=%v err=%v", pending, found, err)
	}
	if _, found, err := store.LoadPendingKubernetesOwnershipBaseAuthority(ctx, KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: otherTarget, OrgID: org, SiteID: scope.siteID}); err != nil || found {
		t.Fatalf("cross-node pending found=%v err=%v", found, err)
	}
	ack := KubernetesOwnershipBaseAuthorityAck{WireVersion: 1, AuthorityRevision: pending.AuthorityRevision, NodeID: pending.NodeID, OrgID: pending.OrgID,
		SiteID: pending.SiteID, BaseVersion: pending.BaseVersion, BaseHash: pending.BaseHash, AuthorityDigest: first.PayloadDigest,
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
	if err := pool.QueryRow(ctx, `SELECT accepted_authority_revision,accepted_payload_digest FROM k8s_base_authority_node_states WHERE org_id=$1 AND node_id=$2`, org, target).Scan(&accepted, &digest); err != nil || accepted != 1 || digest != first.PayloadDigest {
		t.Fatalf("accepted=%d digest=%s err=%v", accepted, digest, err)
	}
	var receipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_base_authority_ack_receipts WHERE org_id=$1 AND node_id=$2`, org, target).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("receipts=%d err=%v", receipts, err)
	}
}
