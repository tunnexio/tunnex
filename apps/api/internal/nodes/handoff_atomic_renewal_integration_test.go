package nodes

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

func TestRetiredOwnerRenewalExclusionRequiresEveryScope(t *testing.T) {
	node, other, owner := uuid.New(), uuid.New(), uuid.New()
	for _, tc := range []struct {
		name            string
		active, retired uuid.UUID
		proved, want    bool
	}{
		{"both pools prove retirement", owner, node, true, true},
		{"second pool has no proof", owner, node, false, false},
		{"second pool retired another member", owner, other, true, false},
		{"node still owns second pool", node, node, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := handoffOrdinaryBaseMaintenanceNode{nodeID: node, renewalExcluded: true}
			entry.includeRenewalScope(owner, node, true)
			entry.includeRenewalScope(tc.active, tc.retired, tc.proved)
			entry.includeRenewalScope(owner, node, true) // later proof cannot erase an earlier required scope
			if entry.renewalExcluded != tc.want {
				t.Fatalf("exclusion=%t want=%t", entry.renewalExcluded, tc.want)
			}
		})
	}
}

type failSecondAtomicRenewalIssuer struct {
	*PostgresPoolVIPOwnershipDeliveryStore
	calls int
	err   error
}

func (i *failSecondAtomicRenewalIssuer) IssueHandoffBootstrapEnvelopeWithLeadershipTx(ctx context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, tx pgx.Tx, envelope PoolVIPOwnershipDeliveryEnvelopeV3) error {
	i.calls++
	if i.calls == 2 {
		return i.err
	}
	return i.PostgresPoolVIPOwnershipDeliveryStore.IssueHandoffBootstrapEnvelopeWithLeadershipTx(ctx, epoch, conn, tx, envelope)
}

func TestHandoffAtomicRenewalRollsBackEarlierPreparedDelivery(t *testing.T) {
	f := newWakeVersionRenewalFixture(t)
	count := func() int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM pool_vip_ownership_deliveries WHERE org_id=$1 AND pool_id=$2`, f.fixture.scope.OrgID, f.fixture.scope.PoolID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before, expiry := count(), f.servingExpiry(t)
	wantErr := errors.New("stop after first prepared insert")
	issuer := &failSecondAtomicRenewalIssuer{PostgresPoolVIPOwnershipDeliveryStore: NewPostgresPoolVIPOwnershipDeliveryStore(f.pool), err: wantErr}
	f.runtime.issuer = issuer
	err := f.runtime.reconcileFencedPools(f.ctx, f.now.Add(time.Minute), f.epoch, f.conn, []k8s.HandoffPoolScope{f.fixture.scope})
	if !errors.Is(err, wantErr) || issuer.calls != 2 {
		t.Fatalf("fault seam not reached: calls=%d error=%v", issuer.calls, err)
	}
	if got := count(); got != before || !f.servingExpiry(t).Equal(expiry) {
		t.Fatalf("failed batch committed a partial renewal: before=%d after=%d", before, got)
	}
	// The same exact leader session and candidate bucket remain usable after
	// rollback; no hidden inner commit or poisoned transaction is tolerated.
	f.runtime.issuer = issuer.PostgresPoolVIPOwnershipDeliveryStore
	if err := f.runtime.reconcileFencedPools(f.ctx, f.now.Add(time.Minute), f.epoch, f.conn, []k8s.HandoffPoolScope{f.fixture.scope}); err != nil {
		t.Fatal(err)
	}
	if count() <= before || !f.servingExpiry(t).After(expiry) {
		t.Fatal("normal retry did not atomically renew")
	}
}
