package nodes

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestPostgresOrdinaryBasePriorReadFailureDoesNotMintAuthority(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run base-authority read-failure integration")
	}
	for _, test := range []struct {
		name          string
		corruptionSQL string
		wantConflict  bool
	}{
		{
			name:          "stored payload conflict",
			corruptionSQL: `UPDATE k8s_base_authority_deliveries SET payload='{}'::jsonb WHERE id=$1`,
			wantConflict:  true,
		},
		{
			name:          "database scan failure",
			corruptionSQL: `UPDATE k8s_base_authority_deliveries SET expires_at='infinity'::timestamptz WHERE id=$1`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			dsn := newOwnershipDeliveryIntegrationDatabase(t, ctx, admin)
			if err := db.MigrateTo(dsn, 134); err != nil {
				t.Fatalf("migrate through 0134: %v", err)
			}
			pool, err := pgxpool.New(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)

			orgID, _, _, nodeID, _, scope := seedOwnershipDeliveryNodes(t, ctx, pool)
			issue := ordinaryBaseAuthorityIssueFixture()
			issue.Authority.NodeID = nodeID.String()
			issue.Authority.OrgID = orgID.String()
			issue.Authority.SiteID = scope.siteID.String()
			issue.Authority.Classifications[0].Scope = KubernetesOwnershipPoolScope{
				OrgID: orgID.String(), SiteID: scope.siteID.String(), ClusterID: scope.clusterID.String(), PoolID: scope.poolID.String(),
			}
			issue.Pools[0].Scope = issue.Authority.Classifications[0].Scope

			store := NewPostgresKubernetesOwnershipBaseAuthorityStore(pool)
			first, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, issue)
			if err != nil || first.Duplicate || first.Authority.AuthorityRevision != 1 {
				t.Fatalf("valid issue = %+v, err = %v", first, err)
			}
			replay, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, issue)
			if err != nil || !replay.Duplicate || replay.DeliveryID != first.DeliveryID || replay.PayloadDigest != first.PayloadDigest {
				t.Fatalf("valid replay = %+v, first = %+v, err = %v", replay, first, err)
			}

			if _, err := pool.Exec(ctx, test.corruptionSQL, first.DeliveryID); err != nil {
				t.Fatalf("corrupt persisted prior authority: %v", err)
			}
			before := readBaseAuthorityWriteState(t, ctx, pool, orgID, scope.siteID, nodeID)
			result, err := store.IssueKubernetesOwnershipBaseAuthority(ctx, issue)
			if test.wantConflict {
				if !errors.Is(err, ErrKubernetesOwnershipBaseAuthorityConflict) {
					t.Fatalf("corrupt prior authority issue = %+v, err = %v; want conflict", result, err)
				}
			} else if err == nil || errors.Is(err, ErrKubernetesOwnershipBaseAuthorityConflict) || !strings.Contains(strings.ToLower(err.Error()), "infinity") {
				t.Fatalf("infinite timestamp prior read issue = %+v, err = %v; want pgx scan failure", result, err)
			}
			after := readBaseAuthorityWriteState(t, ctx, pool, orgID, scope.siteID, nodeID)
			if after != before {
				t.Fatalf("failed prior read changed authority state: before=%+v after=%+v", before, after)
			}
		})
	}
}

type baseAuthorityWriteState struct {
	deliveries       int
	poolRows         int
	nextRevision     int64
	acceptedRevision int64
}

func readBaseAuthorityWriteState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, siteID, nodeID uuid.UUID) baseAuthorityWriteState {
	t.Helper()
	var state baseAuthorityWriteState
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM k8s_base_authority_deliveries
			 WHERE org_id=$1 AND site_id=$2 AND node_id=$3),
			(SELECT count(*) FROM k8s_base_authority_delivery_pools
			 WHERE org_id=$1 AND site_id=$2 AND node_id=$3),
			next_authority_revision,
			accepted_authority_revision
		FROM k8s_base_authority_node_states
		WHERE org_id=$1 AND site_id=$2 AND node_id=$3`, orgID, siteID, nodeID).
		Scan(&state.deliveries, &state.poolRows, &state.nextRevision, &state.acceptedRevision); err != nil {
		t.Fatalf("read base-authority write state: %v", err)
	}
	return state
}
