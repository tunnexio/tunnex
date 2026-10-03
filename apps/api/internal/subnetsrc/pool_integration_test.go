package subnetsrc

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestPoolCIDRHistoricalAndCurrentSchema(t *testing.T) {
	for _, historical := range []bool{true, false} {
		name := "current"
		if historical {
			name = "ipsec_160"
		}
		t.Run(name, func(t *testing.T) {
			newPool := testpostgres.New
			if historical {
				newPool = func(t testing.TB) (context.Context, *pgxpool.Pool) {
					return testpostgres.NewAtVersion(t, 160)
				}
			}
			ctx, pool := newPool(t)
			if historical {
				var version int
				if err := pool.QueryRow(ctx, `SELECT version FROM schema_migrations`).Scan(&version); err != nil {
					t.Fatal(err)
				}
				if version != 160 {
					t.Fatalf("historical fixture version=%d, want 160", version)
				}
			}
			org := uuid.New()
			if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'pool compatibility',$2,'10.199.0.0/24')`, org, org.String()); err != nil {
				t.Fatal(err)
			}
			source := Source{Q: sqlc.New(pool)}
			if got, err := source.PoolCIDR(ctx, org); err != nil || got != "10.199.0.0/24" {
				t.Fatalf("pool=%q error=%v", got, err)
			}
			if _, err := source.PoolCIDR(ctx, uuid.New()); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("unknown organization: %v", err)
			}
			if _, err := pool.Exec(ctx, `UPDATE organizations SET deleted_at=now() WHERE id=$1`, org); err != nil {
				t.Fatal(err)
			}
			if _, err := source.PoolCIDR(ctx, org); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("deleted organization: %v", err)
			}
		})
	}
}
