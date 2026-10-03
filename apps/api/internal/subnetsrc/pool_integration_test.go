package subnetsrc

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db"
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
			ctx, pool := testpostgres.New(t)
			if historical {
				if err := db.MigrateTo(pool.Config().ConnString(), 160); err != nil {
					t.Fatal(err)
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
