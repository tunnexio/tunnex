package connectivity

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIssuanceConfiguration(t *testing.T) {
	defaults, err := LoadIssuanceLimits(func(string) string { return "" })
	if err != nil || defaults != (IssuanceLimits{6, 30, 300}) {
		t.Fatal(defaults, err)
	}
	for _, bad := range []string{"0", "-1", "10001", "not-a-number"} {
		if _, err := LoadIssuanceLimits(func(string) string { return bad }); err == nil {
			t.Fatal("accepted invalid limit")
		}
	}
	got, err := LoadIssuanceLimits(func(string) string { return "10" })
	if err != nil || got != (IssuanceLimits{10, 10, 10}) {
		t.Fatal(got, err)
	}
}

func TestIssuanceRollingLimitsPostgres(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated PostgreSQL")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, kind := range []string{"device", "owner", "organization"} {
		t.Run(kind, func(t *testing.T) {
			org, owner, device := uuid.New(), uuid.New(), uuid.New()
			if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'issuance-test',$2)`, org, org.String()); err != nil {
				t.Fatal(err)
			}
			defer pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org)
			limits := IssuanceLimits{100, 100, 100}
			var ceiling int32
			switch kind {
			case "device":
				limits.Device = 2
				ceiling = 2
			case "owner":
				limits.Owner = 3
				ceiling = 3
			default:
				limits.Organization = 4
				ceiling = 4
			}
			consume := func(b Binding) error {
				tx, err := pool.Begin(ctx)
				if err != nil {
					return err
				}
				defer tx.Rollback(ctx)
				s := NewStore(pool).WithIssuanceLimits(limits)
				_, err = s.reserveIssuance(ctx, sqlc.New(tx), b, DeviceSide, time.Now())
				if err != nil {
					return err
				}
				return tx.Commit(ctx)
			}
			var accepted atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 12; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					b := Binding{SessionID: uuid.New(), OrgID: org, OwnerID: owner, DeviceID: device}
					if kind != "device" {
						b.DeviceID = uuid.New()
					}
					if kind == "organization" {
						b.OwnerID = uuid.New()
					}
					err := consume(b)
					if err == nil {
						accepted.Add(1)
					} else if !errors.Is(err, ErrIssuanceLimited) {
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			if accepted.Load() != ceiling {
				t.Fatalf("accepted %d want %d", accepted.Load(), ceiling)
			}
			// Aging only this isolated fixture proves expiry frees capacity without
			// deleting an active customer's history or changing application sessions.
			if _, err := pool.Exec(ctx, `UPDATE connectivity_issuances SET issued_at=clock_timestamp()-interval '61 seconds' WHERE org_id=$1`, org); err != nil {
				t.Fatal(err)
			}
			b := Binding{SessionID: uuid.New(), OrgID: org, OwnerID: owner, DeviceID: device}
			if err := consume(b); err != nil {
				t.Fatal("window did not recover", err)
			}
			if err := consume(b); err != nil {
				t.Fatal("duplicate issuance consumed capacity", err)
			}
			var count int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM connectivity_issuances WHERE org_id=$1`, org).Scan(&count); err != nil || count != 1 {
				t.Fatal(count, err)
			}
			var issuanceID uuid.UUID
			if err := pool.QueryRow(ctx, `SELECT session_id FROM connectivity_issuances WHERE org_id=$1`, org).Scan(&issuanceID); err != nil {
				t.Fatal(err)
			}
			q := sqlc.New(pool)
			for _, scope := range []uuid.UUID{org, uuid.New()} {
				exists, err := q.HasConnectivityIssuance(ctx, sqlc.HasConnectivityIssuanceParams{SessionID: issuanceID, OrgID: scope})
				if err != nil || exists != (scope == org) {
					t.Fatalf("issuance existence escaped tenant scope: exists=%t err=%v", exists, err)
				}
			}
		})
	}
}
