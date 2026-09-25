package ipsec_test

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"strings"
	"testing"
	"time"
)

// Queue the first operation behind the real org advisory lock, observe its
// PostgreSQL wait, then enqueue the second and observe both before release.
func rotationOrderedRace(t *testing.T, ctx context.Context, p *pgxpool.Pool, org uuid.UUID, first, second func() error) (error, error) {
	t.Helper()
	block, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer block.Rollback(ctx)
	if _, e = block.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, org.String()); e != nil {
		t.Fatal(e)
	}
	wait := func(n int) {
		t.Helper()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			var count int
			e := p.QueryRow(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND l.locktype='advisory' AND NOT l.granted`).Scan(&count)
			if e != nil {
				t.Fatal(e)
			}
			if count >= n {
				return
			}
			select {
			case <-deadline.C:
				t.Fatal("operation never reached observed advisory wait")
			case <-tick.C:
			}
		}
	}
	a, b := make(chan error, 1), make(chan error, 1)
	go func() { a <- first() }()
	wait(1)
	go func() { b <- second() }()
	wait(2)
	if e = block.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	return <-a, <-b
}

func TestRotationEnableDeleteObservedLockOrdering(t *testing.T) {
	for _, other := range []string{"enable", "delete"} {
		for _, rotationFirst := range []bool{false, true} {
			name := other + "-other-first"
			if rotationFirst {
				name = other + "-rotation-first"
			}
			t.Run(name, func(t *testing.T) {
				ctx, p, org, actor, sealer, req := providerFixture(t)
				if e := db.MigrateTo(p.Config().ConnString(), 162); e != nil {
					t.Fatal(e)
				}
				s := ipsec.NewConnectionStore(p)
				s.ConfigureRuntimePolicy(func(context.Context, *sqlc.Queries, ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
					return ipsec.RuntimePolicy{Hash: strings.Repeat("a", 64)}, nil
				})
				c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
				if e != nil {
					t.Fatal(e)
				}
				rotate := func() error {
					_, e := s.RotatePSKs(ctx, org, actor, c.ID, 1, []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: "Synthetic_Lock_Rotation_456"}}, sealer)
					return e
				}
				mutate := func() error {
					if other == "enable" {
						_, e := s.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
						return e
					}
					_, e := s.Delete(ctx, org, actor, c.ID, 1)
					return e
				}
				first, second := mutate, rotate
				if rotationFirst {
					first, second = rotate, mutate
				}
				winner, loser := rotationOrderedRace(t, ctx, p, org, first, second)
				if winner != nil || !errors.Is(loser, ipsec.ErrConnectionConflict) {
					t.Fatal("waiting mutation did not revalidate", winner, loser)
				}
			})
		}
	}
}
