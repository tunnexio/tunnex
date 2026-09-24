package db_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Both winners and both isolation levels matter: lock-only admission is unsafe
// for an older RR snapshot even when sequential overlap checks appear sound.
func TestIPsecProviderRangeConcurrency(t *testing.T) {
	for _, level := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead} {
		for _, kind := range []string{"site", "pool", "vip"} {
			for _, providerWins := range []bool{true, false} {
				order := "range first"
				if providerWins {
					order = "provider first"
				}
				t.Run(string(level)+"/"+kind+"/"+order, func(t *testing.T) {
					ctx, p, _ := providerSchemaFixture(t)
					o := providerSeed(t, ctx, p)
					loser, err := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: level})
					if err != nil {
						t.Fatal(err)
					}
					defer loser.Rollback(ctx)
					var snapshotCount, pid int
					if err := loser.QueryRow(ctx, `SELECT count(*) FROM ipsec_provider_bindings`).Scan(&snapshotCount); err != nil {
						t.Fatal(err)
					}
					if err := loser.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
						t.Fatal(err)
					}
					writeRange := func(tx pgx.Tx) error {
						var e error
						switch kind {
						case "site":
							_, e = tx.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.20.1.0/24','approved')`, uuid.New(), o.site)
						case "pool":
							_, e = tx.Exec(ctx, `UPDATE organizations SET pool_cidr='10.20.1.0/24' WHERE id=$1`, o.org)
						case "vip":
							_, e = tx.Exec(ctx, `INSERT INTO k8s_clusters(id,org_id,site_id,name,vip_range) VALUES($1,$2,$3,'conflict','10.20.1.0/24')`, uuid.New(), o.org, o.site)
						}
						return e
					}
					winner, err := p.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer winner.Rollback(ctx)
					if providerWins {
						err = insertProvider(ctx, winner, o, uuid.New())
					} else {
						err = writeRange(winner)
					}
					if err != nil {
						t.Fatalf("winner setup: %v", err)
					}
					result := make(chan error, 1)
					go func() {
						var e error
						if providerWins {
							e = writeRange(loser)
						} else {
							e = insertProvider(ctx, loser, o, uuid.New())
						}
						if e == nil {
							e = loser.Commit(ctx)
						}
						result <- e
					}()
					deadline := time.Now().Add(5 * time.Second)
					for {
						var blocked bool
						if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, pid).Scan(&blocked); err != nil {
							t.Fatal(err)
						}
						if blocked {
							break
						}
						select {
						case err := <-result:
							t.Fatalf("loser did not wait for range ownership: %v", err)
						default:
						}
						if time.Now().After(deadline) {
							t.Fatal("no observed lock wait")
						}
						time.Sleep(5 * time.Millisecond)
					}
					if err := winner.Commit(ctx); err != nil {
						t.Fatalf("winner commit: %v", err)
					}
					err = <-result
					var pe *pgconn.PgError
					if !errors.As(err, &pe) {
						t.Fatalf("conflicting loser must be refused: %v", err)
					}
					if level == pgx.RepeatableRead {
						if pe.Code != "40001" {
							t.Fatalf("old snapshot requires serialization refusal: %v", err)
						}
					} else if pe.ConstraintName != "ipsec_provider_conflict" {
						t.Fatalf("expected overlap refusal: %v", err)
					}
					if err := loser.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
						t.Fatal(err)
					}
					var records int
					if err := p.QueryRow(ctx, `SELECT count(*) FROM ipsec_provider_bindings WHERE org_id=$1`, o.org).Scan(&records); err != nil {
						t.Fatal(err)
					}
					want := 0
					if providerWins {
						want = 1
					}
					if records != want {
						t.Fatalf("committed providers%d want%d", records, want)
					}
				})
			}
		}
	}
}

func TestIPsecProviderApprovalRechecksMovingSiteOrganization(t *testing.T) {
	ctx, p, _ := providerSchemaFixture(t)
	target := providerSeed(t, ctx, p)
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := insertProvider(ctx, tx, target, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	source := providerSeed(t, ctx, p)
	moved, sub := uuid.New(), uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO sites(id,org_id,name) VALUES($1,$2,'moving pending site')`, moved, source.org); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.20.1.0/24','pending')`, sub, moved); err != nil {
		t.Fatal(err)
	}
	move, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer move.Rollback(ctx)
	if _, err := move.Exec(ctx, `UPDATE sites SET org_id=$1 WHERE id=$2`, target.org, moved); err != nil {
		t.Fatal(err)
	}
	approval, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer approval.Rollback(ctx)
	var pid int
	if err := approval.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, e := approval.Exec(ctx, `UPDATE site_subnets SET status='approved' WHERE id=$1`, sub)
		if e == nil {
			e = approval.Commit(ctx)
		}
		done <- e
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var blocked bool
		if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("approval escaped ownership wait: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("lock wait not observed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := move.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "40001" {
		t.Fatalf("moved ownership must force revalidation: %v", err)
	}
	if err := approval.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	var status string
	if err := p.QueryRow(ctx, `SELECT status FROM site_subnets WHERE id=$1`, sub).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("conflicting advertisement approved: %s %v", status, err)
	}
}
