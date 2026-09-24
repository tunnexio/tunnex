package ipsec_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

// Observe a real blocked statement before releasing its competitor. This proves
// rechecking under locks rather than an uncontended sequential eligibility read.
func TestCreateDisabledRechecksConcurrentEligibility(t *testing.T) {
	for _, scenario := range []string{"optout", "revocation", "capability downgrade", "unbind"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, p, org, actor, sealer, req := createFixture(t)
			config := p.Config().Copy()
			name := "ipsec_create_" + uuid.NewString()
			config.ConnConfig.RuntimeParams["application_name"] = name
			servicePool, err := pgxpool.NewWithConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(servicePool.Close)
			tx, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			switch scenario {
			case "optout":
				_, err = tx.Exec(ctx, `UPDATE ipsec_org_settings SET enabled=false,revision=revision+1 WHERE org_id=$1`, org)
			case "revocation":
				_, err = tx.Exec(ctx, `UPDATE nodes SET status='revoked',revoked_at=now() WHERE id=$1`, req.GatewayID)
			case "capability downgrade":
				_, err = tx.Exec(ctx, `UPDATE nodes SET capabilities='{"ipsec_config_version":0}' WHERE id=$1`, req.GatewayID)
			case "unbind":
				_, err = tx.Exec(ctx, `UPDATE nodes SET site_id=NULL WHERE id=$1`, req.GatewayID)
			}
			if err != nil {
				t.Fatal(err)
			}
			attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, e := ipsec.NewConnectionStore(servicePool).CreateDisabled(attemptCtx, org, actor, sealer, req)
				done <- e
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				var blocked bool
				if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')`, name).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("create returned before competitor committed: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("did not observe lock wait")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, ipsec.ErrConnectionIneligible) && !errors.Is(err, ipsec.ErrConnectionNotFound) {
				t.Fatalf("eligibility race accepted or unexpected error: %v", err)
			}
			var records, audits int
			if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_connections WHERE org_id=$1),(SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ipsec.connection_created')`, org).Scan(&records, &audits); err != nil {
				t.Fatal(err)
			}
			if records != 0 || audits != 0 {
				t.Fatalf("refused creation persisted records=%d audits=%d", records, audits)
			}
		})
	}
}
