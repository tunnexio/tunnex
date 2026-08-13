package tenancy

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestSetOVPNEnabledAudits is the review-#4 red: the OpenVPN opt-in toggle (which unlocks the whole
// server + PKI + cert-delivery surface) records an attributable audit BOTH directions — it was silently
// unaudited, the worst placement for a swallowed audit (D-S9.5-OPTIN required it).
func TestSetOVPNEnabledAudits(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	org := uuid.New()
	if _, e := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, "oa-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	svc := &Service{q: sqlc.New(tx)}

	count := func(action string) int {
		var n int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2", org, action).Scan(&n); e != nil {
			t.Fatalf("count %s: %v", action, e)
		}
		return n
	}

	if _, e := svc.SetOVPNEnabled(ctx, org, true); e != nil {
		t.Fatalf("enable: %v", e)
	}
	if count("org.ovpn_enabled") != 1 {
		t.Fatal("enabling OpenVPN must write an org.ovpn_enabled audit (was swallowed)")
	}
	if _, e := svc.SetOVPNEnabled(ctx, org, false); e != nil {
		t.Fatalf("disable: %v", e)
	}
	if count("org.ovpn_disabled") != 1 {
		t.Fatal("disabling OpenVPN must write an org.ovpn_disabled audit (both directions)")
	}
}
