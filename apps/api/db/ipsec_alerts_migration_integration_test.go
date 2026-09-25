package db_test

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestIPsecAlertSignalsMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0163 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	base, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_ipsec_alerts_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	dsn := testURL.String()
	if err := db.MigrateTo(dsn, 162); err != nil {
		t.Fatalf("migrate prerequisite chain through 0162: %v", err)
	}
	if err := db.MigrateTo(dsn, 163); err != nil {
		t.Fatalf("apply 0163: %v", err)
	}
	if err := db.MigrateTo(dsn, 162); err != nil {
		t.Fatalf("empty 0163 down: %v", err)
	}
	if err := db.MigrateTo(dsn, 163); err != nil {
		t.Fatalf("0163 re-up: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'alerts',$2,'10.247.0.0/24')`, orgID, "alerts-"+orgID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ipsec.tunnel_down", "ipsec.connection_down", "ipsec.status_unavailable"} {
		if _, err := pool.Exec(ctx, `INSERT INTO alert_occurrences(org_id,event_key,dedup_key,resource_type,resource_id,resource_name,severity,subject,state,first_observed_at,last_observed_at,occurrence_count) VALUES($1,$2,$2,'ipsec_connection','connection','AWS','warning','IPsec condition','firing',now(),now(),1)`, orgID, key); err != nil {
			t.Fatal(err)
		}
	}
	down, err := os.ReadFile("migrations/0163_ipsec_alert_signals.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err == nil {
		t.Fatal("rollback must preserve IPsec history")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM alert_occurrences WHERE org_id=$1`, orgID).Scan(&count); err != nil || count != 3 {
		t.Fatalf("history lost: %d %v", count, err)
	}
}
