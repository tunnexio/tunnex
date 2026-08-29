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

func TestCrossProductAlertOccurrencesMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0126 PostgreSQL proof")
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
	name := "tnx_alert_occurrences_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	dsn := testURL.String()
	if err := db.MigrateTo(dsn, 125); err != nil {
		t.Fatalf("migrate prerequisite chain through 0125: %v", err)
	}
	if err := db.MigrateTo(dsn, 126); err != nil {
		t.Fatalf("apply 0126: %v", err)
	}
	if err := db.MigrateTo(dsn, 125); err != nil {
		t.Fatalf("empty 0126 down: %v", err)
	}
	if err := db.MigrateTo(dsn, 126); err != nil {
		t.Fatalf("0126 re-up: %v", err)
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
	if _, err := pool.Exec(ctx, `
		INSERT INTO alert_occurrences(
			org_id,event_key,dedup_key,resource_type,resource_id,resource_name,severity,subject,state,
			first_observed_at,last_observed_at,occurrence_count
		) VALUES($1,'gateway.offline','gateway:one:offline','gateway','one','gw-one','critical','Gateway is offline','firing',now(),now(),1)`, orgID); err != nil {
		t.Fatalf("insert cross-product occurrence: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO alert_occurrences(
			org_id,event_key,dedup_key,resource_type,resource_id,severity,subject,state,
			first_observed_at,last_observed_at,occurrence_count
		) VALUES($1,'gateway.offline','gateway:one:offline','gateway','one','critical','duplicate','firing',now(),now(),1)`, orgID); err == nil {
		t.Fatal("0126 must reject duplicate tenant/event/condition identity")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO alert_occurrences(
			org_id,event_key,dedup_key,severity,subject,state,first_observed_at,last_observed_at,occurrence_count
		) VALUES($1,'gateway.offline','bad-state','critical','bad','resolved',now(),now(),0)`, orgID); err == nil {
		t.Fatal("0126 must reject resolved occurrence without resolved_at")
	}
	down, err := os.ReadFile("migrations/0126_cross_product_alert_occurrences.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err == nil {
		t.Fatal("0126 down must refuse non-empty occurrence history")
	}
}
