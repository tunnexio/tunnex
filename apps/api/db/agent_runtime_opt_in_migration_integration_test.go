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

// TestAgentRuntimeOptInMigrationPostgres proves 0093's default, refusal, dirty
// state, preservation, successful rollback, and up-again compatibility against
// real PostgreSQL. Each branch uses its own throwaway database.
func TestAgentRuntimeOptInMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer adminPool.Close()

	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse admin DSN: %v", err)
	}

	newDatabase := func(label string) (string, *pgxpool.Pool) {
		t.Helper()
		name := "tnx_f04_optin_" + label + "_" + uuid.NewString()[:8]
		if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatalf("create %s database: %v", label, err)
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		})
		branchURL := *u
		branchURL.Path = "/" + name
		pool, err := pgxpool.New(ctx, branchURL.String())
		if err != nil {
			t.Fatalf("connect %s database: %v", label, err)
		}
		t.Cleanup(func() { pool.Close() })
		return branchURL.String(), pool
	}

	refuseDSN, refusePool := newDatabase("refuse")
	if err := db.MigrateTo(refuseDSN, 92); err != nil {
		t.Fatalf("migrate refusal branch to 0092: %v", err)
	}
	org := uuid.New()
	if _, err := refusePool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'F04 opt-in refusal',$2)", org, "f04-refuse-"+org.String()[:8]); err != nil {
		t.Fatalf("seed refusal org: %v", err)
	}
	if err := db.MigrateTo(refuseDSN, 93); err != nil {
		t.Fatalf("migrate refusal branch to 0093: %v", err)
	}
	var enabled bool
	if err := refusePool.QueryRow(ctx, "SELECT managed_agent_runtime_enabled FROM organizations WHERE id=$1", org).Scan(&enabled); err != nil {
		t.Fatalf("read 0093 default: %v", err)
	}
	if enabled {
		t.Fatal("0093 default must be false")
	}
	if _, err := refusePool.Exec(ctx, "UPDATE organizations SET managed_agent_runtime_enabled=true WHERE id=$1", org); err != nil {
		t.Fatalf("enable refusal org: %v", err)
	}
	if err := db.DownOne(refuseDSN); err == nil {
		t.Fatal("0093 down must refuse while a live organization is enabled")
	}
	version, dirty, ok, err := db.Version(refuseDSN)
	if err != nil || !ok || !dirty || version != 92 {
		t.Fatalf("refused down metadata = version=%d dirty=%v ok=%v err=%v; want 92/true/true", version, dirty, ok, err)
	}
	var columnExists bool
	if err := refusePool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_name='organizations' AND column_name='managed_agent_runtime_enabled'
	)`).Scan(&columnExists); err != nil {
		t.Fatalf("check refused column: %v", err)
	}
	if !columnExists {
		t.Fatal("refused down must preserve the opt-in column")
	}
	var preserved bool
	if err := refusePool.QueryRow(ctx, "SELECT managed_agent_runtime_enabled FROM organizations WHERE id=$1", org).Scan(&preserved); err != nil {
		t.Fatalf("read preserved refusal org: %v", err)
	}
	if !preserved {
		t.Fatal("refused down must preserve the enabled flag")
	}

	successDSN, successPool := newDatabase("success")
	if err := db.MigrateTo(successDSN, 93); err != nil {
		t.Fatalf("migrate success branch to 0093: %v", err)
	}
	successOrg := uuid.New()
	if _, err := successPool.Exec(ctx, "INSERT INTO organizations (id,name,slug,managed_agent_runtime_enabled) VALUES ($1,'F04 opt-in success',$2,false)", successOrg, "f04-success-"+successOrg.String()[:8]); err != nil {
		t.Fatalf("seed success org: %v", err)
	}
	if err := db.DownOne(successDSN); err != nil {
		t.Fatalf("0093 down after disable: %v", err)
	}
	if err := db.MigrateTo(successDSN, 93); err != nil {
		t.Fatalf("re-apply 0093: %v", err)
	}
	if err := successPool.QueryRow(ctx, "SELECT managed_agent_runtime_enabled FROM organizations WHERE id=$1", successOrg).Scan(&enabled); err != nil {
		t.Fatalf("read restored default: %v", err)
	}
	if enabled {
		t.Fatal("re-applied 0093 default must be false")
	}
	var name string
	if err := successPool.QueryRow(ctx, "SELECT name FROM organizations WHERE id=$1", successOrg).Scan(&name); err != nil {
		t.Fatalf("read preserved organization: %v", err)
	}
	if name != "F04 opt-in success" {
		t.Fatalf("organization was not preserved across down/up: %q", name)
	}
}
