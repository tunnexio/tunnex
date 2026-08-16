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

func TestAgentAccessEventAttributionMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run 0096 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	base, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	newDB := func(label string) (string, *pgxpool.Pool) {
		name := "tnx_f07_" + label + "_" + uuid.NewString()[:8]
		if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
		u := *base
		u.Path = "/" + name
		pool, err := pgxpool.New(ctx, u.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return u.String(), pool
	}

	successDSN, successPool := newDB("success")
	if err := db.MigrateTo(successDSN, 96); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(successDSN); err != nil {
		t.Fatalf("0096 empty rollback: %v", err)
	}
	var exists bool
	if err := successPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='access_events' AND column_name='policy_hash')`).Scan(&exists); err != nil || exists {
		t.Fatalf("column after down=%v err=%v", exists, err)
	}
	if err := db.MigrateTo(successDSN, 96); err != nil {
		t.Fatalf("0096 reapply: %v", err)
	}

	refuseDSN, refusePool := newDB("refuse")
	if err := db.MigrateTo(refuseDSN, 96); err != nil {
		t.Fatal(err)
	}
	org, event := uuid.New(), uuid.New()
	if _, err := refusePool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,'F07 rollback',$2)`, org, "f07-"+org.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := refusePool.Exec(ctx, `INSERT INTO access_events (id,org_id,seq,occurred_at,decision,src_ip,dst_ip,protocol,policy_hash,policy_version,src_kind,decision_reason) VALUES ($1,$2,1,now(),'deny','10.99.0.8','10.0.0.1','tcp','abcdef123456',7,'agent','no_matching_grant')`, event, org); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(refuseDSN); err == nil {
		t.Fatal("0096 rollback must refuse with attributed rows")
	}
	var hash, kind string
	if err := refusePool.QueryRow(ctx, `SELECT policy_hash,src_kind FROM access_events WHERE id=$1`, event).Scan(&hash, &kind); err != nil || hash != "abcdef123456" || kind != "agent" {
		t.Fatalf("refused rollback lost row hash=%q kind=%q err=%v", hash, kind, err)
	}
}
