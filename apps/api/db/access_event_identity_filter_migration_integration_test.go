package db_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestAccessEventIdentityFilterMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run 0128 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adminPool.Close)

	base, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_access_identity_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	base.Path = "/" + name
	dsn := base.String()
	if err := db.MigrateTo(dsn, 127); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	orgID, eventID := uuid.New(), uuid.New()
	deviceID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$2)`, orgID, "identity-migration-"+orgID.String()[:8]); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_events (
			id,org_id,seq,occurred_at,decision,src_device_id,src_user_id,
			src_ip,dst_ip,protocol,created_at,src_kind
		) VALUES ($1,$2,1,now(),'allow',$3,$4,'10.0.0.1','10.0.0.2','tcp',now(),'human')`,
		eventID, orgID, deviceID, userID); err != nil {
		t.Fatalf("seed attributed event: %v", err)
	}
	assertEvent := func() {
		t.Helper()
		var gotDevice, gotUser uuid.UUID
		var gotKind string
		if err := pool.QueryRow(ctx, `SELECT src_device_id,src_user_id,src_kind FROM access_events WHERE org_id=$1 AND id=$2`, orgID, eventID).Scan(&gotDevice, &gotUser, &gotKind); err != nil {
			t.Fatalf("retained event: %v", err)
		}
		if gotDevice != deviceID || gotUser != userID || gotKind != "human" {
			t.Fatalf("retained attribution = (%s,%s,%q), want (%s,%s,human)", gotDevice, gotUser, gotKind, deviceID, userID)
		}
	}
	assertEvent()

	assertIndex := func(index string, present bool, fragments ...string) {
		t.Helper()
		var definition string
		err := pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND indexname=$1`, index).Scan(&definition)
		if !present {
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("index %s present=%v err=%v definition=%q", index, err == nil, err, definition)
			}
			return
		}
		if err != nil {
			t.Fatalf("index %s: %v", index, err)
		}
		for _, fragment := range fragments {
			if !strings.Contains(definition, fragment) {
				t.Fatalf("index %s definition %q missing %q", index, definition, fragment)
			}
		}
	}

	assertIndex("access_events_org_agent_created_id_idx", true, "org_id", "src_device_id", "src_kind = 'agent'")
	if err := db.MigrateTo(dsn, 128); err != nil {
		t.Fatal(err)
	}
	assertEvent()
	assertIndex("access_events_org_agent_created_id_idx", false)
	assertIndex("access_events_org_device_created_id_idx", true, "org_id", "src_device_id", "created_at DESC", "id DESC", "src_device_id IS NOT NULL")
	assertIndex("access_events_org_user_created_id_idx", true, "org_id", "src_user_id", "created_at DESC", "id DESC", "src_user_id IS NOT NULL")

	if err := db.DownOne(dsn); err != nil {
		t.Fatalf("0128 down: %v", err)
	}
	assertEvent()
	assertIndex("access_events_org_device_created_id_idx", false)
	assertIndex("access_events_org_user_created_id_idx", false)
	assertIndex("access_events_org_agent_created_id_idx", true, "src_kind = 'agent'")
	if err := db.MigrateTo(dsn, 128); err != nil {
		t.Fatalf("0128 up again: %v", err)
	}
	assertEvent()
}
