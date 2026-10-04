package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestNativeSSOConfigRestoreLocalDatabase(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") != "1" {
		t.Skip("owned isolated PostgreSQL qualification")
	}
	password := os.Getenv("AA0_DB_PASSWORD")
	if password == "" {
		t.Fatal("owned database credential missing")
	}
	target := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", password), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
	t.Setenv("TUNNEX_TEST_DATABASE_URL", target.String())
	ctx, pool := testpostgres.New(t)
	q := sqlc.New(pool)
	actor, foreignOrg := uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal("isolated SSO fixture statement failed")
		}
	}
	exec("INSERT INTO users(id,email,name) VALUES($1,$2,'SSO restore actor')", actor, actor.String()+"@fixture.test")
	org := func() uuid.UUID {
		t.Helper()
		id := uuid.New()
		exec("INSERT INTO organizations(id,name,slug) VALUES($1,'SSO fixture',$2)", id, id.String())
		return id
	}
	// An independently scoped row proves cleanup never sweeps other tenants.
	exec("INSERT INTO organizations(id,name,slug) VALUES($1,'Foreign SSO fixture',$2)", foreignOrg, foreignOrg.String())
	exec("INSERT INTO sso_configs(org_id,provider,client_id,client_secret_sealed,enabled) VALUES($1,'google','foreign', $2,true)", foreignOrg, []byte{9, 0, 8, 255})
	foreignBefore, err := q.GetSSOConfig(ctx, sqlc.GetSSOConfigParams{OrgID: foreignOrg, Provider: "google"})
	if err != nil {
		t.Fatal("foreign fixture unavailable")
	}
	get := func(id uuid.UUID) sqlc.SsoConfig {
		t.Helper()
		r, e := q.GetSSOConfig(ctx, sqlc.GetSSOConfigParams{OrgID: id, Provider: "google"})
		if e != nil {
			t.Fatal("isolated SSO row unavailable")
		}
		return r
	}
	backupRow := func(t *testing.T, id uuid.UUID) *nativeSSOConfigSnapshot {
		t.Helper()
		backup := &nativeSSOConfigSnapshot{t: t, pool: pool, org: id, actor: actor, clientID: "aa9-owned-client"}
		row, err := q.GetSSOConfig(ctx, sqlc.GetSSOConfigParams{OrgID: id, Provider: "google"})
		if err == nil {
			backup.original = &row
		} else if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("isolated backup projection unavailable")
		}
		return backup
	}
	captureRow := func(backup *nativeSSOConfigSnapshot) { row := get(backup.org); backup.installed = &row }
	installed := func(id uuid.UUID) {
		t.Helper()
		exec(`INSERT INTO sso_configs(org_id,provider,client_id,client_secret_sealed,enabled,secret_fingerprint) VALUES($1,'google','aa9-owned-client',$2,true,'fixture-fingerprint') ON CONFLICT(org_id,provider) DO UPDATE SET client_id=EXCLUDED.client_id,client_secret_sealed=EXCLUDED.client_secret_sealed,enabled=true,tenant_id=NULL,secret_fingerprint=EXCLUDED.secret_fingerprint`, id, []byte{1, 0, 2, 255, 3})
	}
	auditCount := func(id uuid.UUID) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='sso.fixture_config_restored'", id).Scan(&n); err != nil {
			t.Fatal("cleanup audit unavailable")
		}
		return n
	}
	seedOriginal := func(id uuid.UUID) sqlc.SsoConfig {
		t.Helper()
		created := time.Date(2025, 2, 3, 4, 5, 6, 123456000, time.UTC)
		updated := created.Add(17 * time.Minute)
		exec(`INSERT INTO sso_configs(id,org_id,provider,client_id,client_secret_sealed,enabled,created_at,updated_at,tenant_id,secret_fingerprint) VALUES($1,$2,'google','original-client',$3,false,$4,$5,'original-tenant','original-fingerprint')`, uuid.New(), id, []byte{77, 0, 255, 44, 1, 128}, created, updated)
		return get(id)
	}
	t.Run("original_absent_restores_absence_with_scoped_audit", func(t *testing.T) {
		id := org()
		backup := backupRow(t, id)
		if backup.original != nil {
			t.Fatal("original absence not captured")
		}
		installed(id)
		captureRow(backup)
		if err := backup.restore(ctx); err != nil {
			t.Fatal("absence cleanup refused")
		}
		if _, err := q.GetSSOConfig(ctx, sqlc.GetSSOConfigParams{OrgID: id, Provider: "google"}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("original absence not restored")
		}
		if auditCount(id) != 1 {
			t.Fatal("cleanup audit missing or duplicated")
		}
		var actorID uuid.UUID
		var kind, target string
		var metadata []byte
		if err := pool.QueryRow(ctx, "SELECT actor_user_id,target_type,target_id,metadata FROM audit_logs WHERE org_id=$1 AND action='sso.fixture_config_restored'", id).Scan(&actorID, &kind, &target, &metadata); err != nil {
			t.Fatal("scoped audit projection unavailable")
		}
		var m map[string]any
		if json.Unmarshal(metadata, &m) != nil || actorID != actor || kind != "sso_config" || target != "google" || m["exact_original_restored"] != true || m["provider"] != "google" {
			t.Fatal("cleanup audit actor/scope/metadata incorrect")
		}
	})
	t.Run("existing_original_restores_every_sealed_field_and_timestamp", func(t *testing.T) {
		id := org()
		original := seedOriginal(id)
		backup := backupRow(t, id)
		installed(id)
		captureRow(backup)
		if reflect.DeepEqual(*backup.installed, original) {
			t.Fatal("fixture did not change original")
		}
		if err := backup.restore(ctx); err != nil {
			t.Fatal("exact cleanup refused")
		}
		if !reflect.DeepEqual(get(id), original) {
			t.Fatal("sealed row/timestamps not restored exactly")
		}
		if auditCount(id) != 1 {
			t.Fatal("exact restore audit missing")
		}
	})
	t.Run("concurrent_config_change_refused_without_row_or_audit_mutation", func(t *testing.T) {
		id := org()
		seedOriginal(id)
		backup := backupRow(t, id)
		installed(id)
		captureRow(backup)
		// Same ID/client/enabled state, but another writer changes sealed bytes.
		exec("UPDATE sso_configs SET client_secret_sealed=$2 WHERE org_id=$1 AND provider='google'", id, []byte{88, 99, 0, 255})
		changed := get(id)
		if err := backup.restore(ctx); err == nil {
			t.Fatal("concurrent sealed configuration change overwritten")
		}
		if !reflect.DeepEqual(get(id), changed) {
			t.Fatal("concurrent row changed by refused cleanup")
		}
		if auditCount(id) != 0 {
			t.Fatal("refused cleanup wrote audit")
		}
	})
	t.Run("audit_failure_rolls_back_cleanup_then_retry_restores_exactly", func(t *testing.T) {
		id := org()
		original := seedOriginal(id)
		backup := backupRow(t, id)
		installed(id)
		captureRow(backup)
		before := get(id)
		exec(`CREATE FUNCTION fixture_sso_restore_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated cleanup audit fault'; END $$`)
		exec(`CREATE TRIGGER fixture_sso_restore_audit_fault BEFORE INSERT ON audit_logs FOR EACH ROW WHEN(NEW.action='sso.fixture_config_restored') EXECUTE FUNCTION fixture_sso_restore_audit_fault()`)
		if err := backup.restore(ctx); err == nil {
			t.Fatal("cleanup audit fault accepted")
		}
		if !reflect.DeepEqual(get(id), before) || auditCount(id) != 0 {
			t.Fatal("cleanup/audit transaction was not rolled back")
		}
		exec("DROP TRIGGER fixture_sso_restore_audit_fault ON audit_logs")
		exec("DROP FUNCTION fixture_sso_restore_audit_fault()")
		if err := backup.restore(context.Background()); err != nil {
			t.Fatal("cleanup retry refused")
		}
		if !reflect.DeepEqual(get(id), original) || auditCount(id) != 1 {
			t.Fatal("retry exact restore/audit incorrect")
		}
	})
	foreignAfter, err := q.GetSSOConfig(ctx, sqlc.GetSSOConfigParams{OrgID: foreignOrg, Provider: "google"})
	if err != nil || !reflect.DeepEqual(foreignAfter, foreignBefore) || auditCount(foreignOrg) != 0 {
		t.Fatal("cleanup crossed organization boundary")
	}
}
