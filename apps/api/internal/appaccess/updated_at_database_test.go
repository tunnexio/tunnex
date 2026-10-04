package appaccess

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestAppAccessUpdatedAtMigrationLocalDatabase(t *testing.T) {
	f := newHostnameReuseFixture(t, 179)
	ctx := context.Background()
	app := f.create("timestamps.apps.example.net")
	grant, err := f.service.CreateGrant(ctx, f.org, f.user, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: f.user, Enabled: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	f.disable(app)
	old := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, table := range []string{"app_access_applications", "app_access_grants", "app_access_serving_publications"} {
		f.exec("UPDATE "+table+" SET updated_at=$1", old)
	}
	// Include retained authority/history and tenant/identity rows: adding or
	// removing these triggers must not rewrite data or alter unrelated triggers.
	snapshot := func() string {
		t.Helper()
		const query = `SELECT jsonb_build_object(
   'applications',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM app_access_applications r),
   'grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM app_access_grants r),
   'publications',(SELECT jsonb_agg(to_jsonb(r) ORDER BY org_id,app_id) FROM app_access_serving_publications r),
   'revisions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY org_id,app_id,revision) FROM app_access_revisions r),
   'claims',(SELECT jsonb_agg(to_jsonb(r) ORDER BY hostname,org_id,app_id) FROM app_access_hostnames r),
   'audits',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM audit_logs r),
   'users',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM users r),
   'memberships',(SELECT jsonb_agg(to_jsonb(r) ORDER BY org_id,user_id) FROM memberships r),
   'organizations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM organizations r),
   'other_triggers',(SELECT jsonb_agg(jsonb_build_object('table',c.relname,'name',t.tgname,'definition',pg_get_triggerdef(t.oid)) ORDER BY c.relname,t.tgname)
     FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='public' AND NOT t.tgisinternal AND t.tgname<>'set_updated_at')
  )::text`
		var value string
		if err := f.pool.QueryRow(ctx, query).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	triggerCount := func() int {
		t.Helper()
		var count int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
   JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_proc p ON p.oid=t.tgfoid
   WHERE n.nspname='public' AND c.relname=ANY($1) AND NOT t.tgisinternal
   AND t.tgname='set_updated_at' AND p.proname='set_updated_at' AND t.tgtype=19`,
			[]string{"app_access_applications", "app_access_grants", "app_access_serving_publications"}).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	migratePreserving := func(version uint, want int) {
		t.Helper()
		before := snapshot()
		if err := db.MigrateTo(f.pool.Config().ConnString(), version); err != nil {
			t.Fatal(err)
		}
		if snapshot() != before {
			t.Fatal("timestamp migration rewrote existing data or unrelated triggers")
		}
		if got := triggerCount(); got != want {
			t.Fatalf("timestamp trigger count=%d, want %d", got, want)
		}
	}
	if triggerCount() != 0 {
		t.Fatal("historical179 fixture unexpectedly has timestamp triggers")
	}
	migratePreserving(180, 3)
	for _, row := range []struct {
		table, key string
		id         uuid.UUID
	}{
		{"app_access_applications", "id", app.ID},
		{"app_access_grants", "id", grant.ID},
		{"app_access_serving_publications", "app_id", app.ID},
	} {
		t.Run(row.table, func(t *testing.T) {
			query := "SELECT (to_jsonb(r)-'updated_at')::text FROM " + row.table + " r WHERE org_id=$1 AND " + row.key + "=$2"
			var before, after string
			if err := f.pool.QueryRow(ctx, query, f.org, row.id).Scan(&before); err != nil {
				t.Fatal(err)
			}
			var stamped time.Time
			if err := f.pool.QueryRow(ctx, "UPDATE "+row.table+" SET updated_at=$3 WHERE org_id=$1 AND "+row.key+"=$2 RETURNING updated_at", f.org, row.id, old).Scan(&stamped); err != nil {
				t.Fatal(err)
			}
			if !stamped.After(old) {
				t.Fatal("shared trigger did not override caller-supplied old timestamp")
			}
			if err := f.pool.QueryRow(ctx, query, f.org, row.id).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("timestamp update changed other fields")
			}
		})
	}
	migratePreserving(179, 0)
	migratePreserving(180, 3)
	// The common timestamp trigger must compose with optimistic versions,
	// transactional grant audit and confirmed-withdrawal archival authority.
	updated, err := f.service.UpdateGrant(ctx, f.org, f.user, grant.ID, GrantUpdate{Enabled: false}, grant.Version, true)
	if err != nil || updated.Version != grant.Version+1 || !updated.UpdatedAt.After(old) {
		t.Fatal("versioned grant update after migration", updated, err)
	}
	revoked, err := f.service.RevokeGrant(ctx, f.org, f.user, grant.ID, updated.Version)
	if err != nil || revoked.RevokedAt == nil || revoked.Version != updated.Version+1 {
		t.Fatal("audited revoke after migration", revoked, err)
	}
	f.archive(app)
	if !f.claimReleased(app, app.Draft.PublicHostname) {
		t.Fatal("timestamp trigger interfered with confirmed-withdrawal hostname release")
	}
}
