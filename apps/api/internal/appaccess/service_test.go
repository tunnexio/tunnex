package appaccess

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"os"
	"strings"
	"testing"
)

func TestDraftValidation(t *testing.T) {
	in := DraftInput{Name: "App", Icon: "app", OriginURL: "http://origin:8080", GatewayID: uuid.New(), PublicHostname: "one.apps.fixture.test", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}
	s := NewService(nil, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}})
	if _, _, e := s.validate(in); e != nil {
		t.Fatal(e)
	}
	for _, host := range []string{"console.other.test", "*.apps.fixture.test", "one.apps.fixture.test:443", "127.0.0.1", "one.apps.fixture.test.", "ONE.BAD.test"} {
		bad := in
		bad.PublicHostname = host
		if _, _, e := s.validate(bad); e == nil {
			t.Fatalf("accepted hostname %s", host)
		}
	}
	for _, origin := range []string{"ftp://origin", "https://user:pass@origin", "https://origin/path", "https://origin/?secret=x", "https://origin/#x", "https://origin:0", "https://origin/%2f", "https://origin\\evil"} {
		bad := in
		bad.OriginURL = origin
		if _, _, e := s.validate(bad); e == nil {
			t.Fatalf("accepted origin %s", origin)
		}
	}
	for _, console := range []string{"console.fixture.test", "", "console.invalid.test:443", "https://console.invalid.test"} {
		bad := NewService(nil, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{console}})
		if bad.domainReady {
			t.Fatal("unsafe domain configuration ready")
		}
	}
}
func code(t *testing.T, e error, want string) {
	t.Helper()
	var a *apierr.Error
	if !errors.As(e, &a) || a.Code != want {
		t.Fatalf("want %s got %v", want, e)
	}
}
func TestRegistryLocalDatabase(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") != "1" {
		t.Skip("run owned local integration harness")
	}
	password := os.Getenv("AA0_DB_PASSWORD")
	if password == "" {
		t.Fatal("owned stack password required")
	}
	ctx := context.Background()
	dsn := fmt.Sprintf("postgres://aa0:%s@postgres:5432/aa0?sslmode=disable", password)
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Close)
	name := "aa1_registry_" + uuid.New().String()[:8]
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+name); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)") })
	dsn = fmt.Sprintf("postgres://aa0:%s@postgres:5432/%s?sslmode=disable", password, name)
	if e = db.MigrateTo(dsn, 166); e != nil {
		t.Fatal(e)
	}
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	org, other, actor, gateway, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, e = pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec("INSERT INTO organizations(id,name,slug) VALUES($1,'Old','old'),($2,'Other','other')", org, other)
	exec("INSERT INTO users(id,email) VALUES($1,'test@example.test')", actor)
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,enrolled_kind) VALUES($1,$2,'gateway','local','gateway'),($3,$4,'foreign','foreign','gateway')", gateway, org, foreign, other)
	if e = db.MigrateTo(dsn, 167); e != nil {
		t.Fatal(e)
	}
	var oldName string
	if e = pool.QueryRow(ctx, "SELECT name FROM organizations WHERE id=$1", org).Scan(&oldName); e != nil || oldName != "Old" {
		t.Fatalf("historical row changed: %v", e)
	}
	// Empty registry rolls down safely; previous organizations survive.
	if e = db.MigrateTo(dsn, 166); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(dsn, 167); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(dsn, 174); e != nil {
		t.Fatal(e)
	}
	s := NewService(pool, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}})
	settings, e := s.GetSettings(ctx, org)
	if e != nil || settings.Enabled || settings.Version != 1 {
		t.Fatalf("default setting %+v %v", settings, e)
	}
	_, e = s.UpdateSettings(ctx, org, actor, true, 1, false)
	code(t, e, "feature_unavailable")
	_, e = s.UpdateSettings(ctx, org, actor, true, 1, true)
	if e != nil {
		t.Fatal(e)
	}
	in := DraftInput{Name: "Registry", OriginURL: "http://origin", GatewayID: gateway, PublicHostname: "one.apps.fixture.test", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}
	app, e := s.CreateDraft(ctx, org, actor, in, true)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.CreateDraft(ctx, org, actor, in, true)
	code(t, e, "hostname_taken")
	_, e = s.GetApplication(ctx, other, app.ID)
	code(t, e, "application_not_found")
	_, e = s.GetRevision(ctx, other, app.ID, 1)
	code(t, e, "application_not_found")
	bad := in
	bad.GatewayID = foreign
	bad.PublicHostname = "foreign.apps.fixture.test"
	_, e = s.CreateDraft(ctx, org, actor, bad, true)
	code(t, e, "application_not_found")
	_, e = s.UpdateDraft(ctx, org, actor, app.ID, in, 2, true)
	code(t, e, "version_conflict")
	in.Name = "Updated"
	in.PublicHostname = "two.apps.fixture.test"
	updated, e := s.UpdateDraft(ctx, org, actor, app.ID, in, 1, true)
	if e != nil || updated.Version != 2 {
		t.Fatalf("update %v %v", updated, e)
	}
	old, e := s.GetRevision(ctx, org, app.ID, 1)
	if e != nil || old.Name != "Registry" {
		t.Fatal("historical revision changed", e)
	}
	if _, e = pool.Exec(ctx, "UPDATE app_access_revisions SET name='tampered' WHERE org_id=$1", org); e == nil {
		t.Fatal("revision update allowed")
	}
	list, e := s.ListApplications(ctx, org, "Updated", 1, 0)
	if e != nil || len(list) != 1 {
		t.Fatal("search", e)
	}
	list, e = s.ListApplications(ctx, other, "", 10, 0)
	if e != nil || len(list) != 0 {
		t.Fatal("tenant list leak", e)
	}
	// Composite FK refuses foreign-gateway revision inserts independently of service validation.
	if _, e = pool.Exec(ctx, `INSERT INTO app_access_revisions(org_id,app_id,revision,name,origin_url,gateway_id,public_hostname,idle_timeout_seconds,absolute_timeout_seconds,digest) VALUES($1,$2,3,'foreign','http://origin',$3,'two.apps.fixture.test',60,300,repeat('a',64))`, org, app.ID, foreign); e == nil {
		t.Fatal("foreign gateway composite FK missing")
	}
	var pgError *pgconn.PgError
	if !errors.As(e, &pgError) || pgError.Code != "23503" || pgError.ConstraintName != "app_access_revisions_org_id_gateway_id_fkey" {
		t.Fatalf("wrong foreign-gateway rejection: %v", e)
	}
	var auditCount int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action LIKE 'app_access.%'", org).Scan(&auditCount); e != nil || auditCount != 3 {
		t.Fatalf("expected settings/create/update audits: %d %v", auditCount, e)
	}
	// An invalid audit actor rolls back registry and hostname changes atomically.
	bad = in
	bad.PublicHostname = "rollback.apps.fixture.test"
	if _, e = s.CreateDraft(ctx, org, uuid.New(), bad, true); e == nil {
		t.Fatal("missing actor audit accepted")
	}
	var count int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM app_access_hostnames WHERE hostname=$1", bad.PublicHostname).Scan(&count); e != nil || count != 0 {
		t.Fatal("partial audited mutation", e)
	}
	_, e = s.UpdateSettings(ctx, org, actor, false, 2, false)
	if e != nil {
		t.Fatal("disable after feature loss", e)
	}
	_, e = s.CreateDraft(ctx, org, actor, in, true)
	code(t, e, "app_access_disabled")
	if _, e = s.GetApplication(ctx, org, app.ID); e != nil {
		t.Fatal("feature-loss inspection", e)
	}
	// Search counts Unicode characters, matching OpenAPI string semantics.
	_, e = s.UpdateSettings(ctx, org, actor, true, 3, true)
	if e != nil {
		t.Fatal(e)
	}
	chinese := strings.Repeat("中", 50)
	in.Name = chinese
	_, e = s.UpdateDraft(ctx, org, actor, app.ID, in, 2, true)
	if e != nil {
		t.Fatal(e)
	}
	list, e = s.ListApplications(ctx, org, chinese, 10, 0)
	if e != nil || len(list) != 1 || list[0].Draft.Name != chinese {
		t.Fatalf("unicode search failed: %v", e)
	}
	_, e = s.ListApplications(ctx, org, strings.Repeat("中", 101), 10, 0)
	code(t, e, "invalid_pagination")
	_, e = s.ListApplications(ctx, org, string([]byte{0xff}), 10, 0)
	code(t, e, "invalid_pagination")
	_, e = s.ListApplications(ctx, org, "", 10, 10001)
	code(t, e, "invalid_pagination")
	// Run down SQL inside a transaction: refusal must preserve history. Avoid dirtying migrator metadata.
	down, e := db.MigrationsFS.ReadFile("migrations/0167_app_access.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, string(down))
	_ = tx.Rollback(ctx)
	if e == nil {
		t.Fatal("destructive history rollback allowed")
	}
	if _, e = s.GetRevision(ctx, org, app.ID, 1); e != nil {
		t.Fatal("down refusal erased history", e)
	}
	// Retained revision history blocks deletion and rolls back its pre-delete audit.
	exec("UPDATE nodes SET status='revoked',revoked_at=now() WHERE id=$1", gateway)
	nodeService := nodes.NewService(pool, nil, nil)
	e = nodeService.DeleteRevokedNode(ctx, actor, org, gateway)
	code(t, e, "node_app_access_history_retained")
	var refusal *apierr.Error
	if !errors.As(e, &refusal) || refusal.Status != 409 {
		t.Fatalf("expected conflict: %v", e)
	}
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM nodes WHERE id=$1", gateway).Scan(&count); e != nil || count != 1 {
		t.Fatal("referenced gateway removed", e)
	}
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE action='node.deleted' AND target_id=$1", gateway.String()).Scan(&count); e != nil || count != 0 {
		t.Fatal("failed delete left audit", e)
	}
	spare := uuid.New()
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,enrolled_kind,status,revoked_at) VALUES($1,$2,'unreferenced','spare','gateway','revoked',now())", spare, org)
	if e = nodeService.DeleteRevokedNode(ctx, actor, org, spare); e != nil {
		t.Fatal("unreferenced revoked deletion", e)
	}
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM nodes WHERE id=$1", spare).Scan(&count); e != nil || count != 0 {
		t.Fatal("unreferenced gateway not deleted", e)
	}
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE action='node.deleted' AND target_id=$1", spare.String()).Scan(&count); e != nil || count != 1 {
		t.Fatal("successful delete audit missing", e)
	}

	// Previously enabled settings cannot authorize access or edits after tenant deletion.
	exec("UPDATE organizations SET deleted_at=now() WHERE id=$1", org)
	_, e = s.GetSettings(ctx, org)
	code(t, e, "application_not_found")
	_, e = s.GetApplication(ctx, org, app.ID)
	code(t, e, "application_not_found")
	_, e = s.GetRevision(ctx, org, app.ID, 1)
	code(t, e, "application_not_found")
	_, e = s.ListApplications(ctx, org, "", 10, 0)
	code(t, e, "application_not_found")
	_, e = s.UpdateSettings(ctx, org, actor, false, 4, false)
	code(t, e, "application_not_found")
	_, e = s.UpdateDraft(ctx, org, actor, app.ID, in, 3, true)
	code(t, e, "application_not_found")
	in.PublicHostname = "deleted.apps.fixture.test"
	_, e = s.CreateDraft(ctx, org, actor, in, true)
	code(t, e, "application_not_found")

}
