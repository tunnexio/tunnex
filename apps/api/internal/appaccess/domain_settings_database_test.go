package appaccess

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
)

func TestDomainSettingsLocalDatabase(t *testing.T) {
	pool := grantPool(t) // Always an owned random child database; parent fixture is untouched.
	ctx := context.Background()
	dsn := pool.Config().ConnString()
	for _, version := range []uint{174, 175, 174, 175} {
		if err := db.MigrateTo(dsn, version); err != nil {
			t.Fatal("empty domain migration roundtrip", err)
		}
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, actor, gateway := uuid.New(), uuid.New(), uuid.New()
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Domains',$2)", org, org.String())
	exec("INSERT INTO users(id,email,email_verified_at)VALUES($1,$2,now())", actor, actor.String()+"@fixture.test")
	exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')", org, actor)
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,cert_not_after,enrolled_kind)VALUES($1,$2,'domains','domains-cert',now()+interval '1 day','gateway')", gateway, org)
	fallback := appdomains.Config{PortalURL: "https://console.example.com", AppBaseDomain: "apps.example.net"}
	domains := appdomains.New(pool, fallback)
	first, err := domains.Get(ctx)
	if err != nil || first.Version != 0 || first.Source != "environment" || first.Config != fallback || !first.ConfigurationReady {
		t.Fatal("environment fallback", first, err)
	}
	service := NewService(pool, Config{}).WithDomainProvider(domains)
	if _, err = service.UpdateSettings(ctx, org, actor, true, 1, true); err != nil {
		t.Fatal(err)
	}
	input := DraftInput{Name: "Existing", OriginURL: "http://origin", GatewayID: gateway, PublicHostname: "old.apps.example.net", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}
	app, err := service.CreateDraft(ctx, org, actor, input, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: actor, Enabled: true}, true); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ReportBrowserCapability(ctx, AuthenticatedGateway{org, gateway, "domains-cert"}, 1); err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,state)VALUES($1,$2,$3,$4,$5,$6,'active')", org, app.ID, gateway, app.Draft.Revision, app.Draft.Digest, app.Draft.PublicHostname)
	original, err := service.lookupServingRoute(ctx, app.Draft.PublicHostname, true)
	if err != nil {
		t.Fatal("original route", err)
	}
	in := appdomains.Update{PortalURL: "https://internal.tunnex.app", AppBaseDomain: "internal.tunnex.app", ExpectedVersion: 0}
	var results [2]error
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, results[i] = domains.Save(ctx, actor, in) }(i)
	}
	wg.Wait()
	if (results[0] == nil) == (results[1] == nil) {
		t.Fatal("concurrent first save did not reject stale form", results)
	}
	fresh := appdomains.New(pool, appdomains.Config{})
	saved, err := fresh.Get(ctx)
	if err != nil || saved.Version != 1 || saved.Source != "database" || saved.PortalURL != in.PortalURL {
		t.Fatal("replica/restart persistence", saved, err)
	}
	settings, err := service.GetSettings(ctx, org)
	if err != nil || settings.BaseDomain != "internal.tunnex.app" || !settings.DomainReady || !settings.Enabled {
		t.Fatal("runtime setting not effective", settings, err)
	}
	oldRoute, err := service.lookupServingRoute(ctx, app.Draft.PublicHostname, true)
	if err != nil || oldRoute.RouteBinding != original.RouteBinding || oldRoute.OriginURL != original.OriginURL {
		t.Fatal("published route rewritten or lost", err)
	}
	input.Name = "Changed branding only"
	updated, err := service.UpdateDraft(ctx, org, actor, app.ID, input, app.Version, true)
	if err != nil {
		t.Fatal("old hostname draft update failed", err)
	}
	revision, err := service.GetRevision(ctx, org, app.ID, app.DraftRevision)
	if err != nil || revision.Digest != app.Draft.Digest || revision.PublicHostname != app.Draft.PublicHostname {
		t.Fatal("immutable history drift", err)
	}
	input.PublicHostname = "moved.internal.tunnex.app"
	moved, err := service.UpdateDraft(ctx, org, actor, app.ID, input, updated.Version, true)
	if err != nil {
		t.Fatal("new base edit", err)
	}
	input.PublicHostname = app.Draft.PublicHostname
	updated, err = service.UpdateDraft(ctx, org, actor, app.ID, input, moved.Version, true)
	if err != nil {
		t.Fatal("historically owned hostname cannot be restored", err)
	}
	input.PublicHostname = "new.apps.example.net"
	if _, err = service.CreateDraft(ctx, org, actor, input, true); err == nil {
		t.Fatal("old base accepted for new app")
	}
	input.PublicHostname = "payroll.internal.tunnex.app"
	if _, err = service.CreateDraft(ctx, org, actor, input, true); err != nil {
		t.Fatal("new base not applied", err)
	}
	input.PublicHostname = "nested.payroll.internal.tunnex.app"
	if _, err = service.CreateDraft(ctx, org, actor, input, true); err == nil {
		t.Fatal("nested hostname accepted")
	}
	input.PublicHostname = "internal.tunnex.app"
	if _, err = service.UpdateDraft(ctx, org, actor, app.ID, input, updated.Version, true); err == nil {
		t.Fatal("app claimed portal hostname")
	}
	in.ExpectedVersion = 1
	in.PortalURL = "https://old.apps.example.net"
	in.AppBaseDomain = "old.apps.example.net"
	if _, err = domains.Save(ctx, actor, in); err == nil {
		t.Fatal("historical app hostname became portal")
	}
	if _, err = pool.Exec(ctx, "INSERT INTO app_access_hostnames(hostname,org_id,app_id)VALUES('internal.tunnex.app',$1,$2)", org, app.ID); err == nil {
		t.Fatal("portal reservation trigger absent")
	}
	in.PortalURL = "https://next.tunnex.app"
	in.AppBaseDomain = "next.tunnex.app"
	exec(`CREATE FUNCTION reject_domain_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app_access.domains_updated' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_domain_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_domain_audit()`)
	if _, err = domains.Save(ctx, actor, in); err == nil {
		t.Fatal("audit failure accepted partial save")
	}
	after, err := domains.Get(ctx)
	if err != nil || after.Version != 1 || after.PortalURL != saved.PortalURL {
		t.Fatal("failed save changed authority", err)
	}
	exec("DROP TRIGGER reject_domain_audit ON audit_logs; DROP FUNCTION reject_domain_audit()")
	var grants int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM app_access_grants WHERE org_id=$1", org).Scan(&grants); err != nil || grants != 1 {
		t.Fatal("domain save altered grants", grants, err)
	}
	// Exercise the actual rollback guard without dirtying this migration history.
	down, err := db.MigrationsFS.ReadFile("migrations/0175_app_access_domains.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, downErr := tx.Exec(ctx, string(down))
	_ = tx.Rollback(ctx)
	if downErr == nil {
		t.Fatal("domain override discarded on downgrade")
	}
	after, err = domains.Get(ctx)
	if err != nil || after.Version != saved.Version || after.Config != saved.Config {
		t.Fatal("blocked downgrade altered settings", err)
	}
	// Prove domain checks inside transactions do not acquire another pool slot.
	smallConfig := pool.Config().Copy()
	smallConfig.MaxConns = 1
	small, err := pgxpool.NewWithConfig(ctx, smallConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer small.Close()
	one := NewService(small, Config{}).WithDomainProvider(appdomains.New(small, fallback))
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	listed, err := one.ListGrants(bounded, org, &app.ID, "", nil, 10, 0)
	if err != nil || len(listed) != 1 {
		t.Fatal("one connection grant setup", err)
	}
	if _, err = one.UpdateGrant(bounded, org, actor, listed[0].ID, GrantUpdate{Enabled: true}, listed[0].Version, true); err != nil {
		t.Fatal("domain lookup acquired second connection in grant transaction", err)
	}
	if _, err = one.DesiredBrowser(bounded, AuthenticatedGateway{org, gateway, "domains-cert"}, true); err != nil {
		t.Fatal("domain lookup acquired second connection in gateway transaction", err)
	}
	pool.Close()
	if _, err = fresh.Effective(ctx); err == nil {
		t.Fatal("database failure silently used env fallback")
	}
	if service.domainConfigured(ctx) {
		t.Fatal("runtime kept stale domain authority after DB failure")
	}
}
