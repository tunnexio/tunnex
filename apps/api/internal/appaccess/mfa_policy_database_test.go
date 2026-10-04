package appaccess

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestApplicationMFAPolicyLocalDatabase(t *testing.T) {
	p := grantPool(t)
	ctx := context.Background()
	// The migration is additive and the previous binary's app read remains valid.
	if err := db.MigrateTo(p.Config().ConnString(), 175); err != nil {
		t.Fatal(err)
	}
	org, actor, gateway := uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := p.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'MFA policy',$2)", org, org.String())
	exec("INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'MFA owner',now())", actor, actor.String()+"@fixture.test")
	exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')", org, actor)
	exec("INSERT INTO nodes(id,org_id,name,enrolled_kind,cert_serial)VALUES($1,$2,'MFA gateway','gateway',$3)", gateway, org, gateway.String())
	s := NewService(p, Config{AppBaseDomain: "apps.example.net", ConsoleHosts: []string{"console.example.com"}})
	if _, err := s.UpdateSettings(ctx, org, actor, true, 1, true); err != nil {
		t.Fatal(err)
	}
	app, err := s.CreateDraft(ctx, org, actor, DraftInput{Name: "MFA policy", OriginURL: "http://origin", GatewayID: gateway, PublicHostname: "mfa-policy-" + org.String()[:8] + ".apps.example.net", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 3600}, true)
	if err != nil {
		t.Fatal(err)
	}
	if app.RequireMFA {
		t.Fatal("pre-migration policy must be off")
	}
	if err = db.MigrateTo(p.Config().ConnString(), 176); err != nil {
		t.Fatal(err)
	}
	if err = db.MigrateTo(p.Config().ConnString(), 175); err != nil {
		t.Fatal("off policy rollback", err)
	}
	if err = db.MigrateTo(p.Config().ConnString(), 176); err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,state)VALUES($1,$2,$3,$4,$5,$6,'active')", org, app.ID, gateway, app.DraftRevision, app.Draft.Digest, app.Draft.PublicHostname)
	if _, err = s.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: actor, Enabled: true}, true); err != nil {
		t.Fatal(err)
	}
	enabled, err := s.UpdateMFAPolicy(ctx, org, actor, app.ID, true, app.Version)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled.RequireMFA || enabled.Version != app.Version+1 || enabled.DraftRevision != app.DraftRevision || enabled.PublicationState != "published" {
		t.Fatal("policy changed immutable draft/publication")
	}
	unchanged, err := s.UpdateMFAPolicy(ctx, org, actor, app.ID, true, enabled.Version)
	if err != nil || unchanged.Version != enabled.Version {
		t.Fatal("idempotent current value", err)
	}
	_, err = s.UpdateMFAPolicy(ctx, org, actor, app.ID, false, app.Version)
	code(t, err, "version_conflict")
	_, err = s.UpdateMFAPolicy(ctx, uuid.New(), actor, app.ID, false, enabled.Version)
	code(t, err, "application_not_found")
	var count int
	if err = p.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='app_access.mfa_policy_updated' AND metadata->>'require_mfa'='true' AND metadata->>'previous_require_mfa'='false' AND metadata->>'mfa_freshness_seconds'='900'", org).Scan(&count); err != nil || count != 1 {
		t.Fatal("transactional audit", count, err)
	}
	// Audit failure must roll back the policy and optimistic version together.
	exec("CREATE FUNCTION reject_mfa_policy_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app_access.mfa_policy_updated' THEN RAISE EXCEPTION 'fixture audit unavailable'; END IF; RETURN NEW; END $$")
	exec("CREATE TRIGGER reject_mfa_policy_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_mfa_policy_audit()")
	if _, err = s.UpdateMFAPolicy(ctx, org, actor, app.ID, false, enabled.Version); err == nil {
		t.Fatal("audit failure committed policy")
	}
	current, err := s.GetApplication(ctx, org, app.ID)
	if err != nil || !current.RequireMFA || current.Version != enabled.Version {
		t.Fatal("audit failure lost protected policy", err)
	}
	exec("DROP TRIGGER reject_mfa_policy_audit ON audit_logs")
	// Rollback is refused while protection is enabled, without poisoning the migration ledger.
	down, err := db.MigrationsFS.ReadFile("migrations/0176_app_access_mfa_policy.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, string(down)); err == nil || !strings.Contains(err.Error(), "MFA policies are retained") {
		t.Fatal("protected rollback accepted", err)
	}
	current, err = s.UpdateMFAPolicy(ctx, org, actor, app.ID, false, enabled.Version)
	if err != nil || current.RequireMFA || current.Version != enabled.Version+1 {
		t.Fatal("disable policy", err)
	}
	var grants int
	if err = p.QueryRow(ctx, "SELECT count(*) FROM app_access_grants WHERE org_id=$1 AND app_id=$2 AND enabled", org, app.ID).Scan(&grants); err != nil || grants != 1 {
		t.Fatal("policy changed grants", err)
	}
	exec("UPDATE app_access_applications SET state='archived' WHERE id=$1", app.ID)
	_, err = s.UpdateMFAPolicy(ctx, org, actor, app.ID, true, current.Version)
	code(t, err, "application_archived")
}
