package appaccess

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"strings"
	"testing"
)

func TestProxyAuthorityLocalDatabase(t *testing.T) {
	pool := grantPool(t)
	dsn := pool.Config().ConnString()
	for _, v := range []uint{170, 169, 170, 174} {
		if e := db.MigrateTo(dsn, v); e != nil {
			t.Fatal(e)
		}
	}
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	s := NewService(pool, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}})
	credential, secret, e := s.IssueProxyCredential(ctx, "local-proxy")
	if e != nil {
		t.Fatal(e)
	}
	identity, e := s.AuthenticateProxy(ctx, secret)
	if e != nil || identity.CredentialID != credential.ID || identity.CredentialVersion != 1 {
		t.Fatal("proxy auth", e)
	}
	var stored []byte
	if e = pool.QueryRow(ctx, "SELECT token_hash FROM app_access_proxy_credentials WHERE id=$1", credential.ID).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	expected := sha256.Sum256([]byte(secret))
	if string(stored) != string(expected[:]) || strings.Contains(string(stored), secret) {
		t.Fatal("credential not hash-only")
	}
	for _, invalid := range []string{"", "tnxm_" + secret, "tnx_" + secret, " " + secret, secret + "=", ProxyTokenPrefix + "invalid"} {
		if _, e = s.AuthenticateProxy(ctx, invalid); e == nil {
			t.Fatal("wrong credential family accepted")
		}
	}
	for _, host := range []string{"unknown.apps.fixture.test", "console.other.test", "unknown.apps.fixture.test:443", "UNKNOWN.apps.fixture.test", "127.0.0.1", "unknown.apps.fixture.test.", "one.apps.fixture.test"} {
		if _, e = s.LookupRoute(ctx, identity, host, true); e == nil {
			t.Fatal("empty publication routed")
		}
	}
	org, other, actor, gateway := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Proxy','proxy'),($2,'Other','proxyother')", org, other)
	exec("INSERT INTO users(id,email,name)VALUES($1,'proxy@test.fixture','Proxy')", actor)
	exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')", org, actor)
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,cert_not_after,enrolled_kind)VALUES($1,$2,'proxygateway','proxygw',now()+interval '1 day','gateway')", gateway, org)
	if _, e = s.UpdateSettings(ctx, org, actor, true, 1, true); e != nil {
		t.Fatal(e)
	}
	a, e := s.CreateDraft(ctx, org, actor, DraftInput{Name: "ProxyDraft", OriginURL: "http://origin", GatewayID: gateway, PublicHostname: "one.apps.fixture.test", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.LookupRoute(ctx, identity, a.Draft.PublicHostname, true); e == nil {
		t.Fatal("draft host became route")
	}
	// Publication rows here are isolated negative schema fixtures, never native runtime state.
	insert := "INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,state)VALUES($1,$2,$3,$4,$5,$6,'pending')"
	if _, e = pool.Exec(ctx, insert, other, a.ID, gateway, 1, a.Draft.Digest, a.Draft.PublicHostname); e == nil {
		t.Fatal("foreign org publication accepted")
	}
	if _, e = pool.Exec(ctx, insert, org, a.ID, uuid.New(), 1, a.Draft.Digest, a.Draft.PublicHostname); e == nil {
		t.Fatal("foreign gateway publication accepted")
	}
	if _, e = pool.Exec(ctx, insert, org, a.ID, gateway, 1, strings.Repeat("0", 64), a.Draft.PublicHostname); e == nil {
		t.Fatal("wrong revision digest accepted")
	}
	exec(insert, org, a.ID, gateway, 1, a.Draft.Digest, a.Draft.PublicHostname)
	if _, e = s.LookupRoute(ctx, identity, a.Draft.PublicHostname, true); e == nil {
		t.Fatal("pending publication routed")
	}
	decision, e := s.AuthorizeRequest(ctx, identity, RequestInput{}, true)
	var denied *apierr.Error
	if !errors.As(e, &denied) || denied.Status != 403 || decision.Allowed || decision.LeaseUntil != nil || decision.StreamID != uuid.Nil {
		t.Fatal("request authority fabricated", e)
	}
	decision, e = s.RenewLease(ctx, identity, LeaseInput{}, true)
	if !errors.As(e, &denied) || denied.Status != 403 || decision.Allowed || decision.LeaseUntil != nil || decision.StreamID != uuid.Nil {
		t.Fatal("lease authority fabricated", e)
	}
	until, e := s.ChannelAuthorize(ctx, identity, RouteBinding{}, "gateway-certificate", true)
	if e == nil || !until.IsZero() {
		t.Fatal("browser channel authority fabricated")
	}
	forged := identity
	forged.CredentialVersion++
	if _, e = s.LookupRoute(ctx, forged, a.Draft.PublicHostname, true); e == nil {
		t.Fatal("credential version ignored")
	}
	exec(`CREATE FUNCTION aa4_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app_access.proxy_credential_revoked' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER aa4_fail_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION aa4_fail_audit()`)
	if _, e = s.RevokeProxyCredential(ctx, credential.ID, 1); e == nil {
		t.Fatal("revoke swallowed audit failure")
	}
	if _, e = s.AuthenticateProxy(ctx, secret); e != nil {
		t.Fatal("failed audit did not rollback", e)
	}
	exec("DROP TRIGGER aa4_fail_audit ON audit_logs; DROP FUNCTION aa4_fail_audit()")
	if _, e = s.RevokeProxyCredential(ctx, credential.ID, 2); e == nil {
		t.Fatal("stale revoke accepted")
	}
	revoked, e := s.RevokeProxyCredential(ctx, credential.ID, 1)
	if e != nil || revoked.Version != 2 || revoked.RevokedAt == nil {
		t.Fatal("revoke", e)
	}
	again, e := s.RevokeProxyCredential(ctx, credential.ID, 1)
	if e != nil || again.Version != 2 {
		t.Fatal("revoke not idempotent", e)
	}
	if _, e = s.AuthenticateProxy(ctx, secret); e == nil {
		t.Fatal("revoked secret accepted")
	}
	if _, e = s.AuthorizeRequest(ctx, identity, RequestInput{}, true); e == nil {
		t.Fatal("admitted identity outlived revoke")
	}
	var audits int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE action='app_access.proxy_credential_revoked' AND target_id=$1 AND actor_system='app-proxy-provisioning'", credential.ID.String()).Scan(&audits); e != nil || audits != 1 {
		t.Fatal("idempotent audit", e)
	}
	down, e := db.MigrationsFS.ReadFile("migrations/0170_app_access_proxy_authority.down.sql")
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
		t.Fatal("proxy history destructively rolled down")
	}
}
