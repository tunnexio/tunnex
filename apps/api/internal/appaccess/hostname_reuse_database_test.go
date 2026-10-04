package appaccess

import (
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

type hostnameReuseFixture struct {
	t                  *testing.T
	pool               *pgxpool.Pool
	service            *Service
	org, user, gateway uuid.UUID
}

func newHostnameReuseFixture(t *testing.T, version uint) *hostnameReuseFixture {
	t.Helper()
	p := grantPool(t)
	if err := db.MigrateTo(p.Config().ConnString(), version); err != nil {
		t.Fatal(err)
	}
	f := &hostnameReuseFixture{t: t, pool: p, org: uuid.New(), user: uuid.New(), gateway: uuid.New()}
	f.exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Hostname reuse',$2)", f.org, f.org.String())
	f.exec("INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'Hostname owner',now())", f.user, f.user.String()+"@fixture.test")
	f.exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')", f.org, f.user)
	f.exec("INSERT INTO nodes(id,org_id,name,enrolled_kind,cert_serial,cert_not_after)VALUES($1,$2,'Hostname gateway','gateway',$3,now()+interval '1 day')", f.gateway, f.org, f.gateway.String())
	f.service = NewService(p, Config{AppBaseDomain: "apps.example.net", ConsoleHosts: []string{"console.example.com"}, ConsoleURL: "https://console.example.com"})
	if _, err := f.service.UpdateSettings(context.Background(), f.org, f.user, true, 1, true); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *hostnameReuseFixture) exec(query string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), query, args...); err != nil {
		f.t.Fatal(err)
	}
}
func (f *hostnameReuseFixture) input(host string) DraftInput {
	return DraftInput{Name: "Reusable app", OriginURL: "http://origin", GatewayID: f.gateway, PublicHostname: host, IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}
}
func (f *hostnameReuseFixture) create(host string) Application {
	f.t.Helper()
	a, err := f.service.CreateDraft(context.Background(), f.org, f.user, f.input(host), true)
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}
func (f *hostnameReuseFixture) disable(a Application) PublicationState {
	f.t.Helper()
	ctx := context.Background()
	p, err := f.service.GetPublication(ctx, f.org, a.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	var authority int64
	if p.Active != nil {
		authority = p.Active.AuthorityVersion
	}
	p, err = f.service.DisablePublication(ctx, f.org, f.user, a.ID, p.ApplicationVersion, authority)
	if err != nil || p.Active == nil || !p.Active.WithdrawalConfirmed || p.Active.State != "disabled" {
		f.t.Fatal("disable withdrawal", p, err)
	}
	return p
}
func (f *hostnameReuseFixture) archive(a Application) {
	f.t.Helper()
	p := f.disable(a)
	if err := f.service.ArchiveApplication(context.Background(), f.org, f.user, a.ID, p.ApplicationVersion); err != nil {
		f.t.Fatal(err)
	}
}
func (f *hostnameReuseFixture) claimReleased(a Application, host string) bool {
	f.t.Helper()
	var released bool
	if err := f.pool.QueryRow(context.Background(), "SELECT released_at IS NOT NULL FROM app_access_hostnames WHERE org_id=$1 AND app_id=$2 AND hostname=$3", f.org, a.ID, host).Scan(&released); err != nil {
		f.t.Fatal(err)
	}
	return released
}
func requireHostnameTaken(t *testing.T, err error) {
	t.Helper()
	var api *apierr.Error
	if !errors.As(err, &api) || api.Status != 409 || api.Code != "hostname_taken" {
		t.Fatalf("want hostname_taken409; got %v", err)
	}
}

func TestHostnameReuseMigrationLocalDatabase(t *testing.T) {
	f := newHostnameReuseFixture(t, 178)
	ctx := context.Background()
	dsn := f.pool.Config().ConnString()
	safe := f.create("retired.apps.example.net")
	f.archive(safe)
	disabled := f.create("disabled.apps.example.net")
	f.disable(disabled)
	ambiguous := f.create("ambiguous.apps.example.net")
	// Historical inconsistent archive is deliberately isolated: no withdrawal exists.
	f.exec("UPDATE app_access_applications SET state='archived' WHERE org_id=$1 AND id=$2", f.org, ambiguous.ID)
	var revisions, publications, audits int64
	if err := f.pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM app_access_revisions),(SELECT count(*) FROM app_access_serving_publications),(SELECT count(*) FROM audit_logs)").Scan(&revisions, &publications, &audits); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateTo(dsn, 179); err != nil {
		t.Fatal(err)
	}
	if !f.claimReleased(safe, safe.Draft.PublicHostname) || f.claimReleased(disabled, disabled.Draft.PublicHostname) || f.claimReleased(ambiguous, ambiguous.Draft.PublicHostname) {
		t.Fatal("backfill freed non-archived or ambiguous reservation")
	}
	var r, p, a int64
	if err := f.pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM app_access_revisions),(SELECT count(*) FROM app_access_serving_publications),(SELECT count(*) FROM audit_logs)").Scan(&r, &p, &a); err != nil || r != revisions || p != publications || a != audits {
		t.Fatal("migration changed history", err)
	}
	// Before reuse, a down/up round-trip preserves all old rows and compatibility.
	if err := db.MigrateTo(dsn, 178); err != nil {
		t.Fatal("safe down", err)
	}
	_, err := f.service.CreateDraft(ctx, f.org, f.user, f.input(safe.Draft.PublicHostname), true)
	requireHostnameTaken(t, err)
	if err := db.MigrateTo(dsn, 179); err != nil {
		t.Fatal("up", err)
	}
	replacement := f.create(safe.Draft.PublicHostname)
	if replacement.ID == safe.ID {
		t.Fatal("old application identity reused")
	}
	f.disable(replacement) // Both disabled publication rows must coexist with history.
	var claims int64
	if err := f.pool.QueryRow(ctx, "SELECT count(*) FROM app_access_hostnames WHERE hostname=$1", safe.Draft.PublicHostname).Scan(&claims); err != nil || claims != 2 {
		t.Fatal("historical claim lost", claims, err)
	}
	if _, err := f.pool.Exec(ctx, "UPDATE app_access_hostnames SET released_at=NULL WHERE org_id=$1 AND app_id=$2", f.org, safe.ID); err == nil {
		t.Fatal("released claim resurrected")
	}
	if _, err := f.pool.Exec(ctx, "UPDATE app_access_applications SET state='draft' WHERE org_id=$1 AND id=$2", f.org, safe.ID); err == nil {
		t.Fatal("archived app resurrected")
	}
	// Old binary's targeted ON CONFLICT fails closed on the new schema; it cannot
	// reclaim another application's authority. Deploy schema+new API together.
	if _, err := f.pool.Exec(ctx, "INSERT INTO app_access_hostnames(hostname,org_id,app_id)VALUES($1,$2,$3) ON CONFLICT(hostname) DO NOTHING", safe.Draft.PublicHostname, f.org, safe.ID); err == nil {
		t.Fatal("legacy claim writer unexpectedly supported")
	}
	// Execute the real downgrade inside a rolled-back transaction so the expected
	// refusal cannot leave this disposable DB's migration marker dirty.
	down, err := db.MigrationsFS.ReadFile("migrations/0179_app_access_hostname_reuse.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, string(down))
	_ = tx.Rollback(ctx)
	if err == nil || !strings.Contains(err.Error(), "historical duplicate hostnames") {
		t.Fatal("unsafe downgrade did not refuse", err)
	}
	if err := f.pool.QueryRow(ctx, "SELECT count(*) FROM app_access_hostnames WHERE hostname=$1", safe.Draft.PublicHostname).Scan(&claims); err != nil || claims != 2 {
		t.Fatal("failed downgrade lost history", err)
	}
}

func TestHostnameReuseArchiveAtomicLocalDatabase(t *testing.T) {
	f := newHostnameReuseFixture(t, 179)
	ctx := context.Background()
	app := f.create("atomic.apps.example.net")
	_, err := f.service.CreateDraft(ctx, f.org, f.user, f.input(app.Draft.PublicHostname), true)
	requireHostnameTaken(t, err)
	if err := f.service.ArchiveApplication(ctx, f.org, f.user, app.ID, app.Version); err == nil {
		t.Fatal("unconfirmed archive accepted")
	}
	if f.claimReleased(app, app.Draft.PublicHostname) {
		t.Fatal("failed archive released host")
	}
	p := f.disable(app)
	_, err = f.service.CreateDraft(ctx, f.org, f.user, f.input(app.Draft.PublicHostname), true)
	requireHostnameTaken(t, err)
	f.exec(`CREATE FUNCTION fail_hostname_archive_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app_access.application_archived' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_hostname_archive_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION fail_hostname_archive_audit()`)
	if err := f.service.ArchiveApplication(ctx, f.org, f.user, app.ID, p.ApplicationVersion); err == nil {
		t.Fatal("archive ignored audit failure")
	}
	if f.claimReleased(app, app.Draft.PublicHostname) {
		t.Fatal("failed audit did not roll back release")
	}
	current, err := f.service.GetApplication(ctx, f.org, app.ID)
	if err != nil || current.State != "draft" || current.Version != p.ApplicationVersion {
		t.Fatal("failed audit changed app", err)
	}
	f.exec("DROP TRIGGER fail_hostname_archive_audit ON audit_logs; DROP FUNCTION fail_hostname_archive_audit()")
	if err := f.service.ArchiveApplication(ctx, f.org, f.user, app.ID, p.ApplicationVersion); err != nil {
		t.Fatal(err)
	}
	if !f.claimReleased(app, app.Draft.PublicHostname) {
		t.Fatal("archive did not release")
	}
	replacement := f.create(app.Draft.PublicHostname)
	var history int64
	if err := f.pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE org_id=$1 AND target_type='app_access' AND target_id=$2 AND action='app_access.application_archived'", f.org, app.ID.String()).Scan(&history); err != nil || history != 1 {
		t.Fatal("old archive audit lost", history, err)
	}
	if replacement.ID == app.ID {
		t.Fatal("new hostname owner kept old identity")
	}
	// The old revision still points to its original, released claim, not the new one.
	old, err := f.service.GetRevision(ctx, f.org, app.ID, app.Draft.Revision)
	if err != nil || old.PublicHostname != replacement.Draft.PublicHostname {
		t.Fatal("old revision history lost", err)
	}
}

func TestHostnameReuseConcurrentClaimsLocalDatabase(t *testing.T) {
	f := newHostnameReuseFixture(t, 179)
	ctx := context.Background()
	app := f.create("concurrent.apps.example.net")
	f.archive(app)
	other, gateway := uuid.New(), uuid.New()
	f.exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Other hostname tenant',$2)", other, other.String())
	f.exec("INSERT INTO nodes(id,org_id,name,enrolled_kind,cert_serial,cert_not_after)VALUES($1,$2,'Other gateway','gateway',$3,now()+interval '1 day')", gateway, other, gateway.String())
	if _, err := f.service.UpdateSettings(ctx, other, f.user, true, 1, true); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			org := f.org
			input := f.input(app.Draft.PublicHostname)
			if n%2 == 1 {
				org = other
				input.GatewayID = gateway
			}
			_, err := f.service.CreateDraft(ctx, org, f.user, input, true)
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			requireHostnameTaken(t, err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent owners=%d", successes)
	}
	var live, total int64
	if err := f.pool.QueryRow(ctx, "SELECT count(*) FILTER(WHERE released_at IS NULL),count(*) FROM app_access_hostnames WHERE hostname=$1", app.Draft.PublicHostname).Scan(&live, &total); err != nil || live != 1 || total != 2 {
		t.Fatal("hostname uniqueness/history", live, total, err)
	}
}

func TestHostnameReuseOldAuthorityLocalDatabaseRedis(t *testing.T) {
	f := newHostnameReuseFixture(t, 179)
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", DB: 0})
	defer rdb.Close()
	parents := session.NewWithClient(rdb, time.Hour, time.Hour)
	apps := NewAppSessionStore(rdb)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealer, err := appcrypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	f.service.WithSessionAuthority(parents, apps, sealer, func(context.Context, uuid.UUID) (bool, error) { return false, nil })
	parent, err := parents.CreateWithAuthority(ctx, f.user, authctx.AuthLocalPassword, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer parents.Delete(ctx, parent.ID)
	_, secret, err := f.service.IssueProxyCredential(ctx, "hostname-authority-fixture")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := f.service.AuthenticateProxy(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(app Application) Route {
		t.Helper()
		// Exact negative/positive authority fixture only in the disposable child DB;
		// does not substitute production readiness or public TLS qualification.
		f.exec("INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,state)VALUES($1,$2,$3,$4,$5,$6,'active')", f.org, app.ID, f.gateway, app.Draft.Revision, app.Draft.Digest, app.Draft.PublicHostname)
		if _, e := f.service.ReportBrowserCapability(ctx, AuthenticatedGateway{OrgID: f.org, GatewayID: f.gateway, CertSerial: f.gateway.String()}, 1); e != nil {
			t.Fatal(e)
		}
		if _, e := f.service.CreateGrant(ctx, f.org, f.user, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: f.user, Enabled: true}, true); e != nil {
			t.Fatal(e)
		}
		route, e := f.service.LookupRoute(ctx, proxy, app.Draft.PublicHostname, true)
		if e != nil {
			t.Fatal(e)
		}
		return route
	}
	var nonces, codes, tokens []string
	var streams []uuid.UUID
	defer func() {
		for _, token := range tokens {
			if rec, _, e := apps.Peek(ctx, token); e == nil {
				_ = apps.RevokeOwn(ctx, f.org, f.user, rec.ID)
			}
			rdb.Del(ctx, "aa:stream-session:"+secretHash(token))
		}
		for _, nonce := range nonces {
			rdb.Del(ctx, pendingKey(secretHash(nonce)))
		}
		for _, code := range codes {
			rdb.Del(ctx, launchKey(code))
		}
		for _, id := range streams {
			rdb.Del(ctx, "aa:stream:"+id.String())
		}
	}()
	pending := func(route Route) string {
		t.Helper()
		nonce, e := randomAppSecret("")
		if e != nil {
			t.Fatal(e)
		}
		nonces = append(nonces, nonce)
		if _, e = f.service.RegisterPendingLaunch(ctx, proxy, route.RouteBinding, secretHash(nonce), "/", true); e != nil {
			t.Fatal(e)
		}
		return nonce
	}
	launch := func(app Application, nonce string) string {
		t.Helper()
		out, e := f.service.LaunchApp(ctx, f.org, app.ID, f.user, parent.ID, secretHash(nonce), "/", true)
		if e != nil {
			t.Fatal(e)
		}
		u, e := url.Parse(out.RedirectURL)
		if e != nil {
			t.Fatal(e)
		}
		code := u.Query().Get("code")
		codes = append(codes, code)
		return code
	}
	redeem := func(code, nonce, host string) string {
		t.Helper()
		out, e := f.service.RedeemApp(ctx, proxy, code, nonce, host, true)
		if e != nil {
			t.Fatal(e)
		}
		tokens = append(tokens, out.AppSessionToken)
		return out.AppSessionToken
	}
	old := f.create("authority.apps.example.net")
	oldRoute := publish(old)
	n := pending(oldRoute)
	oldToken := redeem(launch(old, n), n, oldRoute.Hostname)
	request := RequestInput{Binding: oldRoute.RouteBinding, SessionToken: oldToken, Method: "GET", RelativePath: "/"}
	decision, err := f.service.AuthorizeRequest(ctx, proxy, request, true)
	if err != nil || !decision.Allowed {
		t.Fatal("old owner fixture must initially authorize", err)
	}
	if decision.StreamID != uuid.Nil {
		streams = append(streams, decision.StreamID)
	}
	oldPending := pending(oldRoute)
	oldCodeNonce := pending(oldRoute)
	oldCode := launch(old, oldCodeNonce)
	f.archive(old)
	replacement := f.create(old.Draft.PublicHostname)
	newRoute := publish(replacement)
	if newRoute.AppID != replacement.ID || newRoute.AppID == oldRoute.AppID || newRoute.Generation == oldRoute.Generation {
		t.Fatal("lookup reused retired authority")
	}
	if _, err := f.service.LaunchApp(ctx, f.org, replacement.ID, f.user, parent.ID, secretHash(oldPending), "/", true); err == nil {
		t.Fatal("old pending nonce crossed application identity")
	}
	if _, err := f.service.RedeemApp(ctx, proxy, oldCode, oldCodeNonce, newRoute.Hostname, true); err == nil {
		t.Fatal("old launch code crossed application identity")
	}
	for _, binding := range []RouteBinding{oldRoute.RouteBinding, newRoute.RouteBinding} {
		request.Binding = binding
		decision, err = f.service.AuthorizeRequest(ctx, proxy, request, true)
		if err == nil || decision.Allowed {
			t.Fatal("old app cookie authorized reused hostname", err)
		}
	}
	if _, err := f.service.ChannelAuthorize(ctx, proxy, oldRoute.RouteBinding, f.gateway.String(), true); err == nil {
		t.Fatal("old gateway channel authorized")
	}
	n = pending(newRoute)
	fresh := redeem(launch(replacement, n), n, newRoute.Hostname)
	request.Binding = newRoute.RouteBinding
	request.SessionToken = fresh
	decision, err = f.service.AuthorizeRequest(ctx, proxy, request, true)
	if err != nil || !decision.Allowed {
		t.Fatal("fresh new application session failed", err)
	}
	if decision.StreamID != uuid.Nil {
		streams = append(streams, decision.StreamID)
	}
	// Even a corrupted old active pointer cannot route to an archived/released app.
	f.exec("UPDATE app_access_serving_publications SET state='disabled' WHERE org_id=$1 AND app_id=$2", f.org, replacement.ID)
	f.exec("UPDATE app_access_serving_publications SET state='active',withdrawal_confirmed_at=NULL,withdrawal_confirmed_authority_version=NULL,withdrawal_confirmed_generation=NULL WHERE org_id=$1 AND app_id=$2", f.org, old.ID)
	if _, err := f.service.LookupRoute(ctx, proxy, newRoute.Hostname, true); err == nil {
		t.Fatal("historical active row bypassed current claim/app binding")
	}
	if _, err := sqlc.New(f.pool).GetAppAccessServingApplicationHostname(ctx, sqlc.GetAppAccessServingApplicationHostnameParams{OrgID: f.org, AppID: old.ID}); err == nil {
		t.Fatal("old app hostname reader ignored released claim")
	}
}
