package appaccess

import (
	"context"
	"crypto/rand"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

type mfaPolicyParent struct {
	value session.Session
	until time.Time
}

func (p *mfaPolicyParent) GetNoTouch(_ context.Context, id string) (session.Session, time.Time, error) {
	if id != p.value.ID {
		return session.Session{}, time.Time{}, session.ErrNotFound
	}
	return p.value, p.until, nil
}

func TestApplicationMFALiveAuthorityLocalDatabaseRedis(t *testing.T) {
	pool := grantPool(t)
	if err := db.MigrateTo(pool.Config().ConnString(), 176); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	org, user, gateway := uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Live MFA',$2)", org, org.String())
	exec("INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'MFA member',now())", user, user.String()+"@fixture.test")
	exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')", org, user)
	exec("INSERT INTO nodes(id,org_id,name,enrolled_kind,cert_serial,cert_not_after)VALUES($1,$2,'MFA gateway','gateway',$3,now()+interval '1 day')", gateway, org, gateway.String())
	now := time.Now().UTC()
	parents := &mfaPolicyParent{value: session.Session{ID: uuid.NewString(), UserID: user, AuthMethod: authctx.AuthSSO, AppAuthEpoch: 1, ExpiresAt: now.Add(time.Hour)}, until: now.Add(time.Hour)}
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", DB: 0})
	defer rdb.Close()
	apps := NewAppSessionStore(rdb)
	apps.now = func() time.Time { return now }
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealer, err := appcrypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := false
	s := NewService(pool, Config{AppBaseDomain: "apps.example.net", ConsoleHosts: []string{"console.example.com"}, ConsoleURL: "https://console.example.com", Now: func() time.Time { return now }}).
		WithSessionAuthority(parents, apps, sealer, func(context.Context, uuid.UUID) (bool, error) { return false, nil }).
		WithMFAEnrollmentChecker(func(context.Context, uuid.UUID) (bool, error) { return enrolled, nil })
	if _, err = s.UpdateSettings(ctx, org, user, true, 1, true); err != nil {
		t.Fatal(err)
	}
	app, err := s.CreateDraft(ctx, org, user, DraftInput{Name: "Live MFA", OriginURL: "http://origin", GatewayID: gateway, PublicHostname: "mfa-live-" + org.String()[:8] + ".apps.example.net", IdleTimeoutSeconds: 1800, AbsoluteTimeoutSeconds: 3600}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReportBrowserCapability(ctx, AuthenticatedGateway{OrgID: org, GatewayID: gateway, CertSerial: gateway.String()}, 1); err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,state)VALUES($1,$2,$3,$4,$5,$6,'active')", org, app.ID, gateway, app.DraftRevision, app.Draft.Digest, app.Draft.PublicHostname)
	if _, err = s.CreateGrant(ctx, org, user, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: user, Enabled: true}, true); err != nil {
		t.Fatal(err)
	}
	_, secret, err := s.IssueProxyCredential(ctx, "mfa-live-fixture")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := s.AuthenticateProxy(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	route, err := s.LookupRoute(ctx, proxy, app.Draft.PublicHostname, true)
	if err != nil {
		t.Fatal(err)
	}
	var tokens []string
	var streams []uuid.UUID
	defer func() {
		for _, token := range tokens {
			if r, _, e := apps.Peek(ctx, token); e == nil {
				_ = apps.RevokeOwn(ctx, org, user, r.ID)
			}
			rdb.Del(ctx, "aa:stream-session:"+secretHash(token))
		}
		for _, id := range streams {
			rdb.Del(ctx, "aa:stream:"+id.String())
		}
	}()
	pending := func() string {
		t.Helper()
		nonce, e := randomAppSecret("")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.RegisterPendingLaunch(ctx, proxy, route.RouteBinding, secretHash(nonce), "/protected?q=1", true); e != nil {
			t.Fatal(e)
		}
		return nonce
	}
	launch := func(nonce string) (LaunchResult, error) {
		return s.LaunchApp(ctx, org, app.ID, user, parents.value.ID, secretHash(nonce), "/protected?q=1", true)
	}
	redeem := func(launched LaunchResult, nonce string) string {
		t.Helper()
		u, e := url.Parse(launched.RedirectURL)
		if e != nil {
			t.Fatal(e)
		}
		out, e := s.RedeemApp(ctx, proxy, u.Query().Get("code"), nonce, route.Hostname, true)
		if e != nil {
			t.Fatal(e)
		}
		tokens = append(tokens, out.AppSessionToken)
		return out.AppSessionToken
	}
	nonce := pending()
	launched, err := launch(nonce)
	if err != nil {
		t.Fatal(err)
	}
	token := redeem(launched, nonce)
	record, _, err := apps.Peek(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	request := RequestInput{Binding: route.RouteBinding, SessionToken: token, Method: "GET", RelativePath: "/protected"}
	allow := func() Decision {
		t.Helper()
		out, e := s.AuthorizeRequest(ctx, proxy, request, true)
		if e != nil || !out.Allowed {
			t.Fatal("request denied", e)
		}
		streams = append(streams, out.StreamID)
		return out
	}
	active := allow()
	app, err = s.UpdateMFAPolicy(ctx, org, user, app.ID, true, app.Version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthorizeRequest(ctx, proxy, request, true); err == nil {
		t.Fatal("existing session bypassed newly enabled MFA")
	}
	if _, err = s.RenewLease(ctx, proxy, LeaseInput{StreamID: active.StreamID, Binding: route.RouteBinding}, true); err == nil {
		t.Fatal("existing stream bypassed newly enabled MFA")
	}
	catalog, err := s.MyApps(ctx, org, user, parents.value.ID, "", 20, 0, true)
	if err != nil || len(catalog.Items) != 1 || !catalog.Items[0].RequireMFA || !catalog.Items[0].MFARequired || !catalog.Items[0].MFASetupRequired {
		t.Fatal("protected app hidden or setup state lost", err, catalog)
	}
	nonce = pending()
	_, err = launch(nonce)
	code(t, err, "app_mfa_setup_required")
	if _, _, err = apps.LoadPending(ctx, secretHash(nonce)); err != nil {
		t.Fatal("MFA setup error consumed launch binding", err)
	}
	enrolled = true
	_, err = launch(nonce)
	code(t, err, "app_mfa_required")
	if _, _, err = apps.LoadPending(ctx, secretHash(nonce)); err != nil {
		t.Fatal("MFA challenge consumed launch binding", err)
	}
	enrolled = false
	parents.value.MFAVerifiedAt = now.Add(-897 * time.Second)
	parents.value.MFAAssuranceSource = "sso_mfa"
	catalog, err = s.MyApps(ctx, org, user, parents.value.ID, "", 20, 0, true)
	if err != nil || len(catalog.Items) != 1 || catalog.Items[0].MFARequired || catalog.Items[0].MFASetupRequired {
		t.Fatal("trusted SSO required local enrollment", err)
	}
	launched, err = launch(nonce)
	if err != nil {
		t.Fatal("same bound launch could not retry after fresh SSO", err)
	}
	_ = redeem(launched, nonce)
	bounded := allow()
	deadline := parents.value.MFAVerifiedAt.Add(900 * time.Second)
	if bounded.LeaseUntil == nil || bounded.LeaseUntil.After(deadline) {
		t.Fatal("MFA freshness did not bound request lease")
	}
	renewed, err := s.RenewLease(ctx, proxy, LeaseInput{StreamID: bounded.StreamID, Binding: route.RouteBinding}, true)
	if err != nil || !renewed.Allowed || renewed.LeaseUntil.After(deadline) {
		t.Fatal("MFA freshness did not bound renewed lease", err)
	}
	after, _, err := apps.Peek(ctx, token)
	if err != nil || !after.ExpiresAt.Equal(record.ExpiresAt) || !after.ExpiresAt.After(deadline) {
		t.Fatal("MFA deadline permanently truncated app session", err)
	}
	now = now.Add(4 * time.Second)
	if _, err = s.AuthorizeRequest(ctx, proxy, request, true); err == nil {
		t.Fatal("stale MFA allowed request")
	}
	if _, err = s.RenewLease(ctx, proxy, LeaseInput{StreamID: bounded.StreamID, Binding: route.RouteBinding}, true); err == nil {
		t.Fatal("stale MFA renewed stream")
	}
	parents.value.MFAVerifiedAt = now
	allow() // New proof on the same parent permits the still-current app session.
	parents.value.MFAVerifiedAt = time.Time{}
	parents.value.MFAAssuranceSource = ""
	app, err = s.UpdateMFAPolicy(ctx, org, user, app.ID, false, app.Version)
	if err != nil {
		t.Fatal(err)
	}
	allow()
	nonce = pending()
	launched, err = launch(nonce)
	if err != nil {
		t.Fatal("policy off retained MFA gate", err)
	}
	_ = redeem(launched, nonce)
}
