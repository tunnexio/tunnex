package sso

import (
	"context"
	"crypto/rand"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/publicurl"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSSOSafeInternalReturn(t *testing.T) {
	for _, raw := range []string{"https://evil.test/", "//evil.test/", "/%2fevil.test/", "/\\evil", "/%5cevil", "/x#fragment", "/x\n", "/%0aevil", strings.Repeat("a", 32769)} {
		if _, e := SafeInternalReturn(raw); e == nil {
			t.Fatalf("unsafe return accepted %q", raw)
		}
	}
	raw := "/app-access/launch?target=" + url.QueryEscape("/"+strings.Repeat("&", 8190))
	if got, e := SafeInternalReturn(raw); e != nil || got != raw {
		t.Fatal("escaped maximum app target refused")
	}
}

// Owned disposable DB, signed fake IdP, real OIDC discovery/token verification,
// and Redis state. No external IdP or native publication is used.
func TestSSOAppReturnOwnedIntegration(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") != "1" {
		t.Skip("owned stack integration only")
	}
	password := os.Getenv("AA0_DB_PASSWORD")
	if password == "" {
		t.Fatal("owned database password required")
	}
	u := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", password), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
	t.Setenv("TUNNEX_TEST_DATABASE_URL", u.String())
	ctx, pool := testpostgres.New(t)
	q := sqlc.New(pool)
	org, actor := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO organizations(id,name,slug)VALUES($1,'SSO fixture',$2)", org, "sso-return-"+org.String()); e != nil {
		t.Fatal(e)
	}
	if _, e := pool.Exec(ctx, "INSERT INTO users(id,email,email_verified_at,app_auth_epoch)VALUES($1,$2,now(),7)", actor, actor.String()+"@example.test"); e != nil {
		t.Fatal(e)
	}
	key := make([]byte, crypto.KeySize)
	_, _ = rand.Read(key)
	sealer, _ := crypto.NewSealer(key)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	idp := newFakeIdP(t, "test-client")
	svc := NewService(pool, NewConfigService(pool, sealer), NewFlowStore(rdb, 10*time.Minute), idp.factory(), "https://console.example.test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e := svc.configs.Set(ctx, actor, org, "google", "test-client", "test-secret", "", true); e != nil {
		t.Fatal(e)
	}
	next := "/app-access/launch?orgId=" + org.String() + "&target=%2Fwork%3Fa%3Db"
	const configuredPortal = "https://configured.example.test"
	startContext := publicurl.With(ctx, configuredPortal)
	callbackContext := publicurl.With(ctx, "https://changed.example.test")
	factory := svc.factory
	svc.factory = func(ctx context.Context, cfg Config, callback string) (Provider, error) {
		if callback != configuredPortal+"/api/v1/auth/sso/google/callback" {
			t.Fatalf("OIDC callback changed during the flow: %s", callback)
		}
		return factory(ctx, cfg, callback)
	}
	start := func() (string, string) {
		redirect, e := svc.StartLoginWithReturn(startContext, org, "google", next)
		if e != nil {
			t.Fatal(e)
		}
		u, _ := url.Parse(redirect)
		return u.Query().Get("state"), u.Query().Get("nonce")
	}
	verifiedMFATime := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	state, nonce := start()
	idp.mint(idp.key, map[string]any{"sub": "return-actor", "email": actor.String() + "@example.test", "email_verified": true, "nonce": nonce, "amr": []string{"pwd", "mfa"}, "auth_time": verifiedMFATime.Unix()})
	result, e := svc.HandleCallbackWithAuthority(callbackContext, "google", "code", state)
	if e != nil || result.UserID != actor || result.AppAuthEpoch != 7 || result.Next != next || result.PortalURL != configuredPortal || !result.MFAVerifiedAt.Equal(verifiedMFATime) {
		t.Fatalf("callback lost verified authority/return: %+v %v", result, e)
	}
	if _, e = svc.HandleCallbackWithAuthority(ctx, "google", "code", state); e == nil {
		t.Fatal("state replay accepted")
	}
	if _, e = pool.Exec(ctx, "UPDATE users SET app_auth_epoch=8 WHERE id=$1", actor); e != nil {
		t.Fatal(e)
	}
	parents := session.NewWithClient(rdb, time.Hour, 8*time.Hour)
	captured, e := parents.CreateWithAuthority(ctx, actor, "sso", result.AppAuthEpoch)
	if e != nil || captured.AppAuthEpoch != 7 {
		t.Fatal("SSO snapshot silently promoted to newer epoch")
	}
	current, e := q.GetUserByID(ctx, actor)
	if e != nil || current.AppAuthEpoch == captured.AppAuthEpoch {
		t.Fatal("reset race fixture ineffective")
	}
	state, _ = start()
	idp.mint(idp.key, map[string]any{"sub": "bad", "email": "bad@example.test", "email_verified": true, "nonce": "wrong"})
	result, e = svc.HandleCallbackWithAuthority(ctx, "google", "code", state)
	if e == nil || result.Next != next || result.PortalURL != configuredPortal {
		t.Fatal("verified server return lost on callback failure")
	}
	state, _ = start()
	mr.FastForward(10 * time.Minute)
	if _, e = svc.HandleCallbackWithAuthority(ctx, "google", "code", state); e == nil {
		t.Fatal("expired state accepted")
	}
	connection := uuid.New()
	secret := "fixture-secret"
	c, e := svc.SaveConnection(ctx, actor, org, connection, ConnectionInput{Name: "Fixture", Provider: "oidc", Issuer: "https://idp.example.test", ClientID: "test-client", Secret: &secret})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.VerifySSOConnection(ctx, sqlc.VerifySSOConnectionParams{ID: connection, Revision: c.Revision}); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.ActivateConnection(ctx, actor, org, connection, c.Revision, true); e != nil {
		t.Fatal(e)
	}
	if e = q.LinkSSOConnectionIdentity(ctx, sqlc.LinkSSOConnectionIdentityParams{ConnectionID: connection, IssuerUrl: c.IssuerUrl, Subject: "connection-actor", UserID: actor}); e != nil {
		t.Fatal(e)
	}
	svc.connectionFactory = func(ctx context.Context, c sqlc.SsoConnection) (Provider, error) {
		callback := svc.ConnectionCallbackURL(ctx)
		if callback != configuredPortal+"/api/v1/auth/sso-connections/callback" {
			t.Fatalf("connection callback changed during the flow: %s", callback)
		}
		return idp.factory()(ctx, Config{Provider: "google", ClientID: "test-client", ClientSecret: secret}, callback)
	}
	binding := strings.Repeat("b", 43)
	redirect, e := svc.StartConnectionWithReturn(startContext, uuid.Nil, connection, uuid.Nil, false, false, binding, next)
	if e != nil {
		t.Fatal(e)
	}
	cu, _ := url.Parse(redirect)
	state = cu.Query().Get("state")
	nonce = cu.Query().Get("nonce")
	idp.mint(idp.key, map[string]any{"sub": "connection-actor", "email": actor.String() + "@example.test", "email_verified": true, "nonce": nonce, "amr": []string{"pwd", "mfa"}, "auth_time": verifiedMFATime.Unix()})
	if _, e = svc.CompleteConnection(ctx, "code", state, strings.Repeat("c", 43), uuid.Nil); e == nil {
		t.Fatal("other browser consumed connection state")
	}
	cr, e := svc.CompleteConnection(callbackContext, "code", state, binding, uuid.Nil)
	if e != nil || cr.UserID != actor || cr.AppAuthEpoch != 8 || cr.Next != next || cr.PortalURL != configuredPortal || !cr.MFAVerifiedAt.Equal(verifiedMFATime) {
		t.Fatalf("connection callback authority %+v %v", cr, e)
	}
	if _, e = svc.CompleteConnection(ctx, "code", state, binding, uuid.Nil); e == nil {
		t.Fatal("connection replay accepted")
	}
}
