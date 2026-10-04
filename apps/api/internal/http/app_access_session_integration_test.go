package http

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAppAccessMemberLaunchHTTPIntegration(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") == "1" {
		password := os.Getenv("AA0_DB_PASSWORD")
		if password == "" {
			t.Fatal("owned password required")
		}
		u := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", password), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
		t.Setenv("TUNNEX_TEST_DATABASE_URL", u.String())
	}
	ctx, pool := testpostgres.New(t)
	org, owner, user, gateway := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, query := range []struct {
		sql  string
		args []any
	}{{"INSERT INTO users(id,email,email_verified_at)VALUES($1,$2,now()),($3,$4,now())", []any{owner, owner.String() + "@example.test", user, user.String() + "@example.test"}}, {"INSERT INTO organizations(id,name,slug)VALUES($1,'Member launch',$2)", []any{org, "launch-" + org.String()}}, {"INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner'),($1,$3,'member')", []any{org, owner, user}}, {"INSERT INTO nodes(id,org_id,name,cert_serial,cert_not_after,enrolled_kind)VALUES($1,$2,'fixture gateway','ab123',now()+interval '1 day','gateway')", []any{gateway, org}}} {
		if _, e := pool.Exec(ctx, query.sql, query.args...); e != nil {
			t.Fatal(e)
		}
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	parents := session.NewWithClient(rdb, time.Hour, 8*time.Hour)
	parent, e := parents.CreateWithAuthority(ctx, user, authctx.AuthLocalPassword, 1)
	if e != nil {
		t.Fatal(e)
	}
	legacy, e := parents.Create(ctx, owner, authctx.AuthLocalPassword)
	if e != nil {
		t.Fatal(e)
	}
	master := make([]byte, crypto.KeySize)
	_, _ = rand.Read(master)
	sealer, _ := crypto.NewSealer(master)
	svc := appaccess.NewService(pool, appaccess.Config{AppBaseDomain: "apps.example.net", ConsoleHosts: []string{"console.example.com"}, ConsoleURL: "https://console.example.com"}).WithSessionAuthority(parents, appaccess.NewAppSessionStore(rdb), sealer, func(context.Context, uuid.UUID) (bool, error) { return false, nil })
	producer := appaccess.NewEventProducer(pool)
	defer producer.Close()
	svc.WithEventProducer(producer)
	if _, e = svc.UpdateSettings(ctx, org, owner, true, 1, true); e != nil {
		t.Fatal(e)
	}
	app, e := svc.CreateDraft(ctx, org, owner, appaccess.DraftInput{Name: "Fixture publication", Icon: "app", IconDataURL: appIconHTTPFixture(t), OriginURL: "https://origin.internal", GatewayID: gateway, PublicHostname: "member.apps.example.net", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}, true)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := svc.CreateGrant(ctx, org, owner, appaccess.GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: user, Enabled: true}, true)
	if e != nil {
		t.Fatal(e)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := licence.Claims{Version: 1, Kid: "aa5-test", ID: uuid.NewString(), Domain: "example.test", Tier: "trial", Band: "trial", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mgr := &licence.Manager{}
	installed, e := mgr.Install(map[string]ed25519.PublicKey{claims.Kid: pub}, licence.Prefix+encoded+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(encoded))))
	if e != nil || !installed.OK {
		t.Fatal("ephemeral signed licence rejected")
	}
	router, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AuthFn: SessionAuth(parents, sqlc.New(pool)), Sessions: parents, Licence: mgr, AppAccess: svc, AppBaseURL: "http://localhost", TrustedProxies: []string{"127.0.0.1", "::1"}})
	if e != nil {
		t.Fatal(e)
	}
	browser := httptest.NewServer(router)
	defer browser.Close()
	prefix := "/api/v1/organizations/" + org.String() + "/app-access"
	call := func(method, path, body, cookie string, csrf bool, want int) []byte {
		t.Helper()
		r, _ := http.NewRequest(method, browser.URL+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-Proto", "http")
		if csrf {
			r.Header.Set("X-Tunnex-CSRF", "1")
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "tunnex_session_http", Value: cookie})
		}
		res, e := browser.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			t.Fatalf("%s %s: status%d want%d", method, path, res.StatusCode, want)
		}
		return raw
	}
	raw := call("GET", prefix+"/my-apps", "", parent.ID, false, 200)
	if !strings.Contains(string(raw), `"items":[]`) {
		t.Fatal("native draft advertised as published")
	}
	launchPath := prefix + "/my-apps/" + app.ID.String() + "/launch"
	body := `{"nonce_hash":"` + strings.Repeat("b", 64) + `","relative_target":"/work?view=1"}`
	call("POST", launchPath, body, parent.ID, false, 403)
	call("POST", launchPath, body, parent.ID, true, 403)
	call("POST", launchPath, body, "", true, 401)
	// Explicit injected publication exists ONLY in this disposable child DB; AA6
	// production publication and browser/gateway readiness are not claimed here.
	if _, e = svc.ReportBrowserCapability(ctx, appaccess.AuthenticatedGateway{OrgID: org, GatewayID: gateway, CertSerial: "ab123"}, 1); e != nil {
		t.Fatal(e)
	}
	generation := uuid.New()
	if _, e = pool.Exec(ctx, "INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,generation,state)VALUES($1,$2,$3,1,$4,$5,$6,'active')", org, app.ID, gateway, app.Draft.Digest, app.Draft.PublicHostname, generation); e != nil {
		t.Fatal(e)
	}
	raw = call("GET", prefix+"/my-apps?search=Fixture&limit=1", "", parent.ID, false, 200)
	if !strings.Contains(string(raw), "https://member.apps.example.net/__tunnex_app/start") || !strings.Contains(string(raw), `"icon_data_url":"`+app.Draft.IconDataURL+`"`) {
		t.Fatal("server-derived launch url missing")
	}
	t.Run("saved branding visible without publishing draft authority", func(t *testing.T) {
		version := app.Version
		for _, branding := range []struct{ image, fallback string }{
			{appIconHTTPFixtureSized(t, 8), "globe"},
			{appIconHTTPFixtureSized(t, 24), "terminal"},
			{"", "dashboard"},
		} {
			// This normal administrator cookie + CSRF mutation saves a draft only.
			// Its new origin, host and descriptive text must not reach the member.
			input := api.AppAccessUpdateDraftInput{Name: "Unpublished different name", Description: "Unpublished description", Icon: api.AppAccessUpdateDraftInputIcon(branding.fallback), IconDataUrl: &branding.image, OriginUrl: "https://unpublished-origin.internal", GatewayId: gateway, PublicHostname: "unpublished-member.apps.example.net", IdleTimeoutSeconds: 120, AbsoluteTimeoutSeconds: 600, ExpectedVersion: version}
			body, _ := json.Marshal(input)
			var saved api.AppAccessApplication
			if err := json.Unmarshal(call("PATCH", prefix+"/applications/"+app.ID.String(), string(body), legacy.ID, true, 200), &saved); err != nil || saved.Draft.IconDataUrl == nil || *saved.Draft.IconDataUrl != branding.image {
				t.Fatal("normal admin save did not retain branding", err)
			}
			version = saved.Version
			var catalog api.AppAccessMyApps
			if err := json.Unmarshal(call("GET", prefix+"/my-apps", "", parent.ID, false, 200), &catalog); err != nil || len(catalog.Items) != 1 {
				t.Fatal("member catalog unavailable after branding save", err)
			}
			shown := catalog.Items[0]
			if shown.IconDataUrl == nil || *shown.IconDataUrl != branding.image || shown.Icon != branding.fallback || shown.Name != app.Draft.Name || shown.Description != app.Draft.Description || shown.LaunchUrl != "https://member.apps.example.net/__tunnex_app/start" {
				t.Fatal("member branding stale or unpublished draft authority leaked")
			}
			var publishedRevision int64
			if err := pool.QueryRow(ctx, "SELECT revision FROM app_access_serving_publications WHERE org_id=$1 AND app_id=$2", org, app.ID).Scan(&publishedRevision); err != nil || publishedRevision != app.DraftRevision {
				t.Fatal("saving branding changed the publication", err)
			}
		}
	})
	call("POST", launchPath, body, parent.ID, true, 403)
	call("POST", launchPath, body, legacy.ID, true, 401)
	credential, secret, e := svc.IssueProxyCredential(ctx, "AA5 isolated HTTP")
	if e != nil {
		t.Fatal(e)
	}
	_ = credential
	ca, _, e := agentca.LoadOrCreate(ctx, sqlc.New(pool), sealer)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := ca.ServerTLSCertificate("tunnex-app-authority")
	if e != nil {
		t.Fatal(e)
	}
	authority := httptest.NewUnstartedServer(NewAppProxyAuthorityHandler(svc, func() bool { return true }))
	authority.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf}, NextProtos: []string{"http/1.1"}}
	authority.StartTLS()
	defer authority.Close()
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.Pool(), ServerName: "tunnex-app-authority"}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	privateCall := func(path string, input any, want int) []byte {
		t.Helper()
		raw, _ := json.Marshal(input)
		r, _ := http.NewRequest("POST", authority.URL+"/internal/app-access/"+path, strings.NewReader(string(raw)))
		r.Header.Set("Authorization", "AppProxy "+secret)
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		out, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			t.Fatalf("private %s: status%d want%d", path, res.StatusCode, want)
		}
		return out
	}
	route := appProxyRouteWire{}
	if e = json.Unmarshal(privateCall("route-lookup", appProxyLookupWire{app.Draft.PublicHostname}, 200), &route); e != nil {
		t.Fatal(e)
	}
	nonceRaw := make([]byte, 32)
	_, _ = rand.Read(nonceRaw)
	nonce := base64.RawURLEncoding.EncodeToString(nonceRaw)
	nonceHash := fmtHash(nonce)
	privateCall("pending-launch", appProxyPendingWire{route.Binding, nonceHash, "/work?view=1"}, 200)
	wrong := `{"nonce_hash":"` + nonceHash + `","relative_target":"/wrong"}`
	call("POST", launchPath, wrong, parent.ID, true, 403)
	body = `{"nonce_hash":"` + nonceHash + `","relative_target":"/work?view=1"}`
	var launch appaccess.LaunchResult
	var response struct {
		RedirectURL string `json:"redirect_url"`
	}
	_ = launch
	if e = json.Unmarshal(call("POST", launchPath, body, parent.ID, true, 200), &response); e != nil {
		t.Fatal(e)
	}
	redirect, e := url.Parse(response.RedirectURL)
	if e != nil || redirect.Host != app.Draft.PublicHostname || redirect.Path != "/__tunnex_app/redeem" {
		t.Fatal("unsafe launch redirect")
	}
	call("POST", launchPath, body, parent.ID, true, 403)
	code := redirect.Query().Get("code")
	privateCall("redeem", appProxyRedeemWire{code, strings.Repeat("a", 43), app.Draft.PublicHostname}, 403)
	var redeemed appProxyRedeemResultWire
	if e = json.Unmarshal(privateCall("redeem", appProxyRedeemWire{code, nonce, app.Draft.PublicHostname}, 200), &redeemed); e != nil {
		t.Fatal(e)
	}
	privateCall("redeem", appProxyRedeemWire{code, nonce, app.Draft.PublicHostname}, 403)
	input := appProxyAuthorizeWire{Binding: route.Binding, Token: redeemed.Token, Request: appProxyMetadataWire{Method: "GET", Path: "/work", FetchMode: "navigate", FetchDest: "document", FetchUser: "?1"}}
	var decision appProxyDecisionWire
	if e = json.Unmarshal(privateCall("authorize", input, 200), &decision); e != nil || decision.StreamID == uuid.Nil || decision.ExpiresAt.After(time.Now().Add(4*time.Second)) {
		t.Fatal("invalid persisted stream decision")
	}
	privateCall("leases/renew", appProxyLeaseWire{decision.StreamID, route.Binding}, 200)
	privateCall("stream-terminated", appProxyTerminatedWire{Binding: route.Binding, StreamID: decision.StreamID, Reason: "connection_closed"}, 204)
	privateCall("leases/renew", appProxyLeaseWire{decision.StreamID, route.Binding}, 403)
	if e = json.Unmarshal(privateCall("authorize", input, 200), &decision); e != nil {
		t.Fatal(e)
	}
	input.Request.Method = "POST"
	privateCall("authorize", input, 403)
	input.Request.Method = "GET"
	input.Binding.OrgID = uuid.New()
	privateCall("authorize", input, 403)
	input.Binding = route.Binding
	var own struct {
		Items []struct {
			ID            uuid.UUID `json:"id"`
			CurrentParent bool      `json:"current_parent"`
		} `json:"items"`
	}
	if e = json.Unmarshal(call("GET", prefix+"/my-sessions", "", parent.ID, false, 200), &own); e != nil || len(own.Items) != 1 || !own.Items[0].CurrentParent {
		t.Fatal("own-session projection incorrect")
	}
	adminParent, err := parents.CreateWithAuthority(ctx, owner, authctx.AuthLocalPassword, 1)
	if err != nil {
		t.Fatal(err)
	}
	call("GET", prefix+"/events", "", parent.ID, false, 403)
	call("GET", prefix+"/applications/"+app.ID.String()+"/sessions", "", parent.ID, false, 403)
	adminMetadata := call("GET", prefix+"/applications/"+app.ID.String()+"/sessions", "", adminParent.ID, false, 200)
	if strings.Contains(string(adminMetadata), redeemed.Token) || strings.Contains(string(adminMetadata), parent.ID) {
		t.Fatal("admin session metadata leaked tokens")
	}
	call("GET", prefix+"/applications/"+app.ID.String()+"/publication/impact", "", adminParent.ID, false, 200)
	call("DELETE", prefix+"/applications/"+app.ID.String()+"/sessions/"+own.Items[0].ID.String(), "", adminParent.ID, false, 403)
	call("GET", prefix+"/events?before_id="+uuid.New().String(), "", adminParent.ID, false, 400)
	call("GET", prefix+"/events", "", adminParent.ID, false, 200)
	if _, e = svc.RevokeGrant(ctx, org, owner, grant.ID, 1); e != nil {
		t.Fatal(e)
	}
	privateCall("leases/renew", appProxyLeaseWire{decision.StreamID, route.Binding}, 403)
	if _, e = pool.Exec(ctx, "UPDATE memberships SET role='ai-view' WHERE org_id=$1 AND user_id=$2", org, user); e != nil {
		t.Fatal(e)
	}
	call("GET", prefix+"/my-apps", "", parent.ID, false, 403)
	call("GET", prefix+"/my-sessions", "", parent.ID, false, 200)
	call("DELETE", prefix+"/my-sessions/"+own.Items[0].ID.String(), "", parent.ID, false, 403)
	call("DELETE", prefix+"/my-sessions/"+own.Items[0].ID.String(), "", parent.ID, true, 204)
	input.Token = redeemed.Token
	raw = privateCall("authorize", input, 403)
	if !strings.Contains(string(raw), "app_session_invalid") {
		t.Fatal("removed session restart sentinel missing")
	}
	t.Run("AA6 generated public and TLS private publication ports", func(t *testing.T) {
		ownerParent, err := parents.CreateWithAuthority(ctx, owner, authctx.AuthLocalPassword, 1)
		if err != nil {
			t.Fatal(err)
		}
		next, err := svc.CreateDraft(ctx, org, owner, appaccess.DraftInput{Name: "HTTP reviewed publication", Icon: "app", OriginURL: "http://origin.internal", GatewayID: gateway, PublicHostname: "http-publication.apps.example.net", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}, true)
		if err != nil {
			t.Fatal(err)
		}
		g := appaccess.AuthenticatedGateway{OrgID: org, GatewayID: gateway, CertSerial: "ab123"}
		if _, err = svc.ReportCapability(ctx, g, 1); err != nil {
			t.Fatal(err)
		}
		c, err := svc.RequestCheck(ctx, org, owner, next.ID, next.Version, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = svc.DesiredForGateway(ctx, g, true); err != nil {
			t.Fatal(err)
		}
		if _, err = svc.CompleteCheck(ctx, g, appaccess.Result{RequestID: c.ID, AppID: next.ID, Generation: c.Generation, Revision: c.Revision, Digest: c.Digest, Purpose: "origin_check", DNSStatus: "passed", ConnectStatus: "passed", TLSStatus: "skipped"}, true); err != nil {
			t.Fatal(err)
		}
		stage := api.AppAccessPublicationInput{ExpectedVersion: next.Version, Revision: next.DraftRevision, Digest: next.Draft.Digest, CheckId: c.ID, IdempotencyKey: uuid.New()}
		body, _ := json.Marshal(stage)
		path := prefix + "/applications/" + next.ID.String()
		call("POST", path+"/publication-operations", string(body), ownerParent.ID, false, 403)
		call("POST", path+"/publication-operations", string(body), parent.ID, true, 403)
		var op api.AppAccessPublicationOperation
		if err = json.Unmarshal(call("POST", path+"/publication-operations", string(body), ownerParent.ID, true, 201), &op); err != nil {
			t.Fatal(err)
		}
		if op.ExpectedApplicationVersion != next.Version+1 {
			t.Fatal("poststage version missing")
		}
		call("POST", path+"/publication-operations", string(body), ownerParent.ID, true, 201)
		call("GET", path+"/publication-operations/by-key/"+stage.IdempotencyKey.String(), "", ownerParent.ID, false, 200)
		instanceRaw := make([]byte, 32)
		_, _ = rand.Read(instanceRaw)
		instance := base64.RawURLEncoding.EncodeToString(instanceRaw)
		var work appProxyReadinessClaimResultWire
		if err = json.Unmarshal(privateCall("publication-readiness/claim", appProxyReadinessClaimWire{InstanceToken: instance}, 200), &work); err != nil || len(work.Items) != 1 {
			t.Fatal("readiness claim", err)
		}
		item := work.Items[0]
		var channelLease appProxyExpiryWire
		if err = json.Unmarshal(privateCall("channel-authorize", appProxyChannelWire{Binding: item.Route.Binding, Serial: "ab123"}, 200), &channelLease); err != nil || !channelLease.ExpiresAt.After(time.Now()) || channelLease.ExpiresAt.After(time.Now().Add(4*time.Second)) {
			t.Fatal("pending channel authority lease", err)
		}
		privateCall("channel-authorize", appProxyChannelWire{Binding: item.Route.Binding, Serial: "ab124"}, 403)
		privateCall("route-lookup", appProxyLookupWire{next.Draft.PublicHostname}, 404)
		report := appProxyReadinessReportWire{OperationID: op.Id, ExpectedOperationVersion: item.Version, Binding: item.Route.Binding, ReadinessRequestID: item.ReadinessRequestID, InstanceToken: instance, ChallengeToken: item.ChallengeToken, CertificateSerial: "ab123", PublicDNSStatus: "passed", PublicTLSStatus: "passed", DNSStatus: "passed", ConnectStatus: "passed", TLSStatus: "skipped"}
		forged := report
		forged.CertificateSerial = "ab124"
		privateCall("publication-readiness/report", forged, 403)
		result := appProxyReadinessReportResultWire{}
		if err = json.Unmarshal(privateCall("publication-readiness/report", report, 200), &result); err != nil || result.Status != "activated" {
			t.Fatal("publication activation", err)
		}
		privateCall("publication-readiness/report", report, 200)
		privateCall("route-lookup", appProxyLookupWire{next.Draft.PublicHostname}, 200)
		privateCall("channel-authorize", appProxyChannelWire{Binding: item.Route.Binding, Serial: "ab123"}, 200)
		var state api.AppAccessPublicationState
		if err = json.Unmarshal(call("GET", path+"/publication", "", ownerParent.ID, false, 200), &state); err != nil || state.Active == nil || state.ActiveLabel == nil || *state.ActiveLabel != next.Draft.Name || len(state.RollbackRevisions) != 1 {
			t.Fatal("immutable published readback", err)
		}
		call("DELETE", path+"?expected_version=2", "", ownerParent.ID, true, 409)
	})

}

func fmtHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
