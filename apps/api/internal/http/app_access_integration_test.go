package http

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Real migrated disposable PostgreSQL + Redis session/membership auth + generated
// router. The signing key is ephemeral and is passed only to this test Manager;
// production TrustedKeys and the running Community API are never changed.
func TestAppAccessBrowserRegistryIntegration(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") == "1" {
		password := os.Getenv("AA0_DB_PASSWORD")
		if password == "" {
			t.Fatal("owned stack password required")
		}
		u := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", password), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
		t.Setenv("TUNNEX_TEST_DATABASE_URL", u.String())
	}
	ctx, pool := testpostgres.New(t)
	org, other, owner, member, gateway := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now()),($3,$4,now())", []any{owner, "aa-owner-" + owner.String() + "@example.test", member, "aa-member-" + member.String() + "@example.test"}},
		{"INSERT INTO organizations(id,name,slug) VALUES($1,'AA HTTP',$2),($3,'Other',$4)", []any{org, "aa-" + org.String(), other, "aa-" + other.String()}},
		{"INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'member'),($4,$2,'owner')", []any{org, owner, member, other}},
		{"INSERT INTO nodes(id,org_id,name,cert_serial,enrolled_kind) VALUES($1,$2,'aa-http-gateway',$3,'gateway')", []any{gateway, org, gateway.String()}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	sessions := session.NewWithClient(rdb, time.Hour, 24*time.Hour)
	login, err := sessions.Create(ctx, owner, authctx.AuthLocalPassword)
	if err != nil {
		t.Fatal(err)
	}
	memberLogin, err := sessions.Create(ctx, member, authctx.AuthLocalPassword)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := licence.Claims{Version: 1, Kid: "aa-ephemeral", ID: uuid.NewString(), Domain: "example.test", Tier: "trial", Band: "trial", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	wire := licence.Prefix + encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(encoded)))
	mgr := &licence.Manager{}
	result, err := mgr.Install(map[string]ed25519.PublicKey{claims.Kid: public}, wire)
	if err != nil || !result.OK {
		t.Fatalf("ephemeral signature verification %v %v", result, err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewRouter(logger, Deps{AuthFn: SessionAuth(sessions, sqlc.New(pool)), Sessions: sessions, Licence: mgr, AppAccess: appaccess.NewService(pool, appaccess.Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}}), AppBaseURL: "http://localhost", TrustedProxies: []string{"127.0.0.1", "::1"}, MachineFn: func(r *http.Request) (*authctx.Principal, error) {
		if r.Header.Get("Authorization") == "Bearer fixture-machine" {
			return authctx.NewMachinePrincipal(owner, uuid.New(), org, "aa-test", rbac.RoleOperator, ""), nil
		}
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	prefix := "/api/v1/organizations/" + org.String() + "/app-access"
	call := func(method, path, body, cookie, token string, csrf bool, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if want == 413 {
			req.ContentLength = -1
		} // Exercise streaming limit, not Content-Length preflight.
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-Proto", "http")
		if csrf {
			req.Header.Set("X-Tunnex-CSRF", "1")
		}
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "tunnex_session_http", Value: cookie})
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s got %d want %d: %s", method, path, res.StatusCode, want, raw)
		}
		if want < 300 && res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("privileged response cacheable")
		}
		return raw
	}
	settings := prefix + "/settings"
	call("GET", settings, "", "", "", false, 401)
	call("GET", settings, "", memberLogin.ID, "", false, 403)
	call("GET", settings, "", "", "fixture-machine", false, 403)
	call("PATCH", settings, `{"enabled":true,"expected_version":1}`, login.ID, "", false, 403)
	call("PATCH", settings, `{"enabled":true,"expected_version":1,"unexpected":true}`, login.ID, "", true, 400)
	call("PATCH", settings, `{`, login.ID, "", true, 400)
	call("PATCH", settings, `{"enabled":true,"expected_version":1,"padding":"`+strings.Repeat("x", 129*1024)+`"}`, login.ID, "", true, 413)
	call("PATCH", settings, `{"enabled":true,"expected_version":1}`, login.ID, "", true, 200)
	call("PATCH", settings, `{"enabled":true,"expected_version":1}`, login.ID, "", true, 409)
	icon := appIconHTTPFixture(t)
	input := api.AppAccessDraftInput{Name: "Private orders", Description: "fixture", Icon: "app", IconDataUrl: &icon, OriginUrl: "https://orders.internal", GatewayId: gateway, PublicHostname: "orders.apps.fixture.test", IdleTimeoutSeconds: 1800, AbsoluteTimeoutSeconds: 28800}
	body, _ := json.Marshal(input)
	raw := call("POST", prefix+"/applications", string(body), login.ID, "", true, 201)
	var app api.AppAccessApplication
	if err = json.Unmarshal(raw, &app); err != nil {
		t.Fatal(err)
	}
	if app.State != "draft" || (app.ConnectorStatus != "unknown" && app.ConnectorStatus != "unavailable") || app.Version != 1 || len(app.Draft.Digest) != 64 || app.Draft.IconDataUrl == nil || *app.Draft.IconDataUrl != icon {
		t.Fatalf("dishonest draft %#v", app)
	}
	detail := prefix + "/applications/" + app.Id.String()
	call("GET", detail, "", login.ID, "", false, 200)
	call("GET", "/api/v1/organizations/"+other.String()+"/app-access/applications/"+app.Id.String(), "", login.ID, "", false, 404)
	call("GET", prefix+"/applications?limit=1&offset=0", "", login.ID, "", false, 200)
	update := api.AppAccessUpdateDraftInput{Name: "Updated orders", Description: input.Description, Icon: "app", OriginUrl: input.OriginUrl, GatewayId: gateway, PublicHostname: input.PublicHostname, IdleTimeoutSeconds: 1800, AbsoluteTimeoutSeconds: 28800, ExpectedVersion: 1}
	body, _ = json.Marshal(update)
	raw = call("PATCH", detail, string(body), login.ID, "", true, 200)
	if err = json.Unmarshal(raw, &app); err != nil || app.Version != 2 || app.Draft.IconDataUrl == nil || *app.Draft.IconDataUrl != icon {
		t.Fatalf("draft update %v %#v", err, app)
	}
	raw = call("GET", detail+"/revisions/1", "", login.ID, "", false, 200)
	var revision api.AppAccessRevision
	if err = json.Unmarshal(raw, &revision); err != nil || revision.Name != input.Name || revision.IconDataUrl == nil || *revision.IconDataUrl != icon {
		t.Fatal("old revision changed", err)
	}
	call("PATCH", detail, string(body), login.ID, "", true, 409)
	invalidIcon := "data:image/svg+xml;base64,PHN2Zy8+"
	invalidUpload := update
	invalidUpload.ExpectedVersion = app.Version
	invalidUpload.IconDataUrl = &invalidIcon
	invalidBody, _ := json.Marshal(invalidUpload)
	call("PATCH", detail, string(invalidBody), login.ID, "", true, 400)
	exerciseAppAccessAgentHTTP(t, ctx, pool, mgr, org, gateway, app.Id, login.ID, prefix, detail, call)
	// Explicit user and real group grants share one registry. Even a real group
	// named Everyone has no implicit authority: only its explicit members match.
	group := uuid.New()
	if _, err = pool.Exec(ctx, "INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Everyone')", group, org); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)", org, group, member); err != nil {
		t.Fatal(err)
	}
	grants := prefix + "/grants"
	userInput := fmt.Sprintf(`{"app_id":%q,"subject_kind":"user","subject_id":%q,"enabled":true,"starts_at":null,"expires_at":null}`, app.Id, member)
	call("POST", grants, userInput, memberLogin.ID, "", true, 403)
	call("POST", grants, userInput, "", "fixture-machine", true, 403)
	call("POST", grants, userInput, login.ID, "", false, 403)
	var userGrant, groupGrant api.AppAccessGrant
	if err = json.Unmarshal(call("POST", grants, userInput, login.ID, "", true, 201), &userGrant); err != nil {
		t.Fatal(err)
	}
	groupInput := fmt.Sprintf(`{"app_id":%q,"subject_kind":"group","subject_id":%q,"enabled":true,"starts_at":null,"expires_at":null}`, app.Id, group)
	if err = json.Unmarshal(call("POST", grants, groupInput, login.ID, "", true, 201), &groupGrant); err != nil {
		t.Fatal(err)
	}
	var grantList api.AppAccessGrantList
	if err = json.Unmarshal(call("GET", grants+"?app_id="+app.Id.String(), "", login.ID, "", false, 200), &grantList); err != nil || len(grantList.Items) != 2 {
		t.Fatalf("shared grant list %v %#v", err, grantList)
	}
	previewPath := detail + "/effective-access"
	previewBody := fmt.Sprintf(`{"user_id":%q}`, member)
	preview := func(wantMatch bool) {
		t.Helper()
		var out api.AppAccessEffectiveAccess
		if err := json.Unmarshal(call("POST", previewPath, previewBody, login.ID, "", true, 200), &out); err != nil {
			t.Fatal(err)
		}
		if out.GrantMatch != wantMatch || bool(out.AccessAllowed) {
			t.Fatalf("grant/delivery boundary %#v", out)
		}
		if wantMatch && out.DenyReason != "app_unpublished" {
			t.Fatalf("draft delivery reason %#v", out)
		}
	}
	preview(true)
	call("POST", previewPath, fmt.Sprintf(`{"user_id":%q,"published":true}`, member), login.ID, "", true, 400)
	var impact api.AppAccessGrantImpact
	if err = json.Unmarshal(call("GET", grants+"/"+userGrant.Id.String()+"/revoke-impact", "", login.ID, "", false, 200), &impact); err != nil || impact.MatchingUserCount != 1 || impact.UsersLosingGrantMatchCount != 0 || bool(impact.SessionImpactAvailable) {
		t.Fatalf("overlap impact %v %#v", err, impact)
	}
	userPath := grants + "/" + userGrant.Id.String()
	call("PATCH", userPath, `{"enabled":true,"starts_at":null,"expires_at":null,"expected_version":99}`, login.ID, "", true, 409)
	call("PATCH", userPath, `{"enabled":true,"starts_at":"2030-01-02T00:00:00Z","expires_at":"2030-01-01T00:00:00Z","expected_version":1}`, login.ID, "", true, 400)
	call("POST", userPath+"/revoke", `{"expected_version":1}`, login.ID, "", true, 200)
	call("POST", userPath+"/revoke", `{"expected_version":99}`, login.ID, "", true, 200) // Repeat remove is idempotent.
	preview(true)
	if err = json.Unmarshal(call("GET", grants+"/"+groupGrant.Id.String()+"/revoke-impact", "", login.ID, "", false, 200), &impact); err != nil || impact.UsersLosingGrantMatchCount != 1 {
		t.Fatalf("final grant impact %v %#v", err, impact)
	}
	t.Run("uploaded icon HTTP lifecycle", func(t *testing.T) {
		read := func() api.AppAccessApplication {
			t.Helper()
			var current api.AppAccessApplication
			if err := json.Unmarshal(call("GET", detail, "", login.ID, "", false, 200), &current); err != nil {
				t.Fatal(err)
			}
			return current
		}
		current := read()
		if current.Draft.IconDataUrl == nil || *current.Draft.IconDataUrl != icon {
			t.Fatal("existing image missing before PATCH lifecycle")
		}
		request := api.AppAccessUpdateDraftInput{Name: current.Draft.Name, Description: current.Draft.Description, Icon: api.AppAccessUpdateDraftInputIcon(current.Draft.Icon), OriginUrl: current.Draft.OriginUrl, GatewayId: current.Draft.GatewayId, PublicHostname: current.Draft.PublicHostname, IdleTimeoutSeconds: current.Draft.IdleTimeoutSeconds, AbsoluteTimeoutSeconds: current.Draft.AbsoluteTimeoutSeconds, ExpectedVersion: current.Version}
		assertUnchanged := func() {
			t.Helper()
			after := read()
			if after.Version != current.Version || after.Draft.Digest != current.Draft.Digest || after.Draft.IconDataUrl == nil || *after.Draft.IconDataUrl != *current.Draft.IconDataUrl {
				t.Fatal("rejected image PATCH changed the stored revision")
			}
		}
		for _, invalid := range []string{"data:image/svg+xml;base64,PHN2Zy8+", strings.Replace(icon, "image/png", "image/jpeg", 1)} {
			request.IconDataUrl = &invalid
			body, _ := json.Marshal(request)
			call("PATCH", detail, string(body), login.ID, "", true, 400)
			assertUnchanged()
		}
		var imageBytes bytes.Buffer
		if err := png.Encode(&imageBytes, image.NewGray(image.Rect(0, 0, 8, 8))); err != nil {
			t.Fatal(err)
		}
		replacement := "data:image/png;base64," + base64.StdEncoding.EncodeToString(imageBytes.Bytes())
		request.IconDataUrl = &replacement
		body, _ := json.Marshal(request)
		call("PATCH", detail, string(body), memberLogin.ID, "", true, 403)
		call("PATCH", detail, string(body), login.ID, "", false, 403)
		assertUnchanged()
		call("PATCH", detail, string(body), login.ID, "", true, 200)
		replaced := read()
		if replaced.Version != current.Version+1 || replaced.Draft.IconDataUrl == nil || *replaced.Draft.IconDataUrl != replacement || replaced.Draft.Digest == current.Draft.Digest {
			t.Fatal("valid replacement PATCH was not persisted")
		}
		request.ExpectedVersion, request.IconDataUrl = replaced.Version, nil
		body, _ = json.Marshal(request)
		call("PATCH", detail, string(body), login.ID, "", true, 200)
		preserved := read()
		if preserved.Draft.IconDataUrl == nil || *preserved.Draft.IconDataUrl != replacement {
			t.Fatal("omitted icon PATCH erased the saved upload")
		}
		empty := ""
		request.ExpectedVersion, request.IconDataUrl = preserved.Version, &empty
		body, _ = json.Marshal(request)
		call("PATCH", detail, string(body), login.ID, "", true, 200)
		removed := read()
		if removed.Draft.IconDataUrl == nil || *removed.Draft.IconDataUrl != "" || removed.Draft.Icon != current.Draft.Icon {
			t.Fatal("explicit removal did not restore the selected default icon")
		}
		var history api.AppAccessRevision
		if err := json.Unmarshal(call("GET", detail+"/revisions/1", "", login.ID, "", false, 200), &history); err != nil || history.IconDataUrl == nil || *history.IconDataUrl != icon {
			t.Fatal("replace/remove changed immutable historical image", err)
		}
	})
	// Opt-out blocks additions; reads, disabling and removal remain available.
	call("PATCH", settings, `{"enabled":false,"expected_version":2}`, login.ID, "", true, 200)
	call("POST", grants, userInput, login.ID, "", true, 403)
	// A freshly signed test licence beyond the real grace window exercises loss
	// through Manager.Has, without swapping a fake licence port or trusted keys.
	claims.IssuedAt = time.Now().Add(-102 * 24 * time.Hour).Unix()
	claims.ExpiresAt = time.Now().Add(-101 * 24 * time.Hour).Unix()
	payload, err = json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded = base64.RawURLEncoding.EncodeToString(payload)
	wire = licence.Prefix + encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(encoded)))
	result, err = mgr.Install(map[string]ed25519.PublicKey{claims.Kid: public}, wire)
	if err != nil || !result.OK || mgr.Has(licence.FeatAppAccess, time.Now()) {
		t.Fatalf("expired signed licence fixture %v %v", result, err)
	}
	call("POST", grants, userInput, login.ID, "", true, 403)
	call("GET", grants, "", login.ID, "", false, 200)
	call("PATCH", grants+"/"+groupGrant.Id.String(), `{"enabled":false,"starts_at":null,"expires_at":null,"expected_version":1}`, login.ID, "", true, 200)
	call("POST", grants+"/"+groupGrant.Id.String()+"/revoke", `{"expected_version":2}`, login.ID, "", true, 200)
	preview(false)
	// Live membership and user changes invalidate the already-issued cookie.
	if _, err = pool.Exec(ctx, "DELETE FROM memberships WHERE org_id=$1 AND user_id=$2", org, owner); err != nil {
		t.Fatal(err)
	}
	call("GET", settings, "", login.ID, "", false, 404)
	if _, err = pool.Exec(ctx, "UPDATE users SET status='deactivated' WHERE id=$1", member); err != nil {
		t.Fatal(err)
	}
	call("GET", settings, "", memberLogin.ID, "", false, 401)
	t.Log(fmt.Sprintf("Real session/membership auth and signed test entitlement exercised; org=%s, child database owned by testpostgres", org))
}
