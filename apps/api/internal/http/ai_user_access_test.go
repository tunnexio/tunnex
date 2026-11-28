package http

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

type userAccessEngine struct{}

func (userAccessEngine) EnsureKey(context.Context, string, string, []string, []string) (aigateway.EngineKey, error) {
	return aigateway.EngineKey{ID: "fixture-group-key", Value: "sk-bf-private-group-key"}, nil
}
func (userAccessEngine) DisableKey(context.Context, string) error { return nil }
func (userAccessEngine) Price(context.Context, string, string) (aigateway.Price, error) {
	return aigateway.Price{}, nil
}
func (userAccessEngine) Usage(context.Context, []string, time.Time, time.Time) (aigateway.Usage, error) {
	return aigateway.Usage{}, nil
}

func TestAIUserModelSocketAccess(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, group, connection := uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,ai_gateway_enabled) VALUES($1,'Engineering',$2,true)`, org, "eng-"+org.String())
	exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Engineering')`, group, org)
	users := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	for i, u := range users {
		exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, u, u.String()+"@test.local")
		exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, u)
		if i < 4 {
			exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, org, group, u)
		}
	}
	exec(`INSERT INTO ai_provider_connections(id,org_id,key_id,provider,name,models,enabled,revision,applied_revision,status) VALUES($1,$2,$3,'openrouter','Fixture',ARRAY['openrouter/engineering'],true,1,1,'applied')`, connection, org, "tnx-managed-"+connection.String())
	sealer, _ := crypto.NewSealer(bytes.Repeat([]byte{7}, 32))
	policies := aigateway.NewPolicies(pool, sealer, userAccessEngine{})
	if _, err := policies.PutUserModelGrant(ctx, org, users[0], group, connection, "openrouter/engineering", true, 0); err != nil {
		t.Fatal(err)
	}
	var arrivals atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Bf-Vk") != "sk-bf-private-group-key" {
			t.Error("login credential leaked or scoped key missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"Hello Engineering"}}]}`)
	}))
	defer upstream.Close()
	adapter, err := aigateway.NewAdapter(upstream.URL, func(context.Context, string, string) (aigateway.Grant, error) {
		return aigateway.Grant{}, errors.New("agent endpoint must not authorize human")
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := func(r *http.Request) *authctx.Principal {
		raw := r.Header.Get("X-Fixture-User")
		u, err := uuid.Parse(raw)
		if err != nil {
			return nil
		}
		return &authctx.Principal{UserID: u, EmailVerified: true, SessionID: "fixture-session", Roles: map[uuid.UUID]string{org: "member"}, AuthMethod: authctx.AuthLocalPassword}
	}
	srv := aiSocketServer(t, Deps{AIAdapter: adapter, AIPolicies: policies, AuthFn: principal, Mfa: mfa.NewService(pool, sealer, nil, nil), MfaEnforceEnabled: true})
	path := "/api/v1/organizations/" + org.String() + "/ai-gateway/inference/v1/chat/completions"
	call := func(u uuid.UUID, csrf bool) int {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(`{"model":"openrouter/engineering","messages":[{"role":"user","content":"hello"}]}`))
		req.Header.Set("Content-Type", "application/json")
		if u != uuid.Nil {
			req.Header.Set("X-Fixture-User", u.String())
			req.AddCookie(&http.Cookie{Name: "tunnex_session", Value: "fixture-session"})
		}
		if csrf {
			req.Header.Set("X-Tunnex-CSRF", "1")
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if strings.Contains(string(body), "sk-bf-") {
			t.Fatal("private key returned")
		}
		return res.StatusCode
	}
	if got := call(uuid.Nil, true); got != 401 {
		t.Fatalf("anonymous=%d", got)
	}
	if got := call(users[0], false); got != 403 {
		t.Fatalf("CSRF=%d", got)
	}
	for i, u := range users {
		want := 200
		if i == 4 {
			want = 403
		}
		if got := call(u, true); got != want {
			t.Fatalf("member %d: %d want %d", i, got, want)
		}
	}
	if arrivals.Load() != 4 {
		t.Fatal("denied request reached engine")
	}
	exec(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, org, group, users[0])
	if got := call(users[0], true); got != 403 {
		t.Fatalf("removed member=%d", got)
	}
	exec(`INSERT INTO org_mfa(org_id,enforce) VALUES($1,true)`, org)
	if got := call(users[1], true); got != 403 {
		t.Fatalf("MFA bypass=%d", got)
	}
	if arrivals.Load() != 4 {
		t.Fatal("revoked or gated request reached engine")
	}
}

func TestAIUserGrantRoleBoundary(t *testing.T) {
	org := uuid.New()
	srv := apiServer{}
	for _, tc := range []struct {
		role string
		want int
	}{{"member", 403}, {"ai-view", 403}, {"ai-admin", 503}, {"owner", 503}, {"admin", 503}} {
		ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: tc.role}})
		_, err := srv.PutAIUserModelGrant(ctx, api.PutAIUserModelGrantRequestObject{OrgId: org, Body: &api.AIUserModelGrantInput{}})
		var domain *apierr.Error
		if !errors.As(err, &domain) || domain.Status != tc.want {
			t.Errorf("%s: %v", tc.role, err)
		}
	}
}

func TestAIUserGroupCostLimitRoleBoundary(t *testing.T) {
	org := uuid.New()
	srv := apiServer{}
	limit := 5.0
	for _, tc := range []struct {
		role string
		want int
	}{{"member", 403}, {"ai-view", 403}, {"ai-admin", 503}, {"owner", 503}, {"admin", 503}} {
		ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: tc.role}})
		_, err := srv.PutAIUserGroupCostLimit(ctx, api.PutAIUserGroupCostLimitRequestObject{OrgId: org, GroupId: uuid.New(), Body: &api.AIUserGroupCostLimitInput{DailyUsdThreshold: &limit}})
		var domain *apierr.Error
		if !errors.As(err, &domain) || domain.Status != tc.want {
			t.Errorf("%s: %v", tc.role, err)
		}
	}
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}})
	_, err := srv.PutAIUserGroupCostLimit(ctx, api.PutAIUserGroupCostLimitRequestObject{OrgId: org, GroupId: uuid.New()})
	var domain *apierr.Error
	if !errors.As(err, &domain) || domain.Status != 400 {
		t.Errorf("missing body: %v", err)
	}
}

func TestAIUserGroupCostLimitHandler(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, group, owner := uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,ai_gateway_enabled) VALUES($1,'Engineering',$2,true)`, org, "eng-"+org.String())
	exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Engineering')`, group, org)
	exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, owner, owner.String()+"@test.local")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, owner)
	sealer, _ := crypto.NewSealer(bytes.Repeat([]byte{7}, 32))
	srv := apiServer{aiPolicies: aigateway.NewPolicies(pool, sealer, userAccessEngine{})}
	actx := authctx.WithPrincipal(ctx, &authctx.Principal{UserID: owner, EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}})
	limit := 5.0
	res, err := srv.PutAIUserGroupCostLimit(actx, api.PutAIUserGroupCostLimitRequestObject{OrgId: org, GroupId: group, Body: &api.AIUserGroupCostLimitInput{DailyUsdThreshold: &limit, ExpectedRevision: 0}})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := res.(api.PutAIUserGroupCostLimit200JSONResponse)
	if !ok || got.Id != group || got.Name != "Engineering" || got.LimitRevision != 1 || got.DailyUsdThreshold == nil || *got.DailyUsdThreshold != 5 {
		t.Fatalf("response: %#v", res)
	}
	_, err = srv.PutAIUserGroupCostLimit(actx, api.PutAIUserGroupCostLimitRequestObject{OrgId: org, GroupId: group, Body: &api.AIUserGroupCostLimitInput{DailyUsdThreshold: nil, ExpectedRevision: 0}})
	var domain *apierr.Error
	if !errors.As(err, &domain) || domain.Status != 409 {
		t.Fatalf("stale revision: %v", err)
	}
	bad := 0.0
	_, err = srv.PutAIUserGroupCostLimit(actx, api.PutAIUserGroupCostLimitRequestObject{OrgId: org, GroupId: group, Body: &api.AIUserGroupCostLimitInput{DailyUsdThreshold: &bad, ExpectedRevision: 1}})
	if !errors.As(err, &domain) || domain.Status != 400 {
		t.Fatalf("zero limit: %v", err)
	}
	list, err := srv.ListAIUserGroups(actx, api.ListAIUserGroupsRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	groups, ok := list.(api.ListAIUserGroups200JSONResponse)
	if !ok || len(groups) != 1 || groups[0].LimitRevision != 1 || groups[0].DailyUsdThreshold == nil || *groups[0].DailyUsdThreshold != 5 {
		t.Fatalf("list: %#v", list)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND actor_user_id=$2 AND action='ai_user_group.cost_limit_changed' AND target_id=$3`, org, owner, group.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit entries: %d %v", audits, err)
	}
}
