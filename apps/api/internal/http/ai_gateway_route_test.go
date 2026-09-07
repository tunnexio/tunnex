package http

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func aiSocketServer(t *testing.T, d Deps) *httptest.Server {
	t.Helper()
	if d.Orgs == nil {
		d.Orgs = tenancy.NewService(nil)
	}
	h, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), d)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}
func aiSocketRequest(t *testing.T, srv *httptest.Server, method, path, body, bearer, role string) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if role != "" {
		r.Header.Set("X-Fixture-Role", role)
	}
	client := &http.Client{Timeout: 4 * time.Second}
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func TestAIGatewaySocketRoutes(t *testing.T) {
	var arrivals atomic.Int32
	nextChunk := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/anthropic/v1/messages" {
			t.Errorf("wrong forwarded path %q", r.URL.Path)
		}
		if r.URL.Path == "/anthropic/v1/messages" && r.Header.Get("Anthropic-Version") != "2023-06-01" {
			t.Error("trusted Anthropic version missing")
		}
		for _, name := range []string{"Authorization", "Cookie", "X-Tunnex-Tenant", "X-Bf-Api-Key", "X-Bf-Provider", "X-Forwarded-For"} {
			if r.Header.Get(name) != "" {
				t.Errorf("forged %s reached engine", name)
			}
		}
		if r.Header.Get("X-Bf-Vk") != "sk-bf-fixture-route" {
			t.Error("scoped engine key missing")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Set-Cookie", "internal=secret")
		w.Header().Set("X-Bf-Vk", "must-not-return")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-nextChunk:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	adapter, err := aigateway.NewAdapter(upstream.URL, func(_ context.Context, raw, model string) (aigateway.Grant, error) {
		if raw != "fixture-ai" || model != "openrouter/allowed" {
			return aigateway.Grant{}, errors.New("denied")
		}
		return aigateway.Grant{Tenant: "tenant", Agent: "agent", VirtualKey: "sk-bf-fixture-route", Expires: time.Now().Add(time.Minute)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := aiSocketServer(t, Deps{AIAdapter: adapter})
	t.Run("negative_no_engine_arrival", func(t *testing.T) {
		cases := []struct {
			body, bearer string
			status       int
		}{
			{`{"model":"openrouter/allowed","messages":[{"role":"user","content":"test"}]}`, "", 401},
			{`{"model":"openrouter/allowed","messages":[{"role":"user","content":"test"}]}`, "wrong", 403},
			{`{"model":"openrouter/allowed","messages":[{"role":"user","content":"test"}],"fallbacks":[]}`, "fixture-ai", 400},
			{`{"model":"openrouter/allowed","model":"openrouter/other"}`, "fixture-ai", 400},
			{strings.Repeat("x", aigateway.MaxBodyBytes+1), "fixture-ai", 413},
		}
		for _, tc := range cases {
			res := aiSocketRequest(t, srv, "POST", "/ai/v1/chat/completions", tc.body, tc.bearer, "")
			if res.StatusCode != tc.status {
				b, _ := io.ReadAll(res.Body)
				t.Errorf("status=%d want=%d: %s", res.StatusCode, tc.status, b)
			}
			res.Body.Close()
		}
		if arrivals.Load() != 0 {
			t.Fatal("denial reached engine")
		}
	})
	t.Run("streaming_survives_real_middleware", func(t *testing.T) {
		r, _ := http.NewRequest("POST", srv.URL+"/ai/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"test"}],"stream":true}`))
		r.Header.Set("Authorization", "Bearer fixture-ai")
		r.Header.Set("Content-Type", "application/json")
		for _, name := range []string{"Cookie", "X-Tunnex-Tenant", "X-Bf-Api-Key", "X-Bf-Provider", "X-Forwarded-For"} {
			r.Header.Set(name, "forged")
		}
		res, err := (&http.Client{Timeout: 4 * time.Second}).Do(r)
		if err != nil {
			close(nextChunk)
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			close(nextChunk)
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("real middleware response %d: %s", res.StatusCode, b)
		}
		reader := bufio.NewReader(res.Body)
		first, err := reader.ReadString('\n')
		close(nextChunk)
		if err != nil || !strings.Contains(first, "OK") {
			t.Fatalf("incremental first chunk missing: %v", err)
		}
		rest, err := io.ReadAll(reader)
		if err != nil || !strings.Contains(string(rest), "[DONE]") {
			t.Fatalf("terminal event missing: %v", err)
		}
		if res.Header.Get("X-Request-Id") == "" || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("canonical response metadata missing")
		}
		if res.Header.Get("Set-Cookie") != "" || res.Header.Get("X-Bf-Vk") != "" {
			t.Fatal("engine secret header returned")
		}
	})
	t.Run("anthropic_route_reaches_qualified_adapter", func(t *testing.T) {
		res := aiSocketRequest(t, srv, "POST", "/ai/anthropic/v1/messages", `{"model":"openrouter/allowed","messages":[{"role":"user","content":"test"}],"max_tokens":16,"stream":true}`, "fixture-ai", "")
		body, err := io.ReadAll(res.Body)
		if err != nil || res.StatusCode != 200 || !strings.Contains(string(body), "[DONE]") {
			t.Fatalf("Anthropic route failed: status=%d error=%v", res.StatusCode, err)
		}
	})
	t.Run("unconfigured", func(t *testing.T) {
		off := aiSocketServer(t, Deps{})
		res := aiSocketRequest(t, off, "POST", "/ai/v1/chat/completions", `{}`, "fixture-ai", "")
		if res.StatusCode != 503 {
			t.Fatalf("default status %d", res.StatusCode)
		}
	})
}

type aiRoutePolicy struct{}

func (aiRoutePolicy) CanIssue(context.Context, pgx.Tx, agentruntime.Identity) error { return nil }
func (aiRoutePolicy) Resolve(_ context.Context, _ pgx.Tx, id agentruntime.Identity, _ string) (aigateway.Grant, error) {
	return aigateway.Grant{Tenant: id.OrgID.String(), Agent: id.DeviceID.String(), VirtualKey: "sk-bf-route", Expires: time.Now().Add(time.Minute)}, nil
}

func TestAIGatewayRoutesPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, other, owner, device, node := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	seed(`INSERT INTO organizations(id,name,slug) VALUES($1,'AI routes',$2),($3,'AI other',$4)`, org, "ai-route-"+org.String(), other, "ai-route-"+other.String())
	seed(`INSERT INTO users(id,email) VALUES($1,$2)`, owner, owner.String()+"@ai-route.test")
	seed(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, owner)
	seed(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'gateway',$3)`, node, org, node.String())
	seed(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,status,kind) VALUES($1,$2,$3,$4,'agent',$5,'active','agent')`, device, org, owner, node, device.String())
	raw := agentruntime.RuntimeCredentialPrefix + uuid.NewString()
	hash := sha256.Sum256([]byte(raw))
	seed(`INSERT INTO agent_runtime_credentials(org_id,device_id,token_hash) VALUES($1,$2,$3)`, org, device, hash[:])
	runtime := agentruntime.New(pool, nil)
	credentials := aigateway.NewCredentials(pool, runtime, aiRoutePolicy{})
	credentials.SetAvailable(true)
	srv := aiSocketServer(t, Deps{System: sqlc.New(pool), Orgs: tenancy.NewService(pool), AgentRuntimePool: pool, AICredentials: credentials, AuthFn: func(r *http.Request) *authctx.Principal {
		role := r.Header.Get("X-Fixture-Role")
		if role == "" {
			return nil
		}
		return &authctx.Principal{UserID: owner, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}}
	}})
	path := "/api/v1/organizations/" + org.String() + "/ai-gateway"
	for _, role := range []string{rbac.RoleOwner, rbac.RoleAdmin, rbac.RoleMember} {
		for _, method := range []string{"GET", "PUT"} {
			body := ""
			if method == "PUT" {
				body = `{"enabled":true}`
			}
			res := aiSocketRequest(t, srv, method, path, body, "", role)
			want := 200
			if role == rbac.RoleMember {
				want = 403
			}
			if res.StatusCode != want {
				b, _ := io.ReadAll(res.Body)
				t.Fatalf("%s %s status=%d expected=%d %s", role, method, res.StatusCode, want, b)
			}
			res.Body.Close()
		}
	}
	res := aiSocketRequest(t, srv, "GET", "/api/v1/organizations/"+other.String()+"/ai-gateway", "", "", rbac.RoleOwner)
	if res.StatusCode != 404 {
		t.Fatalf("cross-tenant status %d", res.StatusCode)
	}
	res.Body.Close()
	issuance := "/api/v1/agent/runtime/ai-credential"
	for _, bearer := range []string{"", "invalid"} {
		res := aiSocketRequest(t, srv, "POST", issuance, "", bearer, rbac.RoleOwner)
		if res.StatusCode != 401 {
			t.Fatalf("session bypass status %d", res.StatusCode)
		}
		res.Body.Close()
	}
	res = aiSocketRequest(t, srv, "POST", issuance, "", raw, "")
	if res.StatusCode != 201 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("mint status %d: %s", res.StatusCode, b)
	}
	var minted map[string]any
	if err := json.NewDecoder(res.Body).Decode(&minted); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if minted["audience"] != "tunnex-ai" || !strings.HasPrefix(minted["token"].(string), "tnx_ai_") || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("issuance envelope invalid")
	}
}
