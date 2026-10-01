package http

import (
	"context"
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
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/aitransport"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestAITransportHTTPPolicyWire(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	actor, org := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO users(id,email,cp_admin,email_verified_at) VALUES($1,'wire-admin@example.test',true,now())", actor); err != nil {
		t.Fatal(err)
	}
	var arrivals atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Bf-Vk") != "fixture-private-engine-key" {
			t.Error("provider credential boundary changed")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"fixture"}}]}`)
	}))
	t.Cleanup(upstream.Close)
	adapter, err := aigateway.NewAdapter(upstream.URL, func(_ context.Context, raw, model string) (aigateway.Grant, error) {
		if raw != "fixture-ai-bearer" || model != "openrouter/fixture" {
			return aigateway.Grant{}, errors.New("denied")
		}
		return aigateway.Grant{Tenant: org.String(), Agent: actor.String(), VirtualKey: "fixture-private-engine-key", Expires: time.Now().Add(time.Minute)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	makeRouter := func() http.Handler {
		h, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{
			AITransport: aitransport.New(pool), AIAdapter: adapter, AppBaseURL: "https://console.example.test", AIAllowPrivateHTTP: true,
			AuthFn: func(r *http.Request) *authctx.Principal {
				switch r.Header.Get("X-Fixture-Identity") {
				case "admin":
					return &authctx.Principal{UserID: actor, CPAdmin: true, EmailVerified: true}
				case "owner":
					return &authctx.Principal{UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}}
				default:
					return nil
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	plain := httptest.NewServer(makeRouter())
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(makeRouter())
	t.Cleanup(secure.Close)
	call := func(server *httptest.Server, method, path, body, identity, bearer string, cookie, csrf bool, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Fixture-Identity", identity)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if cookie {
			req.AddCookie(&http.Cookie{Name: "tunnex_session", Value: "synthetic-cookie"})
		}
		if csrf {
			req.Header.Set("X-Tunnex-CSRF", "1")
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s got%d want%d: %s", method, path, response.StatusCode, want, raw)
		}
		return raw
	}
	const settings = "/api/v1/admin/ai-transport-settings"
	const inference = "/ai/v1/chat/completions"
	const prompt = `{"model":"openrouter/fixture","messages":[{"role":"user","content":"test"}]}`
	read := func(server *httptest.Server, want bool, revision int64) {
		t.Helper()
		raw := call(server, "GET", settings, "", "admin", "", false, false, 200)
		var v api.AITransportSettings
		if err := json.Unmarshal(raw, &v); err != nil || v.AllowHttp != want || v.Revision != revision {
			t.Fatalf("persisted view %s: %v", raw, err)
		}
	}
	read(plain, false, 1)
	call(plain, "POST", inference, prompt, "", "fixture-ai-bearer", false, false, 403)
	if arrivals.Load() != 0 {
		t.Fatal("default HTTP denial reached private engine")
	}
	call(secure, "POST", inference, prompt, "", "fixture-ai-bearer", false, false, 200)
	call(plain, "PUT", settings, `{"allow_http":true,"revision":1}`, "owner", "", false, false, 403)
	call(plain, "PUT", settings, `{"allow_http":true,"revision":1}`, "admin", "", true, false, 403)
	read(plain, false, 1)
	call(plain, "PUT", settings, `{"allow_http":true,"revision":1}`, "admin", "", true, true, 200)
	read(secure, true, 2)
	// A separately constructed router/service sees the same persisted policy.
	restarted := httptest.NewServer(makeRouter())
	t.Cleanup(restarted.Close)
	read(restarted, true, 2)
	call(restarted, "POST", inference, prompt, "", "", false, false, 401)
	call(restarted, "POST", inference, prompt, "", "wrong", false, false, 403)
	call(restarted, "POST", inference, prompt, "", "fixture-ai-bearer", false, false, 200)
	call(plain, "PUT", settings, `{"allow_http":false,"revision":1}`, "admin", "", true, true, 409)
	read(plain, true, 2)
	call(plain, "PUT", settings, `{"allow_http":false,"revision":2}`, "admin", "", true, true, 200)
	read(restarted, false, 3)
	call(restarted, "POST", inference, prompt, "", "fixture-ai-bearer", false, false, 403)
	call(secure, "POST", inference, prompt, "", "fixture-ai-bearer", false, false, 200)
	if arrivals.Load() != 3 {
		t.Fatalf("unexpected engine requests: %d", arrivals.Load())
	}
}
