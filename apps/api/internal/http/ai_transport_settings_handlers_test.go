package http

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aitransport"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type aiTransportStub struct {
	value   aitransport.Settings
	failure error
	calls   atomic.Int64
	actor   uuid.UUID
}

func (s *aiTransportStub) Get(context.Context) (aitransport.Settings, error) {
	s.calls.Add(1)
	return s.value, s.failure
}
func (s *aiTransportStub) Save(_ context.Context, actor uuid.UUID, in aitransport.Settings) (aitransport.Settings, error) {
	s.calls.Add(1)
	s.actor = actor
	if s.failure != nil {
		return aitransport.Settings{}, s.failure
	}
	s.value = aitransport.Settings{AllowHTTP: in.AllowHTTP, Revision: in.Revision + 1}
	return s.value, nil
}

func TestAITransportRequiresVerifiedServerAdministrator(t *testing.T) {
	for _, p := range []*authctx.Principal{nil, {UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): "owner"}}, {UserID: uuid.New(), CPAdmin: true}, {UserID: uuid.New(), CPAdmin: true, EmailVerified: true, MustChangePassword: true}} {
		ctx := context.Background()
		if p != nil {
			ctx = authctx.WithPrincipal(ctx, p)
		}
		stub := &aiTransportStub{}
		server := apiServer{aiTransport: stub}
		if _, err := server.GetAITransportSettings(ctx, api.GetAITransportSettingsRequestObject{}); err == nil {
			t.Fatal("unauthorized read")
		}
		if _, err := server.UpdateAITransportSettings(ctx, api.UpdateAITransportSettingsRequestObject{Body: &api.AITransportSettings{AllowHttp: true, Revision: 1}}); err == nil {
			t.Fatal("unauthorized write")
		}
		if stub.calls.Load() != 0 {
			t.Fatal("repository accessed before authorization")
		}
	}
	p := &authctx.Principal{UserID: uuid.New(), CPAdmin: true, EmailVerified: true}
	ctx := authctx.WithPrincipal(context.Background(), p)
	stub := &aiTransportStub{value: aitransport.Settings{Revision: 1}}
	server := apiServer{aiTransport: stub}
	response, err := server.UpdateAITransportSettings(ctx, api.UpdateAITransportSettingsRequestObject{Body: &api.AITransportSettings{AllowHttp: true, Revision: 1}})
	if err != nil || stub.actor != p.UserID || !response.(api.UpdateAITransportSettings200JSONResponse).Body.AllowHttp {
		t.Fatal("admin save failed", err)
	}
	stub.failure = apierr.Conflict("ai_transport_settings_changed", "Reload")
	if _, err = server.UpdateAITransportSettings(ctx, api.UpdateAITransportSettingsRequestObject{Body: &api.AITransportSettings{Revision: 1}}); err != stub.failure {
		t.Fatal("revision conflict hidden", err)
	}
	stub.failure = errors.New("database password=secret")
	if _, err = server.GetAITransportSettings(ctx, api.GetAITransportSettingsRequestObject{}); err == nil || strings.Contains(err.Error(), "password") {
		t.Fatal("raw policy error escaped")
	}
}

func TestAITransportCoversAllAIContracts(t *testing.T) {
	spec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	transport, _ := newRequestTransport(nil)
	stub := &aiTransportStub{value: aitransport.Settings{Revision: 1}}
	calls := 0
	handler := transport.middleware(aiTransportMiddleware(stub)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) })))
	tested := 0
	for path, item := range spec.Paths.Map() {
		if !strings.HasPrefix(path, "/ai/") && !strings.Contains(path, "/ai-gateway") && !strings.HasPrefix(path, "/api/v1/workload/") && path != "/api/v1/agent/runtime/ai-credential" {
			continue
		}
		for method := range item.Operations() {
			// Metadata remains available to explain the prerequisite.
			if path == "/api/v1/organizations/{orgId}/ai-gateway" && method == "GET" {
				continue
			}
			tested++
			t.Run(method+" "+path, func(t *testing.T) {
				for _, allow := range []bool{false, true, false} {
					stub.value.AllowHTTP = allow
					before := calls
					req := httptest.NewRequest(method, "http://console.example.test"+path, nil)
					req.Header.Set("X-Forwarded-Proto", "https") // No trusted peer: cannot override native HTTP.
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					want := 403
					if allow {
						want = 204
					}
					if rec.Code != want || (calls > before) != allow {
						t.Fatalf("allow=%v code=%d body=%s", allow, rec.Code, rec.Body.String())
					}
				}
				stub.failure = errors.New("database password=secret")
				req := httptest.NewRequest(method, "https://console.example.test"+path, nil)
				req.TLS = &tls.ConnectionState{}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != 204 {
					t.Fatal("HTTPS depended on HTTP policy storage", rec.Code)
				}
				stub.failure = nil
			})
		}
	}
	if tested < 45 {
		t.Fatalf("too few AI contracts exercised: %d", tested)
	}
	for _, path := range []string{"/api/v1/admin/ai-transport-settings", "/api/v1/organizations/abc/ai-gateway", "/healthz"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 204 {
			t.Fatal("non-gated metadata blocked", path)
		}
	}
	for _, repo := range []aiTransportRepository{nil, &aiTransportStub{failure: errors.New("password=secret")}} {
		rec := httptest.NewRecorder()
		transport.middleware(aiTransportMiddleware(repo)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("missing policy failed open") }))).ServeHTTP(rec, httptest.NewRequest("GET", "/ai/v1/models", nil))
		if rec.Code != 503 || strings.Contains(rec.Body.String(), "password") {
			t.Fatal("unsafe unavailable policy response", rec.Code)
		}
	}
}

func TestAITransportRouterPreservesAuthentication(t *testing.T) {
	stub := &aiTransportStub{value: aitransport.Settings{AllowHTTP: true, Revision: 1}}
	handler, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AITransport: stub, AppBaseURL: "https://console.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/admin/ai-transport-settings", "/api/v1/organizations/" + uuid.NewString() + "/ai-gateway/providers"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 401 {
			t.Fatalf("HTTP opt-in bypassed authentication: %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	stub.value.AllowHTTP = false
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/ai/v1/models", nil))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "ai_https_required") {
		t.Fatalf("advertised HTTPS base bypassed HTTP gate: %d %s", rec.Code, rec.Body.String())
	}
}
