package http

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	// These tests exercise /healthz and the validator only — no DB access — so a
	// service over a nil pool is sufficient.
	h, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Orgs: tenancy.NewService(nil)})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return httptest.NewServer(h)
}

func TestHealthzMatchesContract(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-Request-Id") == "" {
		t.Fatal("missing X-Request-Id header (contract requires it)")
	}

	var body struct {
		Status    string `json:"status"`
		Service   string `json:"service"`
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ok" || body.Service != "tunnex-api" {
		t.Fatalf("unexpected body: %+v", body)
	}
	if body.RequestID == "" {
		t.Fatal("body request_id empty")
	}
}

func TestUnknownRouteRejectedBySpecValidator(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	// A path not in the OpenAPI spec must not fall through to a handler.
	resp, err := http.Get(srv.URL + "/api/v1/ping")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("removed/undocumented route returned 200; validator not enforcing spec")
	}
}
