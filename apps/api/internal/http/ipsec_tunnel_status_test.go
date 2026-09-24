package http

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIPsecTunnelStatusAnonymous(t *testing.T) {
	h, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{})
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/organizations/"+uuid.NewString()+"/ipsec/connections/"+uuid.NewString()+"/status", nil))
	if w.Code != 401 {
		t.Fatalf("status %d", w.Code)
	}
}

type tunnelStatusFake struct {
	calls int
	err   error
}

func (f *tunnelStatusFake) ReadStatus(context.Context, uuid.UUID, uuid.UUID) (ipsec.ConnectionStatus, error) {
	f.calls++
	return ipsec.ConnectionStatus{Tunnels: []ipsec.RuntimeTunnelStatus{{ID: uuid.New(), Slot: 1, Status: "up", Selected: true}, {ID: uuid.New(), Slot: 2, Status: "unknown"}}}, f.err
}
func TestIPsecTunnelStatusMemberAndStaticErrors(t *testing.T) {
	org := uuid.New()
	f := &tunnelStatusFake{}
	h, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecStatus: f, AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: rbac.RoleMember}}
	}})
	if e != nil {
		t.Fatal(e)
	}
	call := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/organizations/"+org.String()+"/ipsec/connections/"+uuid.NewString()+"/status", nil))
		return w
	}
	w := call()
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"status":"up"`) {
		t.Fatal("member projection failed", w.Code)
	}
	f.err = errors.New("private-secret-marker")
	w = call()
	if w.Code != 503 || strings.Contains(w.Body.String(), "private-secret-marker") {
		t.Fatal("raw error reflected", w.Code)
	}
}
