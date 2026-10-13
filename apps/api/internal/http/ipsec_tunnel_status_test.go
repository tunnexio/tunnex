package http

import (
	"context"
	"encoding/json"
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
	calls  int
	err    error
	status *ipsec.ConnectionStatus
}

func (f *tunnelStatusFake) ReadStatus(context.Context, uuid.UUID, uuid.UUID) (ipsec.ConnectionStatus, error) {
	f.calls++
	if f.status != nil {
		return *f.status, f.err
	}
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
	one, two := 1, 2
	sequence := uint64(7)
	f.status = &ipsec.ConnectionStatus{RecoveryVersion: &one, SelectionSequence: &sequence, ActiveSlot: &two, Tunnels: []ipsec.RuntimeTunnelStatus{{ID: uuid.New(), Slot: 1, Selected: true, Status: "down"}, {ID: uuid.New(), Slot: 2, Status: "up"}}}
	w = call()
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"active_slot":2`) || !strings.Contains(w.Body.String(), `"selection_sequence":7`) || !strings.Contains(w.Body.String(), `"recovery_version":1`) {
		t.Fatal("recovery observation missing", w.Code, w.Body.String())
	}
	f.status.ActiveSlot = nil
	w = call()
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"active_slot":null`) {
		t.Fatal("unknown path not nullable", w.Code, w.Body.String())
	}
	f.err = errors.New("private-secret-marker")
	w = call()
	if w.Code != 503 || strings.Contains(w.Body.String(), "private-secret-marker") {
		t.Fatal("raw error reflected", w.Code)
	}
}

func TestIPsecBGPStatusProjection(t *testing.T) {
	org := uuid.New()
	rejected := 3
	f := &tunnelStatusFake{status: &ipsec.ConnectionStatus{
		BGP: &ipsec.RuntimeBGPStatus{Version: 1, Sequence: 7, Peers: [2]ipsec.RuntimeBGPPeerStatus{
			{Slot: 1, State: "established", AcceptedPrefixes: 1, InstalledPrefixes: 1, RejectedPrefixes: &rejected},
			{Slot: 2, State: "active"},
		}, Routes: []ipsec.RuntimeBGPRoute{{Prefix: "10.85.0.0/16", Slot: 1}}},
		Tunnels: []ipsec.RuntimeTunnelStatus{{ID: uuid.New(), Slot: 1, Status: "up"}, {ID: uuid.New(), Slot: 2, Status: "up"}},
	}}
	h, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecStatus: f, AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: rbac.RoleMember}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/organizations/"+org.String()+"/ipsec/connections/"+uuid.NewString()+"/status", nil))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("BGP status projection failed", w.Code)
	}
	var body struct {
		BGP             *ipsec.RuntimeBGPStatus `json:"bgp"`
		RecoveryVersion *int                    `json:"recovery_version"`
		ActiveSlot      *int                    `json:"active_slot"`
	}
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || body.BGP == nil || body.BGP.Sequence != 7 || body.BGP.Peers[0].RejectedPrefixes == nil || *body.BGP.Peers[0].RejectedPrefixes != 3 || len(body.BGP.Routes) != 1 || body.BGP.Routes[0].Slot != 1 || body.RecoveryVersion != nil || body.ActiveSlot != nil {
		t.Fatal("BGP observation mapping lost", w.Body.String())
	}
	f.status.BGP.Routes = nil
	f.status.BGP.Peers[0].RejectedPrefixes = nil
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/organizations/"+org.String()+"/ipsec/connections/"+uuid.NewString()+"/status", nil))
	if !strings.Contains(w.Body.String(), `"routes":[]`) || strings.Contains(w.Body.String(), `"rejected_prefixes"`) {
		t.Fatal("empty routes or unmeasured rejection misreported", w.Body.String())
	}
}
