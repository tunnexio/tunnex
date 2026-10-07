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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/beam"
)

type beamEvidenceCapture struct {
	calls       int
	org         uuid.UUID
	actor       beam.Actor
	user, share *uuid.UUID
	denies      bool
	before      time.Time
	beforeID    uuid.UUID
	limit       int
	rows        []beam.AccessEvent
}

func (c *beamEvidenceCapture) AccessEvents(_ context.Context, org uuid.UUID, a beam.Actor, user, share *uuid.UUID, denies bool, before time.Time, beforeID uuid.UUID, limit int) ([]beam.AccessEvent, error) {
	c.calls++
	c.org, c.actor, c.user, c.share, c.denies, c.before, c.beforeID, c.limit = org, a, user, share, denies, before, beforeID, limit
	return c.rows, nil
}

func evidencePrincipal(org uuid.UUID, role string) *authctx.Principal {
	return &authctx.Principal{UserID: uuid.New(), SessionID: "fixture", AuthMethod: authctx.AuthLocalPassword, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}}
}

func TestBeamAccessEventsPreserveFiltersAndSafeProjection(t *testing.T) {
	org, share, reviewer, cursorID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	cursorTS := time.Now().UTC().Truncate(time.Microsecond)
	limit, denies := 17, true
	port := &beamEvidenceCapture{rows: []beam.AccessEvent{{ID: uuid.New(), ShareID: share, UserID: &reviewer, Action: "beam.access.denied", Reason: "authority_unavailable", CreatedAt: cursorTS}}}
	network := &accessLogIdentityCapture{}
	s := apiServer{beam: port, accessLog: network}
	p := evidencePrincipal(org, "owner")
	response, e := s.ListAccessEvents(authctx.WithPrincipal(context.Background(), p), api.ListAccessEventsRequestObject{OrgId: org, Params: api.ListAccessEventsParams{Source: ptr(api.Beam), ShareId: &share, SrcUserId: &reviewer, DeniesOnly: &denies, CursorTs: &cursorTS, CursorId: &cursorID, Limit: &limit}})
	if e != nil {
		t.Fatal(e)
	}
	if port.calls != 1 || network.calls != 0 || port.org != org || port.actor.ID != p.UserID || port.actor.SessionID != p.SessionID || port.user != &reviewer || port.share != &share || !port.denies || port.before != cursorTS || port.beforeID != cursorID || port.limit != limit {
		t.Fatalf("Beam query lost its boundary: %+v networkCalls=%d", port, network.calls)
	}
	rows := response.(api.ListAccessEvents200JSONResponse).Body
	if len(rows) != 1 || rows[0].Decision != api.Deny || rows[0].Beam == nil || rows[0].Beam.ShareId != share || rows[0].Beam.Action != api.BeamAccessDenied || rows[0].Beam.Reason != "authority_unavailable" || rows[0].SrcUserId == nil || *rows[0].SrcUserId != reviewer || rows[0].Seq != 0 || rows[0].SrcIp != "" || rows[0].DstIp != "" || rows[0].Protocol != "" || rows[0].NodeId != nil || rows[0].SrcDeviceId != nil || rows[0].DstResourceId != nil {
		t.Fatalf("projection invented network evidence: %+v", rows)
	}
	raw, e := json.Marshal(rows)
	if e != nil || strings.Contains(string(raw), "target") || strings.Contains(string(raw), "token") || strings.Contains(string(raw), "path") {
		t.Fatal("projection disclosed origin or authority material", e)
	}
}

func TestBeamAccessEventsRejectUnauthorizedReadersAndIdentityCombinations(t *testing.T) {
	org, identity := uuid.New(), uuid.New()
	for _, tc := range []struct {
		name   string
		p      *authctx.Principal
		params api.ListAccessEventsParams
		code   int
	}{
		{"signed out", nil, api.ListAccessEventsParams{Source: ptr(api.Beam)}, 401},
		{"member", evidencePrincipal(org, "member"), api.ListAccessEventsParams{Source: ptr(api.Beam)}, 403},
		{"foreign", evidencePrincipal(uuid.New(), "owner"), api.ListAccessEventsParams{Source: ptr(api.Beam)}, 404},
		{"native bearer", &authctx.Principal{UserID: uuid.New(), AuthMethod: authctx.AuthBearer, EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}}, api.ListAccessEventsParams{Source: ptr(api.Beam)}, 403},
		{"multiple identities", evidencePrincipal(org, "owner"), api.ListAccessEventsParams{Source: ptr(api.Beam), SrcDeviceId: &identity, SrcUserId: &identity}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := &beamEvidenceCapture{}
			ctx := context.Background()
			if tc.p != nil {
				ctx = authctx.WithPrincipal(ctx, tc.p)
			}
			_, e := (apiServer{beam: port}).ListAccessEvents(ctx, api.ListAccessEventsRequestObject{OrgId: org, Params: tc.params})
			var typed *apierr.Error
			if !errors.As(e, &typed) || typed.Status != tc.code || port.calls != 0 {
				t.Fatalf("unauthorized request reached evidence: err=%v calls=%d", e, port.calls)
			}
		})
	}
	port := &beamEvidenceCapture{}
	response, e := (apiServer{beam: port}).ListAccessEvents(authctx.WithPrincipal(context.Background(), evidencePrincipal(org, "owner")), api.ListAccessEventsRequestObject{OrgId: org, Params: api.ListAccessEventsParams{Source: ptr(api.Beam), SrcDeviceId: &identity}})
	if e != nil || len(response.(api.ListAccessEvents200JSONResponse).Body) != 0 || port.calls != 0 {
		t.Fatal("Beam device filter invented source attribution", response, e)
	}
}

func TestBeamAccessEventsRouterKeepsNetworkEditionAndBeamHumanGates(t *testing.T) {
	org := uuid.New()
	p := evidencePrincipal(org, "owner")
	h, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AuthFn: func(*http.Request) *authctx.Principal { return p }})
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		query  string
		status int
		code   string
	}{
		{"", 403, "edition_required"},
		{"?source=network", 403, "edition_required"},
		{"?source=beam", 503, "beam_unavailable"},
		{"?source=beam&limit=0", 400, ""},
		{"?source=unknown", 400, ""},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/organizations/"+org.String()+"/access-events"+tc.query, nil))
		if rec.Code != tc.status || (tc.code != "" && !strings.Contains(rec.Body.String(), tc.code)) {
			t.Fatalf("query %q: %d %s", tc.query, rec.Code, rec.Body.String())
		}
	}
}

func TestBeamAccessEventsRejectAuthorizationHeaderFallback(t *testing.T) {
	org := uuid.New()
	p := evidencePrincipal(org, "owner")
	h, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AuthFn: func(*http.Request) *authctx.Principal { return p }})
	if e != nil {
		t.Fatal(e)
	}
	for _, authorization := range []string{"Bearer invalid", "Bearer tnx_fixture", "AppProxy invalid"} {
		req := httptest.NewRequest("GET", "/api/v1/organizations/"+org.String()+"/access-events?source=beam", nil)
		req.Header.Set("Authorization", authorization)
		req.Header.Set("Cookie", "tunnex_session=fixture")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), "human_browser_session_required") {
			t.Fatalf("authorization fallback admitted: %d %s", rec.Code, rec.Body.String())
		}
	}
}

func ptr[T any](v T) *T { return &v }
