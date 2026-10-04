package http

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type appAccessPreviewRecorder struct {
	appAccessRecorder
	preview appaccess.Preview
}

func (f *appAccessPreviewRecorder) EffectiveAccess(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, bool) (appaccess.Preview, error) {
	f.calls++
	return f.preview, nil
}

func TestAppAccessEffectiveAccessHTTPProjection(t *testing.T) {
	org, app, subject, grant := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	evaluated := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	expires := evaluated.Add(time.Hour)
	ctx := authctx.WithPrincipal(context.Background(), appAccessPrincipal(org, rbac.RoleOwner))
	for _, tc := range []struct {
		name    string
		allowed bool
		reason  string
	}{
		{"published eligible user", true, ""},
		{"unpublished draft", false, "app_unpublished"},
		{"disabled feature", false, "feature_disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &appAccessPreviewRecorder{preview: appaccess.Preview{
				EvaluatedAt: evaluated, GrantMatch: true, MatchingGrantIDs: []uuid.UUID{grant},
				AccessAllowed: tc.allowed, DenyReason: tc.reason, NextExpiryAt: &expires,
			}}
			s := apiServer{appAccess: f}
			response, err := s.PreviewAppAccessEffectiveAccess(ctx, api.PreviewAppAccessEffectiveAccessRequestObject{
				OrgId: org, AppId: app, Body: &api.AppAccessEffectiveAccessInput{UserId: subject},
			})
			if err != nil {
				t.Fatal(err)
			}
			wire := httptest.NewRecorder()
			if err := response.VisitPreviewAppAccessEffectiveAccessResponse(wire); err != nil {
				t.Fatal(err)
			}
			if wire.Code != 200 || wire.Header().Get("Cache-Control") != "no-store" || f.calls != 1 {
				t.Fatalf("unexpected preview response: status=%d cache=%q calls=%d", wire.Code, wire.Header().Get("Cache-Control"), f.calls)
			}
			var got api.AppAccessEffectiveAccess
			if err := json.Unmarshal(wire.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.AccessAllowed != tc.allowed || string(got.DenyReason) != tc.reason {
				t.Fatalf("HTTP response changed service eligibility: allowed=%t reason=%q; want allowed=%t reason=%q", got.AccessAllowed, got.DenyReason, tc.allowed, tc.reason)
			}
			if !got.GrantMatch || len(got.MatchingGrantIds) != 1 || got.MatchingGrantIds[0] != grant || !got.EvaluatedAt.Equal(evaluated) || got.NextExpiryAt == nil || !got.NextExpiryAt.Equal(expires) {
				t.Fatalf("preview metadata was not preserved: %#v", got)
			}
		})
	}
}
