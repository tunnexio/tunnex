package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"testing"
	"time"
)

type appDurableRecorder struct{ appAccessRecorder }

func (r *appDurableRecorder) ListEvents(_ context.Context, org uuid.UUID, _, _, _ *uuid.UUID, ts *time.Time, id *uuid.UUID, limit int32) (appaccess.EventHistory, error) {
	r.calls++
	r.org = org
	return appaccess.EventHistory{Items: nil}, nil
}
func (r *appDurableRecorder) PublicationImpact(_ context.Context, org, app uuid.UUID) (appaccess.PublicationImpact, error) {
	r.calls++
	r.org = org
	return appaccess.PublicationImpact{}, nil
}
func (r *appDurableRecorder) ApplicationSessions(_ context.Context, org, app uuid.UUID, limit, offset int32) ([]appaccess.AdminAppSession, error) {
	r.calls++
	r.org = org
	return []appaccess.AdminAppSession{}, nil
}
func (r *appDurableRecorder) RevokeApplicationSession(_ context.Context, org, app, actor, id uuid.UUID) error {
	r.calls++
	r.org = org
	r.actor = actor
	return nil
}

func TestAppAccessDurableEndpointsPermissionBeforeService(t *testing.T) {
	org := uuid.New()
	app := uuid.New()
	r := &appDurableRecorder{}
	s := apiServer{appAccess: r}
	ctx := authctx.WithPrincipal(context.Background(), appAccessPrincipal(org, "member"))
	if _, err := s.ListAppAccessEvents(ctx, api.ListAppAccessEventsRequestObject{OrgId: org}); err == nil {
		t.Fatal("member event permission bypass")
	}
	if _, err := s.ListAppAccessApplicationSessions(ctx, api.ListAppAccessApplicationSessionsRequestObject{OrgId: org, AppId: app}); err == nil {
		t.Fatal("member session permission bypass")
	}
	if _, err := s.GetAppAccessPublicationImpact(ctx, api.GetAppAccessPublicationImpactRequestObject{OrgId: org, AppId: app}); err == nil {
		t.Fatal("member manage permission bypass")
	}
	if r.calls != 0 {
		t.Fatal("denied authority reached service")
	}
	ctx = authctx.WithPrincipal(context.Background(), appAccessPrincipal(org, "admin"))
	if _, err := s.ListAppAccessEvents(ctx, api.ListAppAccessEventsRequestObject{OrgId: org}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListAppAccessApplicationSessions(ctx, api.ListAppAccessApplicationSessionsRequestObject{OrgId: org, AppId: app}); err != nil {
		t.Fatal(err)
	}
	if r.org != org || r.calls != 2 {
		t.Fatal("admin reads did not preserve tenant")
	}
	if _, err := s.ListAppAccessEvents(ctx, api.ListAppAccessEventsRequestObject{OrgId: uuid.New()}); err == nil {
		t.Fatal("foreign tenant admitted")
	}
	p := appAccessPrincipal(org, "owner")
	p.AuthMethod = authctx.AuthBearer
	p.SessionID = ""
	ctx = authctx.WithPrincipal(context.Background(), p)
	if _, err := s.RevokeAppAccessApplicationSession(ctx, api.RevokeAppAccessApplicationSessionRequestObject{OrgId: org, AppId: app, SessionId: uuid.New()}); err == nil {
		t.Fatal("nonhuman revocation admitted")
	}
}
