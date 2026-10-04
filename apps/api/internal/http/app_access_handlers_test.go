package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"strings"
	"testing"
	"time"
)

type appAccessRecorder struct {
	org, actor        uuid.UUID
	enabled, entitled bool
	calls             int
	version           int64
	input             appaccess.DraftInput
	err               error
}

func (f *appAccessRecorder) GetSettings(_ context.Context, org uuid.UUID) (appaccess.Settings, error) {
	f.org = org
	f.calls++
	return appaccess.Settings{Version: 1, DomainReady: true, BaseDomain: "apps.example.net"}, f.err
}
func (f *appAccessRecorder) UpdateSettings(_ context.Context, org, actor uuid.UUID, enabled bool, version int64, entitled bool) (appaccess.Settings, error) {
	f.org = org
	f.actor = actor
	f.enabled = enabled
	f.entitled = entitled
	f.version = version
	f.calls++
	return appaccess.Settings{Enabled: enabled, Version: version + 1}, f.err
}
func (f *appAccessRecorder) CreateDraft(_ context.Context, org, actor uuid.UUID, in appaccess.DraftInput, entitled bool) (appaccess.Application, error) {
	f.org = org
	f.actor = actor
	f.input = in
	f.entitled = entitled
	f.calls++
	return appaccess.Application{ID: uuid.New(), OrgID: org, Version: 1, DraftRevision: 1, State: "draft", ConnectorStatus: "unknown"}, f.err
}
func (f *appAccessRecorder) UpdateDraft(_ context.Context, org, actor, app uuid.UUID, in appaccess.DraftInput, version int64, entitled bool) (appaccess.Application, error) {
	f.version = version
	return f.CreateDraft(context.Background(), org, actor, in, entitled)
}
func (f *appAccessRecorder) GetApplication(_ context.Context, org, app uuid.UUID) (appaccess.Application, error) {
	f.org = org
	f.calls++
	return appaccess.Application{ID: app, OrgID: org, State: "draft", ConnectorStatus: "unknown"}, f.err
}
func (f *appAccessRecorder) ListApplications(_ context.Context, org uuid.UUID, _ string, _, _ int32, _ ...string) ([]appaccess.Application, error) {
	f.org = org
	f.calls++
	return []appaccess.Application{}, f.err
}
func (f *appAccessRecorder) GetRevision(_ context.Context, org, app uuid.UUID, revision int64) (appaccess.Revision, error) {
	f.org = org
	f.version = revision
	f.calls++
	return appaccess.Revision{Revision: revision}, f.err
}
func appAccessPrincipal(org uuid.UUID, role string) *authctx.Principal {
	return &authctx.Principal{UserID: uuid.New(), SessionID: "parent-login", EmailVerified: true, AuthMethod: authctx.AuthLocalPassword, Roles: map[uuid.UUID]string{org: role}}
}
func TestAppAccessMutationAuthorityBeforeEntitlement(t *testing.T) {
	org := uuid.New()
	for _, tc := range []struct {
		name           string
		role           string
		method         string
		session        string
		verified, wall bool
		code           int
		reason         string
	}{
		{"member", rbac.RoleMember, authctx.AuthLocalPassword, "s", true, false, 403, "forbidden"},
		{"unverified", rbac.RoleOwner, authctx.AuthLocalPassword, "s", false, false, 403, "email_not_verified"},
		{"password", rbac.RoleOwner, authctx.AuthLocalPassword, "s", true, true, 403, "password_change_required"},
		{"bearer", rbac.RoleOwner, authctx.AuthBearer, "s", true, false, 403, "human_session_required"},
		{"machine", rbac.RoleOwner, authctx.AuthMachine, "s", true, false, 403, "human_session_required"},
		{"agent", rbac.RoleOwner, authctx.AuthAgent, "s", true, false, 403, "human_session_required"},
		{"no cookie", rbac.RoleOwner, authctx.AuthLocalPassword, "", true, false, 403, "human_session_required"},
		{"unentitled", rbac.RoleOwner, authctx.AuthLocalPassword, "s", true, false, 403, "entitlement_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := appAccessPrincipal(org, tc.role)
			p.AuthMethod = tc.method
			p.SessionID = tc.session
			p.EmailVerified = tc.verified
			p.MustChangePassword = tc.wall
			ctx := authctx.WithPrincipal(context.Background(), p)
			f := &appAccessRecorder{}
			s := apiServer{appAccess: f}
			_, err := s.UpdateAppAccessSettings(ctx, api.UpdateAppAccessSettingsRequestObject{OrgId: org, Body: &api.AppAccessSettingsInput{Enabled: true, ExpectedVersion: 1}})
			if !hasCode(err, tc.code, tc.reason) || f.calls != 0 {
				t.Fatalf("want %s, got %v calls%d", tc.reason, err, f.calls)
			}
		})
	}
	s := apiServer{}
	req := api.GetAppAccessSettingsRequestObject{OrgId: org}
	if _, err := s.GetAppAccessSettings(context.Background(), req); !hasCode(err, 401, "unauthenticated") {
		t.Fatal(err)
	}
	foreign := authctx.WithPrincipal(context.Background(), appAccessPrincipal(uuid.New(), rbac.RoleOwner))
	if _, err := s.GetAppAccessSettings(foreign, req); !hasCode(err, 404, "org_not_found") {
		t.Fatal(err)
	}
}
func TestAppAccessReadAndDisableSurviveLapse(t *testing.T) {
	org := uuid.New()
	p := appAccessPrincipal(org, rbac.RoleOwner)
	ctx := authctx.WithPrincipal(context.Background(), p)
	f := &appAccessRecorder{}
	s := apiServer{appAccess: f, licence: licence.NewTestManager("trial", time.Now().Add(-licence.GracePeriod-time.Hour))}
	got, err := s.GetAppAccessSettings(ctx, api.GetAppAccessSettingsRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	body := got.(api.GetAppAccessSettings200JSONResponse)
	if body.Body.EntitlementAvailable || body.Headers.CacheControl != "no-store" || !body.Body.DomainReady {
		t.Fatalf("projection %#v", body)
	}
	_, err = s.UpdateAppAccessSettings(ctx, api.UpdateAppAccessSettingsRequestObject{OrgId: org, Body: &api.AppAccessSettingsInput{Enabled: false, ExpectedVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if f.org != org || f.actor != p.UserID || f.enabled || f.entitled {
		t.Fatal("wrong disabled operation scope")
	}
}
func TestAppAccessDraftLocalAndSSOAuthority(t *testing.T) {
	org := uuid.New()
	for _, method := range []string{authctx.AuthLocalPassword, authctx.AuthSSO} {
		t.Run(method, func(t *testing.T) {
			p := appAccessPrincipal(org, rbac.RoleAdmin)
			p.AuthMethod = method
			ctx := authctx.WithPrincipal(context.Background(), p)
			f := &appAccessRecorder{}
			s := apiServer{appAccess: f, licence: licence.NewTestManager("trial", time.Now().Add(time.Hour))}
			got, err := s.CreateAppAccessApplication(ctx, api.CreateAppAccessApplicationRequestObject{OrgId: org, Body: &api.AppAccessDraftInput{Name: "Orders", Description: "Internal", Icon: "app", OriginUrl: "https://orders.internal", GatewayId: uuid.New(), PublicHostname: "orders.apps.example.net", IdleTimeoutSeconds: 1800, AbsoluteTimeoutSeconds: 28800}})
			if err != nil {
				t.Fatal(err)
			}
			if f.org != org || f.actor != p.UserID || !f.entitled || f.input.Name != "Orders" {
				t.Fatal("draft actor/scope lost")
			}
			if got.(api.CreateAppAccessApplication201JSONResponse).Body.ConnectorStatus != "unknown" {
				t.Fatal("fabricated readiness")
			}
		})
	}
}
func TestAppAccessPaginationAndErrors(t *testing.T) {
	org := uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), appAccessPrincipal(org, rbac.RoleOwner))
	f := &appAccessRecorder{}
	s := apiServer{appAccess: f}
	huge := int(1 << 40)
	_, err := s.ListAppAccessApplications(ctx, api.ListAppAccessApplicationsRequestObject{OrgId: org, Params: api.ListAppAccessApplicationsParams{Offset: &huge}})
	if !hasCode(err, 400, "invalid_pagination") || f.calls != 0 {
		t.Fatal("pagination overflow")
	}
	search := strings.Repeat("界", 100)
	if _, err = s.ListAppAccessApplications(ctx, api.ListAppAccessApplicationsRequestObject{OrgId: org, Params: api.ListAppAccessApplicationsParams{Search: &search}}); err != nil {
		t.Fatal("Unicode search rejected", err)
	}
	f.err = apierr.NotFound("application_not_found", "application not found")
	_, err = s.GetAppAccessApplication(ctx, api.GetAppAccessApplicationRequestObject{OrgId: org, AppId: uuid.New()})
	if !hasCode(err, 404, "application_not_found") || f.org != org {
		t.Fatal("tenant error changed")
	}
	if appAccessTimeouts(huge+1800, huge+28800) == nil {
		t.Fatal("timeout overflow")
	}
}

func (f *appAccessRecorder) ListGrants(_ context.Context, org uuid.UUID, _ *uuid.UUID, _ string, _ *uuid.UUID, _, _ int32, _ ...appaccess.GrantListFilter) ([]appaccess.Grant, error) {
	f.org = org
	f.calls++
	return []appaccess.Grant{}, f.err
}
func (f *appAccessRecorder) CreateGrant(_ context.Context, org, actor uuid.UUID, in appaccess.GrantInput, entitled bool) (appaccess.Grant, error) {
	f.org = org
	f.actor = actor
	f.entitled = entitled
	f.enabled = in.Enabled
	f.calls++
	return appaccess.Grant{ID: uuid.New(), OrgID: org, AppID: in.AppID, SubjectKind: in.SubjectKind, SubjectID: in.SubjectID, Version: 1, Enabled: in.Enabled, Status: "active"}, f.err
}
func (f *appAccessRecorder) UpdateGrant(_ context.Context, org, actor, grant uuid.UUID, in appaccess.GrantUpdate, version int64, entitled bool) (appaccess.Grant, error) {
	f.org = org
	f.actor = actor
	f.entitled = entitled
	f.enabled = in.Enabled
	f.calls++
	f.version = version
	return appaccess.Grant{ID: grant, Version: version + 1, Enabled: in.Enabled, Status: "disabled"}, f.err
}
func (f *appAccessRecorder) RevokeGrant(_ context.Context, org, actor, grant uuid.UUID, version int64) (appaccess.Grant, error) {
	f.org = org
	f.actor = actor
	f.calls++
	f.version = version
	return appaccess.Grant{ID: grant, Version: version + 1, Status: "revoked"}, f.err
}
func (f *appAccessRecorder) EffectiveAccess(_ context.Context, org, app, user uuid.UUID, _ bool) (appaccess.Preview, error) {
	f.org = org
	f.calls++
	return appaccess.Preview{GrantMatch: true, AccessAllowed: false, DenyReason: "app_unpublished"}, f.err
}
func (f *appAccessRecorder) RevokeImpact(_ context.Context, org, grant uuid.UUID) (appaccess.GrantImpact, error) {
	f.org = org
	f.calls++
	return appaccess.GrantImpact{GrantVersion: 1, MatchingUserCount: 2, UsersLosingGrantMatchCount: 1}, f.err
}
