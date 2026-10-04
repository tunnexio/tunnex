package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"unicode/utf8"
)

type appSessionHTTPPort interface {
	MyApps(context.Context, uuid.UUID, uuid.UUID, string, string, int32, int32, bool) (appaccess.MyApps, error)
	LaunchApp(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, string, string, bool) (appaccess.LaunchResult, error)
	MySessions(context.Context, uuid.UUID, uuid.UUID, string, int32, int32) ([]appaccess.MyAppSession, error)
	RevokeMySession(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error
}

func (s apiServer) appSessionContext(ctx context.Context, org uuid.UUID) (context.Context, *authctx.Principal, appSessionHTTPPort, error) {
	ctx, _, e := s.appAccessPermissionContext(ctx, org, rbac.PermAppAccessUse, true)
	if e != nil {
		return ctx, nil, nil, e
	}
	p, e := requireVerifiedUser(ctx)
	if e != nil {
		return ctx, nil, nil, e
	}
	svc, ok := s.appAccess.(appSessionHTTPPort)
	if !ok {
		return ctx, nil, nil, apierr.New(503, "app_access_unavailable", "App Access service unavailable")
	}
	return ctx, p, svc, nil
}

// Own-session withdrawal remains available to a verified live member after use-role loss.
func (s apiServer) appOwnSessionContext(ctx context.Context, org uuid.UUID) (context.Context, *authctx.Principal, appSessionHTTPPort, error) {
	p, e := requireVerifiedUser(ctx)
	if e != nil {
		return ctx, nil, nil, e
	}
	if p.UserID == uuid.Nil || p.IsMachine() || p.IsAgent() || p.SessionID == "" || p.AuthMethod == authctx.AuthBearer {
		return ctx, nil, nil, apierr.Forbidden("human_session_required", "human browser session required")
	}
	if _, ok := p.RoleIn(org); !ok {
		return ctx, nil, nil, apierr.NotFound("org_not_found", "organization not found")
	}
	svc, ok := s.appAccess.(appSessionHTTPPort)
	if !ok {
		return ctx, nil, nil, apierr.New(503, "app_access_unavailable", "App Access service unavailable")
	}
	return authctx.WithOrg(ctx, org), p, svc, nil
}
func appSessionPagination(limit, offset *int) (int32, int32, error) {
	l, o := 50, 0
	if limit != nil {
		l = *limit
	}
	if offset != nil {
		o = *offset
	}
	if l < 1 || l > 100 || o < 0 || o > 10000 {
		return 0, 0, apierr.BadRequest("invalid_pagination", "invalid pagination")
	}
	return int32(l), int32(o), nil
}
func (s apiServer) ListMyAppAccessApps(ctx context.Context, req api.ListMyAppAccessAppsRequestObject) (api.ListMyAppAccessAppsResponseObject, error) {
	ctx, p, svc, e := s.appSessionContext(ctx, req.OrgId)
	if e != nil {
		return nil, e
	}
	limit, offset, e := appSessionPagination(req.Params.Limit, req.Params.Offset)
	if e != nil {
		return nil, e
	}
	search := ""
	if req.Params.Search != nil {
		search = *req.Params.Search
	}
	if !utf8.ValidString(search) || utf8.RuneCountInString(search) > 100 {
		return nil, apierr.BadRequest("invalid_search", "search exceeds 100 characters")
	}
	out, e := svc.MyApps(ctx, req.OrgId, p.UserID, p.SessionID, search, limit, offset, s.appAccessEntitled())
	if e != nil {
		return nil, e
	}
	items := []api.AppAccessMyApp{}
	for _, a := range out.Items {
		items = append(items, api.AppAccessMyApp{RequireMfa: a.RequireMFA, MfaRequired: a.MFARequired, MfaSetupRequired: a.MFASetupRequired, MfaFreshnessSeconds: appaccess.MFAFreshnessSeconds, Id: a.ID, Name: a.Name, Description: a.Description, Icon: a.Icon, IconDataUrl: &a.IconDataURL, LaunchUrl: a.LaunchURL})
	}
	return api.ListMyAppAccessApps200JSONResponse{Body: api.AppAccessMyApps{Items: items, Availability: api.AppAccessMyAppsAvailability(out.Availability), Limit: int(limit), Offset: int(offset)}, Headers: api.ListMyAppAccessApps200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) LaunchMyAppAccessApp(ctx context.Context, req api.LaunchMyAppAccessAppRequestObject) (api.LaunchMyAppAccessAppResponseObject, error) {
	ctx, p, svc, e := s.appSessionContext(ctx, req.OrgId)
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_launch", "launch request required")
	}
	out, e := svc.LaunchApp(ctx, req.OrgId, req.AppId, p.UserID, p.SessionID, req.Body.NonceHash, req.Body.RelativeTarget, s.appAccessEntitled())
	if e != nil {
		return nil, e
	}
	return api.LaunchMyAppAccessApp200JSONResponse{Body: api.AppAccessLaunchResult{RedirectUrl: out.RedirectURL}, Headers: api.LaunchMyAppAccessApp200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) ListMyAppAccessSessions(ctx context.Context, req api.ListMyAppAccessSessionsRequestObject) (api.ListMyAppAccessSessionsResponseObject, error) {
	ctx, p, svc, e := s.appOwnSessionContext(ctx, req.OrgId)
	if e != nil {
		return nil, e
	}
	limit, offset, e := appSessionPagination(req.Params.Limit, req.Params.Offset)
	if e != nil {
		return nil, e
	}
	out, e := svc.MySessions(ctx, req.OrgId, p.UserID, p.SessionID, limit, offset)
	if e != nil {
		return nil, e
	}
	items := []api.AppAccessMySession{}
	for _, r := range out {
		items = append(items, api.AppAccessMySession{Id: r.ID, AppId: r.AppID, AppLabel: r.AppLabel, CurrentParent: r.CurrentParent, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt})
	}
	return api.ListMyAppAccessSessions200JSONResponse{Body: api.AppAccessMySessions{Items: items, Limit: int(limit), Offset: int(offset)}, Headers: api.ListMyAppAccessSessions200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) RevokeMyAppAccessSession(ctx context.Context, req api.RevokeMyAppAccessSessionRequestObject) (api.RevokeMyAppAccessSessionResponseObject, error) {
	ctx, p, svc, e := s.appOwnSessionContext(ctx, req.OrgId)
	if e != nil {
		return nil, e
	}
	if e = svc.RevokeMySession(ctx, req.OrgId, p.UserID, req.SessionId); e != nil {
		return nil, e
	}
	return api.RevokeMyAppAccessSession204Response{Headers: api.RevokeMyAppAccessSession204ResponseHeaders{CacheControl: "no-store"}}, nil
}
