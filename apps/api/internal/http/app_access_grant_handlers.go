package http

import (
	"context"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) appAccessGrantContext(ctx context.Context, org uuid.UUID, write bool) (context.Context, uuid.UUID, error) {
	return s.appAccessPermissionContext(ctx, org, rbac.PermAppAccessGrant, write)
}
func appAccessGrant(r appaccess.Grant) api.AppAccessGrant {
	return api.AppAccessGrant{Id: r.ID, OrgId: r.OrgID, AppId: r.AppID, AppLabel: r.AppLabel, SubjectKind: api.AppAccessSubjectKind(r.SubjectKind), SubjectId: r.SubjectID, SubjectLabel: r.SubjectLabel, Enabled: r.Enabled, StartsAt: r.StartsAt, ExpiresAt: r.ExpiresAt, Version: r.Version, RevokedAt: r.RevokedAt, Status: api.AppAccessGrantStatus(r.Status), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}
func (s apiServer) ListAppAccessGrants(ctx context.Context, req api.ListAppAccessGrantsRequestObject) (api.ListAppAccessGrantsResponseObject, error) {
	ctx, _, err := s.appAccessGrantContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	limit, offset := 50, 0
	kind := ""
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if req.Params.Offset != nil {
		offset = *req.Params.Offset
	}
	if req.Params.SubjectKind != nil {
		kind = string(*req.Params.SubjectKind)
	}
	if limit < 1 || limit > 100 || offset < 0 || offset > 10000 || (kind != "" && kind != "user" && kind != "group") || (req.Params.SubjectId != nil && kind == "") {
		return nil, apierr.BadRequest("invalid_grant_filter", "invalid grant filter or pagination")
	}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	filter := appaccess.GrantListFilter{}
	if req.Params.View != nil {
		filter.View = string(*req.Params.View)
	}
	if req.Params.Search != nil {
		filter.Search = *req.Params.Search
	}
	if req.Params.Status != nil {
		filter.Status = string(*req.Params.Status)
	}
	filter, err = appaccess.NormalizeGrantListFilter(filter)
	if err != nil {
		return nil, err
	}
	rows, err := svc.ListGrants(ctx, req.OrgId, req.Params.AppId, kind, req.Params.SubjectId, int32(limit), int32(offset), filter)
	if err != nil {
		return nil, err
	}
	items := make([]api.AppAccessGrant, len(rows))
	for i, r := range rows {
		items[i] = appAccessGrant(r)
	}
	return api.ListAppAccessGrants200JSONResponse{Body: api.AppAccessGrantList{Items: items, Limit: limit, Offset: offset}, Headers: api.ListAppAccessGrants200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) CreateAppAccessGrant(ctx context.Context, req api.CreateAppAccessGrantRequestObject) (api.CreateAppAccessGrantResponseObject, error) {
	ctx, actor, err := s.appAccessGrantContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	if err = s.requireAppAccessEntitlement(); err != nil {
		return nil, err
	}
	r := req.Body
	input := appaccess.GrantInput{AppID: r.AppId, SubjectKind: string(r.SubjectKind), SubjectID: r.SubjectId, Enabled: r.Enabled, StartsAt: r.StartsAt, ExpiresAt: r.ExpiresAt}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	out, err := svc.CreateGrant(ctx, req.OrgId, actor, input, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.CreateAppAccessGrant201JSONResponse{Body: appAccessGrant(out), Headers: api.CreateAppAccessGrant201ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) UpdateAppAccessGrant(ctx context.Context, req api.UpdateAppAccessGrantRequestObject) (api.UpdateAppAccessGrantResponseObject, error) {
	ctx, actor, err := s.appAccessGrantContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	if req.Body.ExpectedVersion < 1 {
		return nil, apierr.BadRequest("invalid_version", "expected version must be positive")
	}
	if req.Body.Enabled {
		if err = s.requireAppAccessEntitlement(); err != nil {
			return nil, err
		}
	}
	r := req.Body
	input := appaccess.GrantUpdate{Enabled: r.Enabled, StartsAt: r.StartsAt, ExpiresAt: r.ExpiresAt}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	out, err := svc.UpdateGrant(ctx, req.OrgId, actor, req.GrantId, input, r.ExpectedVersion, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.UpdateAppAccessGrant200JSONResponse{Body: appAccessGrant(out), Headers: api.UpdateAppAccessGrant200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) RevokeAppAccessGrant(ctx context.Context, req api.RevokeAppAccessGrantRequestObject) (api.RevokeAppAccessGrantResponseObject, error) {
	ctx, actor, err := s.appAccessGrantContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	if req.Body.ExpectedVersion < 1 {
		return nil, apierr.BadRequest("invalid_version", "expected version must be positive")
	}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	out, err := svc.RevokeGrant(ctx, req.OrgId, actor, req.GrantId, req.Body.ExpectedVersion)
	if err != nil {
		return nil, err
	}
	return api.RevokeAppAccessGrant200JSONResponse{Body: appAccessGrant(out), Headers: api.RevokeAppAccessGrant200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) PreviewAppAccessEffectiveAccess(ctx context.Context, req api.PreviewAppAccessEffectiveAccessRequestObject) (api.PreviewAppAccessEffectiveAccessResponseObject, error) {
	ctx, _, err := s.appAccessGrantContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	out, err := svc.EffectiveAccess(ctx, req.OrgId, req.AppId, req.Body.UserId, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	ids := append([]uuid.UUID{}, out.MatchingGrantIDs...)
	// Project the service's current eligibility decision. Preview does not create
	// a session; browser launch still requires a valid login and fresh authority.
	return api.PreviewAppAccessEffectiveAccess200JSONResponse{Body: api.AppAccessEffectiveAccess{EvaluatedAt: out.EvaluatedAt, GrantMatch: out.GrantMatch, MatchingGrantIds: ids, AccessAllowed: out.AccessAllowed, DenyReason: api.AppAccessEffectiveAccessDenyReason(out.DenyReason), NextExpiryAt: out.NextExpiryAt}, Headers: api.PreviewAppAccessEffectiveAccess200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) GetAppAccessGrantRevokeImpact(ctx context.Context, req api.GetAppAccessGrantRevokeImpactRequestObject) (api.GetAppAccessGrantRevokeImpactResponseObject, error) {
	ctx, _, err := s.appAccessGrantContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	out, err := svc.RevokeImpact(ctx, req.OrgId, req.GrantId)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessGrantRevokeImpact200JSONResponse{Body: api.AppAccessGrantImpact{EvaluatedAt: out.EvaluatedAt, GrantVersion: out.GrantVersion, MatchingUserCount: out.MatchingUserCount, UsersLosingGrantMatchCount: out.UsersLosingGrantMatchCount, SessionImpactAvailable: false}, Headers: api.GetAppAccessGrantRevokeImpact200ResponseHeaders{CacheControl: "no-store"}}, nil
}
