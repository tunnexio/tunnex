package http

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type appAccessCompanyPort interface {
	GetAccessManagement(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (appaccess.AccessManagement, error)
	UpdateAccessManagement(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, bool, *uuid.UUID, int64) (appaccess.AccessManagement, error)
	CompanyApps(context.Context, uuid.UUID, uuid.UUID, string, string, int32, int32, bool) (appaccess.CompanyApps, error)
	ManagedApps(context.Context, uuid.UUID, uuid.UUID, *uuid.UUID, int32, int32) (appaccess.ManagedApps, error)
	AccessRequests(context.Context, uuid.UUID, uuid.UUID, bool, string, *uuid.UUID, int32, int32) (appaccess.AccessRequests, error)
	CreateAccessRequest(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, bool) (appaccess.AccessRequest, error)
	DecideAccessRequest(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, appaccess.AccessDecision, bool) (appaccess.AccessRequest, error)
	GrantSubjects(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, string, int32, int32) ([]appaccess.GrantSubject, error)
	ManagedGrants(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int32, int32, ...appaccess.GrantListFilter) ([]appaccess.Grant, error)
	CreateManagedGrant(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, appaccess.GrantInput, bool) (appaccess.Grant, error)
	UpdateManagedGrant(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, appaccess.GrantUpdate, int64, bool) (appaccess.Grant, error)
	RevokeManagedGrant(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, int64) (appaccess.Grant, error)
}

func (s apiServer) companyContext(ctx context.Context, org uuid.UUID) (context.Context, *authctx.Principal, appAccessCompanyPort, error) {
	p, err := requireVerifiedUser(ctx)
	if err != nil {
		return ctx, nil, nil, err
	}
	if p.UserID == uuid.Nil || p.IsMachine() || p.IsAgent() || p.SessionID == "" || p.AuthMethod == authctx.AuthBearer || p.AuthMethod == authctx.AuthMachine || p.AuthMethod == authctx.AuthAgent {
		return ctx, nil, nil, apierr.New(http.StatusForbidden, "human_session_required", "App Access requires a human browser session")
	}
	if _, ok := p.RoleIn(org); !ok {
		return ctx, nil, nil, apierr.NotFound("org_not_found", "organization not found")
	}
	svc, ok := s.appAccess.(appAccessCompanyPort)
	if !ok || svc == nil {
		return ctx, nil, nil, apierr.New(503, "app_access_unavailable", "App Access service is unavailable")
	}
	// Service methods rehydrate and lock active membership and exact app authority.
	return authctx.WithOrg(ctx, org), p, svc, nil
}
func (s apiServer) companyManagementContext(ctx context.Context, org uuid.UUID) (context.Context, *authctx.Principal, appAccessCompanyPort, error) {
	var err error
	ctx, _, err = s.appAccessPermissionContext(ctx, org, rbac.PermAppAccessManage, true)
	if err != nil {
		return ctx, nil, nil, err
	}
	ctx, _, err = s.appAccessPermissionContext(ctx, org, rbac.PermAppAccessGrant, true)
	if err != nil {
		return ctx, nil, nil, err
	}
	return s.companyContext(ctx, org)
}
func companyString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func appAccessPerson(p *appaccess.CompanyPerson) *api.AppAccessPerson {
	if p == nil {
		return nil
	}
	return &api.AppAccessPerson{Id: p.ID, Name: p.Name, Email: p.Email, Available: p.Available}
}
func appAccessManagement(out appaccess.AccessManagement) api.AppAccessAccessManagement {
	return api.AppAccessAccessManagement{AppId: out.AppID, Version: out.Version, CatalogVisible: out.CatalogVisible, AppAdminUserId: out.AppAdminUserID, AppAdmin: appAccessPerson(out.AppAdmin)}
}
func appAccessRequest(out appaccess.AccessRequest) api.AppAccessAccessRequest {
	return api.AppAccessAccessRequest{Id: out.ID, AppId: out.AppID, AppName: out.AppName, Requester: *appAccessPerson(&out.Requester), AppAdmin: appAccessPerson(out.AppAdmin), Status: api.AppAccessAccessRequestStatus(out.Status), Reason: out.Reason, DecisionReason: out.DecisionReason, Version: out.Version, CreatedAt: out.CreatedAt, DecidedAt: out.DecidedAt, DecidedBy: out.DecidedBy, GrantId: out.GrantID}
}
func (s apiServer) GetAppAccessManagement(ctx context.Context, req api.GetAppAccessManagementRequestObject) (api.GetAppAccessManagementResponseObject, error) {
	ctx, p, svc, err := s.companyManagementContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out, err := svc.GetAccessManagement(ctx, req.OrgId, p.UserID, req.AppId)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessManagement200JSONResponse{Body: appAccessManagement(out), Headers: api.GetAppAccessManagement200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) UpdateAppAccessManagement(ctx context.Context, req api.UpdateAppAccessManagementRequestObject) (api.UpdateAppAccessManagementResponseObject, error) {
	ctx, p, svc, err := s.companyManagementContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	out, err := svc.UpdateAccessManagement(ctx, req.OrgId, p.UserID, req.AppId, req.Body.CatalogVisible, req.Body.AppAdminUserId, req.Body.ExpectedVersion)
	if err != nil {
		return nil, err
	}
	return api.UpdateAppAccessManagement200JSONResponse{Body: appAccessManagement(out), Headers: api.UpdateAppAccessManagement200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) ListCompanyApps(ctx context.Context, req api.ListCompanyAppsRequestObject) (api.ListCompanyAppsResponseObject, error) {
	ctx, p, svc, err := s.companyContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	limit, offset, err := appSessionPagination(req.Params.Limit, req.Params.Offset)
	if err != nil {
		return nil, err
	}
	out, err := svc.CompanyApps(ctx, req.OrgId, p.UserID, p.SessionID, companyString(req.Params.Search), limit, offset, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	items := []api.AppAccessCompanyApp{}
	for _, row := range out.Items {
		item := api.AppAccessCompanyApp{Id: row.ID, Name: row.Name, Description: row.Description, Icon: row.Icon, IconDataUrl: row.IconDataURL, AppAdmin: appAccessPerson(row.AppAdmin), AccessGranted: row.AccessGranted, RequireMfa: row.RequireMFA, MfaRequired: row.MFARequired, MfaSetupRequired: row.MFASetupRequired, MfaFreshnessSeconds: appaccess.MFAFreshnessSeconds}
		if row.AccessGranted && row.LaunchURL != "" {
			url := row.LaunchURL
			item.LaunchUrl = &url
		}
		if row.LatestRequest != nil {
			request := appAccessRequest(*row.LatestRequest)
			item.LatestRequest = &request
		}
		items = append(items, item)
	}
	return api.ListCompanyApps200JSONResponse{Body: api.AppAccessCompanyApps{Items: items, Availability: api.AppAccessCompanyAppsAvailability(out.Availability), Limit: int(limit), Offset: int(offset)}, Headers: api.ListCompanyApps200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) ListManagedAppAccessApps(ctx context.Context, req api.ListManagedAppAccessAppsRequestObject) (api.ListManagedAppAccessAppsResponseObject, error) {
	ctx, p, svc, err := s.companyContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	limit, offset, err := appSessionPagination(req.Params.Limit, req.Params.Offset)
	if err != nil {
		return nil, err
	}
	out, err := svc.ManagedApps(ctx, req.OrgId, p.UserID, req.Params.AppId, limit, offset)
	if err != nil {
		return nil, err
	}
	items := []api.AppAccessManagedApp{}
	for _, row := range out.Items {
		items = append(items, api.AppAccessManagedApp{Id: row.ID, Name: row.Name, Description: row.Description, Icon: row.Icon, IconDataUrl: row.IconDataURL, PendingCount: row.PendingCount})
	}
	return api.ListManagedAppAccessApps200JSONResponse{Body: api.AppAccessManagedApps{Items: items, CanViewApplications: out.CanViewApplications, CanManageGrants: out.CanManageGrants, Limit: int(limit), Offset: int(offset)}, Headers: api.ListManagedAppAccessApps200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) ListAppAccessRequests(ctx context.Context, req api.ListAppAccessRequestsRequestObject) (api.ListAppAccessRequestsResponseObject, error) {
	ctx, p, svc, err := s.companyContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	limit, offset, err := appSessionPagination(req.Params.Limit, req.Params.Offset)
	if err != nil {
		return nil, err
	}
	own, status := true, ""
	if req.Params.Scope != nil {
		scope := string(*req.Params.Scope)
		if scope != "mine" && scope != "managed" {
			return nil, apierr.BadRequest("invalid_scope", "select own or managed requests")
		}
		own = scope == "mine"
	}
	if req.Params.Status != nil {
		status = string(*req.Params.Status)
	}
	out, err := svc.AccessRequests(ctx, req.OrgId, p.UserID, own, status, req.Params.AppId, limit, offset)
	if err != nil {
		return nil, err
	}
	items := []api.AppAccessAccessRequest{}
	for _, row := range out.Items {
		items = append(items, appAccessRequest(row))
	}
	return api.ListAppAccessRequests200JSONResponse{Body: api.AppAccessAccessRequests{Items: items, PendingCount: out.PendingCount, Limit: int(limit), Offset: int(offset)}, Headers: api.ListAppAccessRequests200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) CreateAppAccessRequest(ctx context.Context, req api.CreateAppAccessRequestRequestObject) (api.CreateAppAccessRequestResponseObject, error) {
	ctx, p, svc, err := s.companyContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	out, err := svc.CreateAccessRequest(ctx, req.OrgId, p.UserID, req.AppId, companyString(req.Body.Reason), s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.CreateAppAccessRequest200JSONResponse{Body: appAccessRequest(out), Headers: api.CreateAppAccessRequest200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) DecideAppAccessRequest(ctx context.Context, req api.DecideAppAccessRequestRequestObject) (api.DecideAppAccessRequestResponseObject, error) {
	ctx, p, svc, err := s.companyContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	input := appaccess.AccessDecision{ExpectedVersion: req.Body.ExpectedVersion, Decision: string(req.Body.Decision), Reason: companyString(req.Body.Reason), ExpiresAt: req.Body.ExpiresAt}
	out, err := svc.DecideAccessRequest(ctx, req.OrgId, p.UserID, req.RequestId, input, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.DecideAppAccessRequest200JSONResponse{Body: appAccessRequest(out), Headers: api.DecideAppAccessRequest200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) ListAppAccessGrantSubjects(ctx context.Context, req api.ListAppAccessGrantSubjectsRequestObject) (api.ListAppAccessGrantSubjectsResponseObject, error) {
	ctx, p, svc, err := s.companyContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	limit, offset, err := appSessionPagination(req.Params.Limit, req.Params.Offset)
	if err != nil {
		return nil, err
	}
	out, err := svc.GrantSubjects(ctx, req.OrgId, p.UserID, req.AppId, string(req.Params.Kind), companyString(req.Params.Search), limit, offset)
	if err != nil {
		return nil, err
	}
	items := []api.AppAccessGrantSubject{}
	for _, row := range out {
		item := api.AppAccessGrantSubject{Id: row.ID, Name: row.Name, Kind: api.AppAccessSubjectKind(row.Kind)}
		if row.Kind == "user" {
			email := row.Email
			item.Email = &email
		}
		items = append(items, item)
	}
	return api.ListAppAccessGrantSubjects200JSONResponse{Body: api.AppAccessGrantSubjects{Items: items, Limit: int(limit), Offset: int(offset)}, Headers: api.ListAppAccessGrantSubjects200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) ListManagedAppAccessGrants(ctx context.Context, req api.ListManagedAppAccessGrantsRequestObject) (api.ListManagedAppAccessGrantsResponseObject, error) {
	ctx, p, svc, err := s.companyContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	limit, offset, err := appSessionPagination(req.Params.Limit, req.Params.Offset)
	if err != nil {
		return nil, err
	}
	filter := appaccess.GrantListFilter{}
	if req.Params.View != nil {
		filter.View = string(*req.Params.View)
	}
	if req.Params.Status != nil {
		filter.Status = string(*req.Params.Status)
	}
	if req.Params.Search != nil {
		filter.Search = *req.Params.Search
	}
	filter, err = appaccess.NormalizeGrantListFilter(filter)
	if err != nil {
		return nil, err
	}
	out, err := svc.ManagedGrants(ctx, req.OrgId, p.UserID, req.AppId, limit, offset, filter)
	if err != nil {
		return nil, err
	}
	items := []api.AppAccessGrant{}
	for _, row := range out {
		items = append(items, appAccessGrant(row))
	}
	return api.ListManagedAppAccessGrants200JSONResponse{Body: api.AppAccessGrantList{Items: items, Limit: int(limit), Offset: int(offset)}, Headers: api.ListManagedAppAccessGrants200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) CreateManagedAppAccessGrant(ctx context.Context, req api.CreateManagedAppAccessGrantRequestObject) (api.CreateManagedAppAccessGrantResponseObject, error) {
	ctx, p, svc, err := s.companyContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	input := appaccess.GrantInput{AppID: req.Body.AppId, SubjectKind: string(req.Body.SubjectKind), SubjectID: req.Body.SubjectId, Enabled: req.Body.Enabled, StartsAt: req.Body.StartsAt, ExpiresAt: req.Body.ExpiresAt}
	out, err := svc.CreateManagedGrant(ctx, req.OrgId, p.UserID, req.AppId, input, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.CreateManagedAppAccessGrant200JSONResponse{Body: appAccessGrant(out), Headers: api.CreateManagedAppAccessGrant200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) UpdateManagedAppAccessGrant(ctx context.Context, req api.UpdateManagedAppAccessGrantRequestObject) (api.UpdateManagedAppAccessGrantResponseObject, error) {
	ctx, p, svc, err := s.companyContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	input := appaccess.GrantUpdate{Enabled: req.Body.Enabled, StartsAt: req.Body.StartsAt, ExpiresAt: req.Body.ExpiresAt}
	out, err := svc.UpdateManagedGrant(ctx, req.OrgId, p.UserID, req.AppId, req.GrantId, input, req.Body.ExpectedVersion, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.UpdateManagedAppAccessGrant200JSONResponse{Body: appAccessGrant(out), Headers: api.UpdateManagedAppAccessGrant200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) RevokeManagedAppAccessGrant(ctx context.Context, req api.RevokeManagedAppAccessGrantRequestObject) (api.RevokeManagedAppAccessGrantResponseObject, error) {
	ctx, p, svc, err := s.companyContext(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	out, err := svc.RevokeManagedGrant(ctx, req.OrgId, p.UserID, req.AppId, req.GrantId, req.Body.ExpectedVersion)
	if err != nil {
		return nil, err
	}
	return api.RevokeManagedAppAccessGrant200JSONResponse{Body: appAccessGrant(out), Headers: api.RevokeManagedAppAccessGrant200ResponseHeaders{CacheControl: "no-store"}}, nil
}
