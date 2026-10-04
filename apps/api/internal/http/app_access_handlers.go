package http

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func appAccessBodyLimitError(w http.ResponseWriter, r *http.Request, err error) bool {
	if !strings.Contains(r.URL.Path, "/app-access/") {
		return false
	}
	var limit *http.MaxBytesError
	if errors.As(err, &limit) {
		apierr.Write(w, r, apierr.New(http.StatusRequestEntityTooLarge, "request_body_too_large", "App Access metadata request exceeds 128 KiB"))
		return true
	}
	return false
}

// appAccessPort keeps HTTP authority testable without replacing production services.
type appAccessPort interface {
	GetSettings(context.Context, uuid.UUID) (appaccess.Settings, error)
	UpdateSettings(context.Context, uuid.UUID, uuid.UUID, bool, int64, bool) (appaccess.Settings, error)
	CreateDraft(context.Context, uuid.UUID, uuid.UUID, appaccess.DraftInput, bool) (appaccess.Application, error)
	UpdateDraft(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, appaccess.DraftInput, int64, bool) (appaccess.Application, error)
	GetApplication(context.Context, uuid.UUID, uuid.UUID) (appaccess.Application, error)
	ListApplications(context.Context, uuid.UUID, string, int32, int32, ...string) ([]appaccess.Application, error)
	GetRevision(context.Context, uuid.UUID, uuid.UUID, int64) (appaccess.Revision, error)
	ListGrants(context.Context, uuid.UUID, *uuid.UUID, string, *uuid.UUID, int32, int32, ...appaccess.GrantListFilter) ([]appaccess.Grant, error)
	CreateGrant(context.Context, uuid.UUID, uuid.UUID, appaccess.GrantInput, bool) (appaccess.Grant, error)
	UpdateGrant(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, appaccess.GrantUpdate, int64, bool) (appaccess.Grant, error)
	RevokeGrant(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64) (appaccess.Grant, error)
	EffectiveAccess(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, bool) (appaccess.Preview, error)
	RevokeImpact(context.Context, uuid.UUID, uuid.UUID) (appaccess.GrantImpact, error)
}

func (s apiServer) appAccessContext(ctx context.Context, org uuid.UUID, write bool) (context.Context, uuid.UUID, error) {
	perm := rbac.PermAppAccessView
	if write {
		perm = rbac.PermAppAccessManage
	}
	return s.appAccessPermissionContext(ctx, org, perm, write)
}
func (s apiServer) appAccessPermissionContext(ctx context.Context, org uuid.UUID, perm rbac.Permission, write bool) (context.Context, uuid.UUID, error) {
	scoped, err := authorize(ctx, org, perm)
	if err != nil {
		return ctx, uuid.Nil, err
	}
	p, _ := authctx.PrincipalFrom(scoped)
	// App Access v1 is a human browser workspace, including configuration mutation.
	// Tokens and synthetic machine/agent identities cannot inherit human authority.
	if p.UserID == uuid.Nil || p.IsMachine() || p.IsAgent() || p.AuthMethod == authctx.AuthBearer || p.AuthMethod == authctx.AuthMachine || p.AuthMethod == authctx.AuthAgent {
		return scoped, uuid.Nil, apierr.New(http.StatusForbidden, "human_session_required", "App Access requires a human browser session")
	}
	if write && p.SessionID == "" {
		return scoped, uuid.Nil, apierr.New(http.StatusForbidden, "human_session_required", "App Access changes require a human browser session")
	}
	return scoped, p.UserID, nil
}
func (s apiServer) appAccessService() (appAccessPort, error) {
	if s.appAccess == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "app_access_unavailable", "App Access service is unavailable")
	}
	return s.appAccess, nil
}
func (s apiServer) appAccessEntitled() bool {
	return licenceOrCommunity(s.licence).Has(licence.FeatAppAccess, time.Now())
}
func (s apiServer) requireAppAccessEntitlement() error {
	if !s.appAccessEntitled() {
		return apierr.New(http.StatusForbidden, "entitlement_required", "App Access requires an entitled license")
	}
	return nil
}
func (s apiServer) appAccessSettings(r appaccess.Settings) api.AppAccessSettings {
	return api.AppAccessSettings{Enabled: r.Enabled, Version: r.Version, BaseDomain: r.BaseDomain, DomainReady: r.DomainReady, EntitlementAvailable: s.appAccessEntitled()}
}
func appAccessRevision(r appaccess.Revision) api.AppAccessRevision {
	return api.AppAccessRevision{Revision: r.Revision, Digest: r.Digest, CreatedAt: r.CreatedAt, Name: r.Name, Description: r.Description, Icon: api.AppAccessRevisionIcon(r.Icon), IconDataUrl: &r.IconDataURL, OriginUrl: r.OriginURL, GatewayId: r.GatewayID, PublicHostname: r.PublicHostname, IdleTimeoutSeconds: int(r.IdleTimeoutSeconds), AbsoluteTimeoutSeconds: int(r.AbsoluteTimeoutSeconds), AllowedDestinationCidrs: append([]string{}, r.AllowedDestinationCIDRs...), OriginCaDigest: r.OriginCADigest}
}
func appAccessApplication(r appaccess.Application) api.AppAccessApplication {
	return api.AppAccessApplication{RequireMfa: r.RequireMFA, MfaFreshnessSeconds: appaccess.MFAFreshnessSeconds, Id: r.ID, OrgId: r.OrgID, Version: r.Version, DraftRevision: r.DraftRevision, State: api.AppAccessApplicationState(r.State), Draft: appAccessRevision(r.Draft), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, ConnectorStatus: api.AppAccessApplicationConnectorStatus(r.ConnectorStatus), PublicationState: api.AppAccessApplicationPublicationState(r.PublicationState), ActiveRevision: r.ActiveRevision}
}
func appAccessTimeouts(idle, absolute int) error {
	if idle < 60 || idle > 1800 || absolute < 300 || absolute > 28800 || idle > absolute {
		return apierr.BadRequest("invalid_application", "invalid session limits")
	}
	return nil
}
func appAccessInput(r api.AppAccessDraftInput) appaccess.DraftInput {
	input := appaccess.DraftInput{Name: r.Name, Description: r.Description, Icon: string(r.Icon), OriginURL: r.OriginUrl, GatewayID: r.GatewayId, PublicHostname: r.PublicHostname, IdleTimeoutSeconds: int32(r.IdleTimeoutSeconds), AbsoluteTimeoutSeconds: int32(r.AbsoluteTimeoutSeconds)}
	input.IconDataURLSet = r.IconDataUrl != nil
	if r.IconDataUrl != nil {
		input.IconDataURL = *r.IconDataUrl
	}
	appAccessOriginPolicy(&input, r.AllowedDestinationCidrs, r.OriginCaPem)
	return input
}
func appAccessOriginPolicy(input *appaccess.DraftInput, cidrs *[]string, ca *string) {
	input.AllowedDestinationCIDRsSet = cidrs != nil
	if cidrs != nil {
		input.AllowedDestinationCIDRs = append([]string{}, (*cidrs)...)
	}
	input.OriginCAPEMSet = ca != nil
	if ca != nil {
		input.OriginCAPEM = *ca
	}
}
func (s apiServer) GetAppAccessSettings(ctx context.Context, req api.GetAppAccessSettingsRequestObject) (api.GetAppAccessSettingsResponseObject, error) {
	ctx, _, err := s.appAccessContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	out, err := svc.GetSettings(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessSettings200JSONResponse{Body: s.appAccessSettings(out), Headers: api.GetAppAccessSettings200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) UpdateAppAccessSettings(ctx context.Context, req api.UpdateAppAccessSettingsRequestObject) (api.UpdateAppAccessSettingsResponseObject, error) {
	ctx, actor, err := s.appAccessContext(ctx, req.OrgId, true)
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
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	out, err := svc.UpdateSettings(ctx, req.OrgId, actor, req.Body.Enabled, req.Body.ExpectedVersion, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.UpdateAppAccessSettings200JSONResponse{Body: s.appAccessSettings(out), Headers: api.UpdateAppAccessSettings200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) ListAppAccessApplications(ctx context.Context, req api.ListAppAccessApplicationsRequestObject) (api.ListAppAccessApplicationsResponseObject, error) {
	ctx, _, err := s.appAccessContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	search := ""
	limit, offset := 50, 0
	if req.Params.Search != nil {
		search = *req.Params.Search
	}
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if req.Params.Offset != nil {
		offset = *req.Params.Offset
	}
	if limit < 1 || limit > 100 || offset < 0 || offset > 10000 || !utf8.ValidString(search) || utf8.RuneCountInString(search) > 100 {
		return nil, apierr.BadRequest("invalid_pagination", "invalid pagination or search")
	}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	filter := ""
	if req.Params.PublicationState != nil {
		filter = string(*req.Params.PublicationState)
	}
	out, err := svc.ListApplications(ctx, req.OrgId, search, int32(limit), int32(offset), filter)
	if err != nil {
		return nil, err
	}
	items := make([]api.AppAccessApplication, len(out))
	for i, r := range out {
		items[i] = appAccessApplication(r)
	}
	return api.ListAppAccessApplications200JSONResponse{Body: api.AppAccessApplicationList{Items: items, Limit: limit, Offset: offset}, Headers: api.ListAppAccessApplications200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) CreateAppAccessApplication(ctx context.Context, req api.CreateAppAccessApplicationRequestObject) (api.CreateAppAccessApplicationResponseObject, error) {
	ctx, actor, err := s.appAccessContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	if err = s.requireAppAccessEntitlement(); err != nil {
		return nil, err
	}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	if err = appAccessTimeouts(req.Body.IdleTimeoutSeconds, req.Body.AbsoluteTimeoutSeconds); err != nil {
		return nil, err
	}
	out, err := svc.CreateDraft(ctx, req.OrgId, actor, appAccessInput(*req.Body), s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.CreateAppAccessApplication201JSONResponse{Body: appAccessApplication(out), Headers: api.CreateAppAccessApplication201ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) GetAppAccessApplication(ctx context.Context, req api.GetAppAccessApplicationRequestObject) (api.GetAppAccessApplicationResponseObject, error) {
	ctx, _, err := s.appAccessContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	out, err := svc.GetApplication(ctx, req.OrgId, req.AppId)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessApplication200JSONResponse{Body: appAccessApplication(out), Headers: api.GetAppAccessApplication200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) UpdateAppAccessApplication(ctx context.Context, req api.UpdateAppAccessApplicationRequestObject) (api.UpdateAppAccessApplicationResponseObject, error) {
	ctx, actor, err := s.appAccessContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	if req.Body.ExpectedVersion < 1 {
		return nil, apierr.BadRequest("invalid_version", "expected version must be positive")
	}
	if err = s.requireAppAccessEntitlement(); err != nil {
		return nil, err
	}
	r := req.Body
	if err = appAccessTimeouts(r.IdleTimeoutSeconds, r.AbsoluteTimeoutSeconds); err != nil {
		return nil, err
	}
	input := appaccess.DraftInput{Name: r.Name, Description: r.Description, Icon: string(r.Icon), OriginURL: r.OriginUrl, GatewayID: r.GatewayId, PublicHostname: r.PublicHostname, IdleTimeoutSeconds: int32(r.IdleTimeoutSeconds), AbsoluteTimeoutSeconds: int32(r.AbsoluteTimeoutSeconds)}
	input.IconDataURLSet = r.IconDataUrl != nil
	if r.IconDataUrl != nil {
		input.IconDataURL = *r.IconDataUrl
	}
	appAccessOriginPolicy(&input, r.AllowedDestinationCidrs, r.OriginCaPem)
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	out, err := svc.UpdateDraft(ctx, req.OrgId, actor, req.AppId, input, r.ExpectedVersion, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.UpdateAppAccessApplication200JSONResponse{Body: appAccessApplication(out), Headers: api.UpdateAppAccessApplication200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) GetAppAccessRevision(ctx context.Context, req api.GetAppAccessRevisionRequestObject) (api.GetAppAccessRevisionResponseObject, error) {
	ctx, _, err := s.appAccessContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	if req.Revision < 1 {
		return nil, apierr.BadRequest("invalid_revision", "revision must be positive")
	}
	svc, err := s.appAccessService()
	if err != nil {
		return nil, err
	}
	out, err := svc.GetRevision(ctx, req.OrgId, req.AppId, req.Revision)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessRevision200JSONResponse{Body: appAccessRevision(out), Headers: api.GetAppAccessRevision200ResponseHeaders{CacheControl: "no-store"}}, nil
}
