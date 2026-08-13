package http

import (
	"context"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/idpsyncspec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// idpSyncPort is the enterprise IdP-group-sync capability (S7.5.2). nil in the open build → every
// handler returns 403 edition_required (the established precedent). PollAll is the background
// poller's entry point (started only in the enterprise build).
type idpSyncPort interface {
	UpsertConfig(ctx context.Context, orgID uuid.UUID, provider string, in idpsyncspec.ConfigInput) (idpsyncspec.ConfigView, error)
	Health(ctx context.Context, orgID uuid.UUID, provider string) (idpsyncspec.HealthView, error)
	Trigger(ctx context.Context, orgID uuid.UUID, provider string) (idpsyncspec.HealthView, error)
	MapGroup(ctx context.Context, orgID uuid.UUID, provider string, in idpsyncspec.MapInput) (sqlc.UserGroup, error)
	UnmapGroup(ctx context.Context, orgID uuid.UUID, provider string, groupID uuid.UUID) error
	PollAll(ctx context.Context)
}

// PutIdpSyncConfig implements PUT /idp-sync/{provider}. Manage-level (a credential is a
// high-privilege object); authorize first (401-walk), then the edition gate.
func (s apiServer) PutIdpSyncConfig(ctx context.Context, req api.PutIdpSyncConfigRequestObject) (api.PutIdpSyncConfigResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.idpSync == nil {
		return nil, editionRequired()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	in := idpsyncspec.ConfigInput{
		ClientID:           req.Body.ClientId,
		ClientSecret:       req.Body.ClientSecret,
		ServiceAccountJSON: valueOrEmpty(req.Body.ServiceAccountJson),
		Enabled:            req.Body.Enabled == nil || *req.Body.Enabled, // default enabled
	}
	if req.Body.TenantId != nil {
		in.TenantID = *req.Body.TenantId
	}
	if req.Body.DelegatedAdminEmail != nil {
		in.DelegatedAdminEmail = string(*req.Body.DelegatedAdminEmail)
	}
	view, err := s.idpSync.UpsertConfig(ctx, req.OrgId, req.Provider, in)
	if err != nil {
		return nil, err
	}
	return api.PutIdpSyncConfig200JSONResponse{
		Body:    toAPIIdpSyncConfig(view),
		Headers: api.PutIdpSyncConfig200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func valueOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// GetIdpSyncHealth implements GET /idp-sync/{provider}/health (view-level).
func (s apiServer) GetIdpSyncHealth(ctx context.Context, req api.GetIdpSyncHealthRequestObject) (api.GetIdpSyncHealthResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if s.idpSync == nil {
		return nil, editionRequired()
	}
	h, err := s.idpSync.Health(ctx, req.OrgId, req.Provider)
	if err != nil {
		return nil, err
	}
	return api.GetIdpSyncHealth200JSONResponse{
		Body:    toAPIIdpSyncHealth(h),
		Headers: api.GetIdpSyncHealth200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// TriggerIdpSync implements POST /idp-sync/{provider}/trigger (manage-level; it mutates access).
func (s apiServer) TriggerIdpSync(ctx context.Context, req api.TriggerIdpSyncRequestObject) (api.TriggerIdpSyncResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.idpSync == nil {
		return nil, editionRequired()
	}
	h, err := s.idpSync.Trigger(ctx, req.OrgId, req.Provider)
	if err != nil {
		return nil, err
	}
	return api.TriggerIdpSync200JSONResponse{
		Body:    toAPIIdpSyncHealth(h),
		Headers: api.TriggerIdpSync200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// MapIdpGroup implements POST /idp-sync/{provider}/groups (manage-level).
func (s apiServer) MapIdpGroup(ctx context.Context, req api.MapIdpGroupRequestObject) (api.MapIdpGroupResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.idpSync == nil {
		return nil, editionRequired()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	in := idpsyncspec.MapInput{IdpGroupID: req.Body.IdpGroupId}
	if req.Body.Name != nil {
		in.Name = *req.Body.Name
	}
	if req.Body.GroupId != nil {
		gid := uuid.UUID(*req.Body.GroupId)
		in.GroupID = &gid
	}
	g, err := s.idpSync.MapGroup(ctx, req.OrgId, req.Provider, in)
	if err != nil {
		return nil, err
	}
	return api.MapIdpGroup200JSONResponse{
		Body:    toAPIGroup(g),
		Headers: api.MapIdpGroup200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// UnmapIdpGroup implements DELETE /idp-sync/{provider}/groups/{groupId} (manage-level).
func (s apiServer) UnmapIdpGroup(ctx context.Context, req api.UnmapIdpGroupRequestObject) (api.UnmapIdpGroupResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.idpSync == nil {
		return nil, editionRequired()
	}
	if err := s.idpSync.UnmapGroup(ctx, req.OrgId, req.Provider, uuid.UUID(req.GroupId)); err != nil {
		return nil, err
	}
	return api.UnmapIdpGroup204Response{
		Headers: api.UnmapIdpGroup204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func toAPIIdpSyncConfig(v idpsyncspec.ConfigView) api.IdpSyncConfig {
	out := api.IdpSyncConfig{
		Provider:   api.IdpSyncConfigProvider(v.Provider),
		ClientId:   v.ClientID,
		Enabled:    v.Enabled,
		LastSyncOk: v.LastSyncOk,
		SyncHealth: v.SyncHealth,
	}
	if v.SecretFingerprint != "" {
		out.SecretFingerprint = &v.SecretFingerprint
	}
	if v.TenantID != "" {
		out.TenantId = &v.TenantID
	}
	if v.DelegatedAdminEmail != "" {
		email := openapi_types.Email(v.DelegatedAdminEmail)
		out.DelegatedAdminEmail = &email
	}
	if v.LastSyncError != "" {
		out.LastSyncError = &v.LastSyncError
	}
	out.LastSyncAt = v.LastSyncAt
	return out
}

func toAPIIdpSyncHealth(v idpsyncspec.HealthView) api.IdpSyncHealth {
	out := api.IdpSyncHealth{
		Provider:   api.IdpSyncHealthProvider(v.Provider),
		SyncHealth: v.SyncHealth,
		LastSyncOk: v.LastSyncOk,
	}
	if v.LastSyncError != "" {
		out.LastSyncError = &v.LastSyncError
	}
	out.LastSyncAt = v.LastSyncAt
	return out
}
