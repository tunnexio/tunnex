package http

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type agentAccessPort interface {
	Setting(context.Context, uuid.UUID) (agentaccess.Setting, error)
	SetEnabled(context.Context, uuid.UUID, uuid.UUID, bool) (bool, error)
	Create(context.Context, uuid.UUID, uuid.UUID, agentaccess.CreateInput) (sqlc.AgentAccessRequest, bool, error)
	Approve(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (sqlc.AgentAccessRequest, bool, error)
	Reject(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, agentaccess.DecisionInput) (sqlc.AgentAccessRequest, bool, error)
	Cancel(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (sqlc.AgentAccessRequest, bool, error)
	Revoke(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (sqlc.AgentAccessRequest, bool, error)
	Get(context.Context, uuid.UUID, uuid.UUID) (sqlc.AgentAccessRequest, []sqlc.AgentAccessRequestEvent, error)
	List(context.Context, uuid.UUID, *string, *uuid.UUID, *time.Time, *uuid.UUID, int32) ([]sqlc.AgentAccessRequest, error)
	ListForActor(context.Context, uuid.UUID, uuid.UUID, *string, *uuid.UUID, *time.Time, *uuid.UUID, int32) ([]sqlc.AgentAccessRequest, error)
	Describe(context.Context, sqlc.AgentAccessRequest) (string, string, error)
	ListDestinations(context.Context, uuid.UUID) ([]agentaccess.NamedDestination, error)
}

func (s apiServer) ListAgentAccessDestinations(ctx context.Context, req api.ListAgentAccessDestinationsRequestObject) (api.ListAgentAccessDestinationsResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(req.OrgId)
	if !rbac.Can(role, rbac.PermAgentAccessRequest) {
		if s.system == nil {
			return nil, apierr.Internal()
		}
		n, err := s.system.CountAgentJITRequestAuthorities(ctx, sqlc.CountAgentJITRequestAuthoritiesParams{OrgID: req.OrgId, UserID: p.UserID})
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, apierr.New(403, "forbidden", "you may not access agent requests")
		}
	}
	if err := s.requireAgentAccessCapability(); err != nil {
		return nil, err
	}
	rows, err := s.agentAccess.ListDestinations(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.AgentAccessDestination, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.AgentAccessDestination{Kind: api.AgentAccessDestinationKind(row.Kind), Id: row.ID, Name: row.Name})
	}
	return api.ListAgentAccessDestinations200JSONResponse{Body: out, Headers: api.ListAgentAccessDestinations200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func agentAccessFeatureRequired() error {
	return apierr.Forbidden("feature_required", "This capability is not included in your current plan.")
}

func (s apiServer) requireAgentAccessCapability() error {
	if s.licence == nil || !s.licence.Has(licence.FeatAgentJITAccess, time.Now()) {
		return agentAccessFeatureRequired()
	}
	if s.agentAccess == nil {
		return apierr.New(503, "agent_access_unavailable", "agent access service is unavailable")
	}
	return nil
}

func (s apiServer) GetOrganizationAgentJITAccessSetting(ctx context.Context, req api.GetOrganizationAgentJITAccessSettingRequestObject) (api.GetOrganizationAgentJITAccessSettingResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentAccessApprove)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentAccessCapability(); err != nil {
		return nil, err
	}
	setting, err := s.agentAccess.Setting(ctx, req.OrgId)
	if err != nil {
		return nil, mapAgentAccessError(err)
	}
	return api.GetOrganizationAgentJITAccessSetting200JSONResponse{Body: toAPIJITSetting(setting), Headers: api.GetOrganizationAgentJITAccessSetting200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) SetOrganizationAgentJITAccessEnabled(ctx context.Context, req api.SetOrganizationAgentJITAccessEnabledRequestObject) (api.SetOrganizationAgentJITAccessEnabledResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentAccessApprove)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentAccessCapability(); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if _, err := s.agentAccess.SetEnabled(ctx, req.OrgId, actorID(ctx), req.Body.Enabled); err != nil {
		return nil, mapAgentAccessError(err)
	}
	setting, err := s.agentAccess.Setting(ctx, req.OrgId)
	if err != nil {
		return nil, mapAgentAccessError(err)
	}
	return api.SetOrganizationAgentJITAccessEnabled200JSONResponse{Body: toAPIJITSetting(setting), Headers: api.SetOrganizationAgentJITAccessEnabled200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) CreateAgentAccessRequest(ctx context.Context, req api.CreateAgentAccessRequestRequestObject) (api.CreateAgentAccessRequestResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.Body.DeviceId, rbac.PermAgentAccessRequest); err != nil {
		return nil, err
	}
	if err := s.requireAgentAccessCapability(); err != nil {
		return nil, err
	}
	row, replay, err := s.agentAccess.Create(ctx, req.OrgId, actorID(ctx), agentaccess.CreateInput{
		DeviceID:    req.Body.DeviceId,
		Destination: agentaccess.Destination{Kind: string(req.Body.DestinationKind), ID: req.Body.DestinationId},
		Reason:      req.Body.Reason, Duration: time.Duration(req.Body.DurationSeconds) * time.Second,
		IdempotencyKey: req.Body.IdempotencyKey,
	})
	if err != nil {
		return nil, mapAgentAccessError(err)
	}
	out, err := s.toAPIAgentAccessRequest(ctx, row)
	if err != nil {
		return nil, err
	}
	if replay {
		return api.CreateAgentAccessRequest200JSONResponse{Body: out, Headers: api.CreateAgentAccessRequest200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
	}
	return api.CreateAgentAccessRequest201JSONResponse{Body: out, Headers: api.CreateAgentAccessRequest201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ListAgentAccessRequests(ctx context.Context, req api.ListAgentAccessRequestsRequestObject) (api.ListAgentAccessRequestsResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	if (req.Params.BeforeRequestedAt == nil) != (req.Params.BeforeId == nil) {
		return nil, apierr.BadRequest("invalid_request", "before_requested_at and before_id must be supplied together")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(req.OrgId)
	global := rbac.Can(role, rbac.PermAgentAccessRequest)
	if !global {
		if s.system == nil {
			return nil, apierr.Internal()
		}
		n, err := s.system.CountAgentJITRequestAuthorities(ctx, sqlc.CountAgentJITRequestAuthoritiesParams{OrgID: req.OrgId, UserID: p.UserID})
		if err != nil {
			return nil, err
		}
		if n == 0 {
			own, err := s.system.CountAgentAccessRequestsRequestedByActor(ctx, sqlc.CountAgentAccessRequestsRequestedByActorParams{OrgID: req.OrgId, RequestedByUserID: p.UserID})
			if err != nil {
				return nil, err
			}
			if own == 0 {
				return nil, apierr.New(403, "forbidden", "you may not access agent requests")
			}
		}
	}
	if req.Params.DeviceId != nil {
		if err := s.requireAgentPermission(ctx, req.OrgId, *req.Params.DeviceId, rbac.PermAgentAccessRequest); err != nil {
			return nil, err
		}
	}
	if err := s.requireAgentAccessCapability(); err != nil {
		return nil, err
	}
	pageSize := int32(50)
	if req.Params.PageSize != nil {
		pageSize = int32(*req.Params.PageSize)
	}
	state := (*string)(nil)
	if req.Params.State != nil {
		v := string(*req.Params.State)
		state = &v
	}
	limit := pageSize + 1
	var rows []sqlc.AgentAccessRequest
	if global {
		rows, err = s.agentAccess.List(ctx, req.OrgId, state, req.Params.DeviceId, req.Params.BeforeRequestedAt, req.Params.BeforeId, limit)
	} else {
		rows, err = s.agentAccess.ListForActor(ctx, req.OrgId, p.UserID, state, req.Params.DeviceId, req.Params.BeforeRequestedAt, req.Params.BeforeId, limit)
	}
	if err != nil {
		return nil, mapAgentAccessError(err)
	}
	page := api.AgentAccessRequestPage{Items: make([]api.AgentAccessRequest, 0, min(len(rows), int(pageSize)))}
	if len(rows) > int(pageSize) {
		cursor := rows[pageSize-1]
		page.NextBeforeRequestedAt, page.NextBeforeId = &cursor.RequestedAt, &cursor.ID
		rows = rows[:pageSize]
	}
	for _, row := range rows {
		item, err := s.toAPIAgentAccessRequest(ctx, row)
		if err != nil {
			return nil, err
		}
		page.Items = append(page.Items, item)
	}
	return api.ListAgentAccessRequests200JSONResponse{Body: page, Headers: api.ListAgentAccessRequests200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) GetAgentAccessRequest(ctx context.Context, req api.GetAgentAccessRequestRequestObject) (api.GetAgentAccessRequestResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	row, allowed, err := s.authorizeAgentAccessRequest(ctx, req.OrgId, req.RequestId, true)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, apierr.New(403, "forbidden", "you may not access agent requests")
	}
	if err := s.requireAgentAccessCapability(); err != nil {
		return nil, err
	}
	row, events, err := s.agentAccess.Get(ctx, req.OrgId, req.RequestId)
	if err != nil {
		return nil, mapAgentAccessError(err)
	}
	out, err := s.toAPIAgentAccessRequest(ctx, row)
	if err != nil {
		return nil, err
	}
	return api.GetAgentAccessRequest200JSONResponse{Body: api.AgentAccessRequestDetail{Request: out, Events: toAPIAgentAccessEvents(events)}, Headers: api.GetAgentAccessRequest200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ApproveAgentAccessRequest(ctx context.Context, req api.ApproveAgentAccessRequestRequestObject) (api.ApproveAgentAccessRequestResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentAccessApprove)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentAccessCapability(); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	row, _, err := s.agentAccess.Approve(ctx, req.OrgId, req.RequestId, actorID(ctx), req.Body.IdempotencyKey)
	if err != nil {
		return nil, mapAgentAccessError(err)
	}
	out, err := s.toAPIAgentAccessRequest(ctx, row)
	return api.ApproveAgentAccessRequest200JSONResponse{Body: out, Headers: api.ApproveAgentAccessRequest200ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

func (s apiServer) RejectAgentAccessRequest(ctx context.Context, req api.RejectAgentAccessRequestRequestObject) (api.RejectAgentAccessRequestResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentAccessApprove)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentAccessCapability(); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	row, _, err := s.agentAccess.Reject(ctx, req.OrgId, req.RequestId, actorID(ctx), agentaccess.DecisionInput{IdempotencyKey: req.Body.IdempotencyKey, Reason: req.Body.Reason})
	if err != nil {
		return nil, mapAgentAccessError(err)
	}
	out, err := s.toAPIAgentAccessRequest(ctx, row)
	return api.RejectAgentAccessRequest200JSONResponse{Body: out, Headers: api.RejectAgentAccessRequest200ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

func (s apiServer) CancelAgentAccessRequest(ctx context.Context, req api.CancelAgentAccessRequestRequestObject) (api.CancelAgentAccessRequestResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	row, allowed, err := s.authorizeAgentAccessRequest(ctx, req.OrgId, req.RequestId, true)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, apierr.New(403, "forbidden", "you may not access agent requests")
	}
	if err := s.requireAgentAccessCapability(); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	row, _, err = s.agentAccess.Cancel(ctx, req.OrgId, row.ID, actorID(ctx), req.Body.IdempotencyKey)
	if err != nil {
		return nil, mapAgentAccessError(err)
	}
	out, err := s.toAPIAgentAccessRequest(ctx, row)
	return api.CancelAgentAccessRequest200JSONResponse{Body: out, Headers: api.CancelAgentAccessRequest200ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

func (s apiServer) RevokeAgentAccessRequest(ctx context.Context, req api.RevokeAgentAccessRequestRequestObject) (api.RevokeAgentAccessRequestResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentAccessApprove)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentAccessCapability(); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	row, _, err := s.agentAccess.Revoke(ctx, req.OrgId, req.RequestId, actorID(ctx), req.Body.IdempotencyKey)
	if err != nil {
		return nil, mapAgentAccessError(err)
	}
	out, err := s.toAPIAgentAccessRequest(ctx, row)
	return api.RevokeAgentAccessRequest200JSONResponse{Body: out, Headers: api.RevokeAgentAccessRequest200ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

func (s apiServer) authorizeAgentAccessRequest(ctx context.Context, orgID, requestID uuid.UUID, allowRequester bool) (sqlc.AgentAccessRequest, bool, error) {
	if s.system == nil {
		return sqlc.AgentAccessRequest{}, false, apierr.Internal()
	}
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(orgID)
	if rbac.Can(role, rbac.PermAgentAccessApprove) || rbac.Can(role, rbac.PermAgentAccessRequest) {
		row, err := s.system.GetAgentAccessRequest(ctx, sqlc.GetAgentAccessRequestParams{ID: requestID, OrgID: orgID})
		return row, true, mapAgentAccessLookup(err)
	}
	row, err := s.system.GetAgentAccessRequest(ctx, sqlc.GetAgentAccessRequestParams{ID: requestID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.AgentAccessRequest{}, false, nil
	}
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if allowRequester && row.RequestedByUserID == p.UserID {
		return row, true, nil
	}
	if err := s.requireAgentPermission(ctx, orgID, row.DeviceID, rbac.PermAgentAccessRequest); err != nil {
		return sqlc.AgentAccessRequest{}, false, nil
	}
	return row, true, nil
}

func (s apiServer) toAPIAgentAccessRequest(ctx context.Context, row sqlc.AgentAccessRequest) (api.AgentAccessRequest, error) {
	agentName, destinationName, err := s.agentAccess.Describe(ctx, row)
	if err != nil {
		return api.AgentAccessRequest{}, mapAgentAccessError(err)
	}
	destination := agentaccess.Destination{Kind: row.DstKind}
	switch row.DstKind {
	case "resource":
		destination.ID = row.DstResourceID.Bytes
	case "group":
		destination.ID = row.DstGroupID.Bytes
	case "site":
		destination.ID = row.DstSiteID.Bytes
	default:
		destination.ID = row.DstK8sServiceID.Bytes
	}
	out := api.AgentAccessRequest{
		Id: row.ID, OrgId: row.OrgID, DeviceId: row.DeviceID, AgentName: agentName,
		DestinationKind: api.AgentAccessDestinationKind(row.DstKind), DestinationId: destination.ID, DestinationName: destinationName,
		Reason: row.Reason, RequestedDurationSeconds: int(row.RequestedDurationSeconds), State: api.AgentAccessRequestState(row.State),
		RequestedByUserId: row.RequestedByUserID, RequestedAt: row.RequestedAt, UpdatedAt: row.UpdatedAt,
		RejectionReason: row.RejectionReason,
	}
	setUUID := func(v uuid.UUID) *uuid.UUID { return &v }
	setTime := func(v time.Time) *time.Time { return &v }
	if row.ApprovedByUserID.Valid {
		out.ApprovedByUserId = setUUID(row.ApprovedByUserID.Bytes)
	}
	if row.ApprovedAt.Valid {
		out.ApprovedAt = setTime(row.ApprovedAt.Time)
	}
	if row.ApprovedExpiresAt.Valid {
		out.ApprovedExpiresAt = setTime(row.ApprovedExpiresAt.Time)
	}
	if row.RejectedByUserID.Valid {
		out.RejectedByUserId = setUUID(row.RejectedByUserID.Bytes)
	}
	if row.RejectedAt.Valid {
		out.RejectedAt = setTime(row.RejectedAt.Time)
	}
	if row.CancelledByUserID.Valid {
		out.CancelledByUserId = setUUID(row.CancelledByUserID.Bytes)
	}
	if row.CancelledAt.Valid {
		out.CancelledAt = setTime(row.CancelledAt.Time)
	}
	if row.RevokedByUserID.Valid {
		out.RevokedByUserId = setUUID(row.RevokedByUserID.Bytes)
	}
	if row.RevokedAt.Valid {
		out.RevokedAt = setTime(row.RevokedAt.Time)
	}
	return out, nil
}

func toAPIAgentAccessEvents(rows []sqlc.AgentAccessRequestEvent) []api.AgentAccessRequestEvent {
	out := make([]api.AgentAccessRequestEvent, 0, len(rows))
	for _, row := range rows {
		event := api.AgentAccessRequestEvent{Id: row.ID, State: api.AgentAccessRequestState(row.State), CreatedAt: row.CreatedAt, ActorSystem: row.ActorSystem}
		if row.ActorUserID.Valid {
			id := uuid.UUID(row.ActorUserID.Bytes)
			event.ActorUserId = &id
		}
		out = append(out, event)
	}
	return out
}

func toAPIJITSetting(setting agentaccess.Setting) api.AgentJITAccessSetting {
	return api.AgentJITAccessSetting{Enabled: setting.Enabled, PendingRequests: int(setting.Pending), ApprovedRequests: int(setting.Approved)}
}

func mapAgentAccessLookup(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.NotFound("agent_access_request_not_found", "agent access request not found")
	}
	return err
}

func mapAgentAccessError(err error) error {
	switch {
	case errors.Is(err, agentaccess.ErrInvalid):
		return apierr.BadRequest("invalid_agent_access_request", "agent access request is invalid")
	case errors.Is(err, agentaccess.ErrNotFound):
		return apierr.NotFound("agent_access_request_not_found", "agent access request not found")
	case errors.Is(err, agentaccess.ErrConflict):
		return apierr.New(409, "agent_access_request_conflict", "agent access request conflicts with current state")
	case errors.Is(err, agentaccess.ErrDisabled):
		return apierr.Forbidden("opt_in_required", "enable just-in-time agent access in organization settings first")
	default:
		return err
	}
}
