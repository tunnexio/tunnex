package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"time"
)

type appEventHTTPPort interface {
	ListEvents(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID, *uuid.UUID, *time.Time, *uuid.UUID, int32) (appaccess.EventHistory, error)
}
type appImpactHTTPPort interface {
	PublicationImpact(context.Context, uuid.UUID, uuid.UUID) (appaccess.PublicationImpact, error)
}

func optionalEventID(id pgtype.UUID) *uuid.UUID {
	if !id.Valid {
		return nil
	}
	value := uuid.UUID(id.Bytes)
	return &value
}
func (s apiServer) ListAppAccessEvents(ctx context.Context, req api.ListAppAccessEventsRequestObject) (api.ListAppAccessEventsResponseObject, error) {
	ctx, _, err := s.appAccessPermissionContext(ctx, req.OrgId, rbac.PermAppAccessEventView, false)
	if err != nil {
		return nil, err
	}
	p, ok := s.appAccess.(appEventHTTPPort)
	if !ok {
		return nil, apierr.New(503, "app_access_unavailable", "App Access service unavailable")
	}
	limit := 50
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if limit < 1 || limit > 100 {
		return nil, apierr.BadRequest("invalid_pagination", "invalid event limit")
	}
	if (req.Params.BeforeTime == nil) != (req.Params.BeforeId == nil) {
		return nil, apierr.BadRequest("invalid_pagination", "event cursor requires timestamp and identifier")
	}
	history, err := p.ListEvents(ctx, req.OrgId, req.Params.AppId, req.Params.UserId, req.Params.SessionId, req.Params.BeforeTime, req.Params.BeforeId, int32(limit))
	if err != nil {
		return nil, err
	}
	out := api.AppAccessEvents{Items: []api.AppAccessEvent{}, Telemetry: api.AppAccessEventTelemetry{Available: history.TelemetryAvailable, Emitted: int64(history.Emitted), Dropped: int64(history.Dropped), StorageFailures: int64(history.StorageFailures)}}
	for _, e := range history.Items {
		out.Items = append(out.Items, api.AppAccessEvent{Id: e.ID, AppId: e.AppID, InstallationGeneration: e.InstallationGeneration, CreatedAt: e.CreatedAt, Revision: e.Revision, ServingGeneration: optionalEventID(e.ServingGeneration), Kind: api.AppAccessEventKind(e.EventKind), Outcome: api.AppAccessEventOutcome(e.Outcome), Reason: api.AppAccessEventReason(e.Reason), UserId: optionalEventID(e.UserID), GatewayId: optionalEventID(e.GatewayID), ProxyId: optionalEventID(e.ProxyID), SessionId: optionalEventID(e.SessionID), StreamId: optionalEventID(e.StreamID)})
	}
	if len(out.Items) == limit {
		last := out.Items[len(out.Items)-1]
		out.NextCursor = &api.AppAccessEventCursor{BeforeId: last.Id, BeforeTime: last.CreatedAt}
	}
	return api.ListAppAccessEvents200JSONResponse(out), nil
}
func (s apiServer) GetAppAccessPublicationImpact(ctx context.Context, req api.GetAppAccessPublicationImpactRequestObject) (api.GetAppAccessPublicationImpactResponseObject, error) {
	ctx, _, err := s.appAccessPermissionContext(ctx, req.OrgId, rbac.PermAppAccessManage, false)
	if err != nil {
		return nil, err
	}
	p, ok := s.appAccess.(appImpactHTTPPort)
	if !ok {
		return nil, apierr.New(503, "app_impact_unavailable", "application impact unavailable")
	}
	out, err := p.PublicationImpact(ctx, req.OrgId, req.AppId)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessPublicationImpact200JSONResponse{EvaluatedAt: out.EvaluatedAt, ApplicationVersion: out.ApplicationVersion, AuthorityVersion: out.AuthorityVersion, MatchingUserCount: out.MatchingUserCount, MatchingUserCountIsLowerBound: out.MatchingUserCountIsLowerBound, LiveAppSessionCount: out.LiveAppSessionCount, LiveAppSessionCountIsLowerBound: out.LiveAppSessionCountIsLowerBound, SessionImpactAvailable: out.SessionImpactAvailable}, nil
}
