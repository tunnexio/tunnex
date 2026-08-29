package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) GetOrganizationAlertingSetting(ctx context.Context, req api.GetOrganizationAlertingSettingRequestObject) (api.GetOrganizationAlertingSettingResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage); err != nil {
		return nil, err
	}
	org, err := s.orgs.GetOrganization(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetOrganizationAlertingSetting200JSONResponse{Body: api.AlertingSetting{Enabled: org.AlertingEnabled}, Headers: api.GetOrganizationAlertingSetting200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) SetOrganizationAlertingEnabled(ctx context.Context, req api.SetOrganizationAlertingEnabledRequestObject) (api.SetOrganizationAlertingEnabledResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	org, err := s.orgs.SetAlertingEnabled(ctx, req.OrgId, req.Body.Enabled)
	if err != nil {
		return nil, err
	}
	return api.SetOrganizationAlertingEnabled200JSONResponse{Body: api.AlertingSetting{Enabled: org.AlertingEnabled}, Headers: api.SetOrganizationAlertingEnabled200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) ListAlertDestinations(ctx context.Context, req api.ListAlertDestinationsRequestObject) (api.ListAlertDestinationsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage); err != nil {
		return nil, err
	}
	if s.alertConfig == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "alerting_unavailable", "alerting configuration is temporarily unavailable")
	}
	rows, err := s.alertConfig.List(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.AlertDestination, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAPIAlertDestination(row))
	}
	return api.ListAlertDestinations200JSONResponse{Body: out, Headers: api.ListAlertDestinations200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) CreateAlertDestination(ctx context.Context, req api.CreateAlertDestinationRequestObject) (api.CreateAlertDestinationResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	allowPrivate := req.Body.AllowPrivate != nil && *req.Body.AllowPrivate
	role, _ := p.RoleIn(req.OrgId)
	if allowPrivate && role != rbac.RoleOwner {
		return nil, apierr.New(http.StatusForbidden, "forbidden", "only the organization owner may enable private alert destinations")
	}
	if s.alertConfig == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "alerting_unavailable", "alerting configuration is temporarily unavailable")
	}
	input := alerts.DestinationInput{Kind: string(req.Body.Kind), Name: req.Body.Name, Endpoint: req.Body.Endpoint, AllowPrivate: allowPrivate}
	if req.Body.SeverityFloor != nil {
		input.SeverityFloor = string(*req.Body.SeverityFloor)
	}
	if req.Body.CooldownSeconds != nil {
		input.CooldownSeconds = int32(*req.Body.CooldownSeconds)
	}
	row, err := s.alertConfig.Create(ctx, req.OrgId, p.UserID, input)
	if err != nil {
		return nil, alertingError(err)
	}
	return api.CreateAlertDestination201JSONResponse{Body: toAPIAlertDestination(row), Headers: api.CreateAlertDestination201ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) ListAlertDestinationSubscriptions(ctx context.Context, req api.ListAlertDestinationSubscriptionsRequestObject) (api.ListAlertDestinationSubscriptionsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage); err != nil {
		return nil, err
	}
	if s.alertConfig == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "alerting_unavailable", "alerting configuration is temporarily unavailable")
	}
	rows, err := s.alertConfig.ListSubscriptions(ctx, req.OrgId, req.DestinationId)
	if err != nil {
		return nil, alertingError(err)
	}
	out := make([]api.AlertEventKey, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.AlertEventKey(row.EventKey))
	}
	return api.ListAlertDestinationSubscriptions200JSONResponse{Body: out, Headers: api.ListAlertDestinationSubscriptions200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) AddAlertDestinationSubscription(ctx context.Context, req api.AddAlertDestinationSubscriptionRequestObject) (api.AddAlertDestinationSubscriptionResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if s.alertConfig == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "alerting_unavailable", "alerting configuration is temporarily unavailable")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	key := alerts.EventKey(req.Body.EventKey)
	if err := s.alertConfig.AddSubscription(ctx, req.OrgId, req.DestinationId, p.UserID, key); err != nil {
		return nil, alertingError(err)
	}
	return api.AddAlertDestinationSubscription201JSONResponse{Body: api.AlertEventKey(key), Headers: api.AddAlertDestinationSubscription201ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) RemoveAlertDestinationSubscription(ctx context.Context, req api.RemoveAlertDestinationSubscriptionRequestObject) (api.RemoveAlertDestinationSubscriptionResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage)
	if err != nil {
		return nil, err
	}
	if s.alertConfig == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "alerting_unavailable", "alerting configuration is temporarily unavailable")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.alertConfig.RemoveSubscription(ctx, req.OrgId, req.DestinationId, p.UserID, alerts.EventKey(req.EventKey)); err != nil {
		return nil, alertingError(err)
	}
	return api.RemoveAlertDestinationSubscription204Response{Headers: api.RemoveAlertDestinationSubscription204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) ArchiveAlertDestination(ctx context.Context, req api.ArchiveAlertDestinationRequestObject) (api.ArchiveAlertDestinationResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage)
	if err != nil {
		return nil, err
	}
	if s.alertConfig == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "alerting_unavailable", "alerting configuration is temporarily unavailable")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.alertConfig.Archive(ctx, req.OrgId, req.DestinationId, p.UserID); err != nil {
		return nil, alertingError(err)
	}
	return api.ArchiveAlertDestination204Response{Headers: api.ArchiveAlertDestination204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) TestAlertDestination(ctx context.Context, req api.TestAlertDestinationRequestObject) (api.TestAlertDestinationResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage)
	if err != nil {
		return nil, err
	}
	if s.alertConfig == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "alerting_unavailable", "alerting configuration is temporarily unavailable")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	result, err := s.alertConfig.Test(ctx, req.OrgId, req.DestinationId, p.UserID)
	if err != nil {
		return nil, alertingError(err)
	}
	body := api.AlertTestResult{Delivered: result.Delivered}
	if result.StatusCode != nil {
		status := int(*result.StatusCode)
		body.StatusCode = &status
	}
	if result.FailureCode != "" {
		code := api.AlertTestResultFailureCode(result.FailureCode)
		body.FailureCode = &code
	}
	return api.TestAlertDestination200JSONResponse{Body: body, Headers: api.TestAlertDestination200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) ListAlertDeliveries(ctx context.Context, req api.ListAlertDeliveriesRequestObject) (api.ListAlertDeliveriesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage); err != nil {
		return nil, err
	}
	if s.alertConfig == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "alerting_unavailable", "alerting configuration is temporarily unavailable")
	}
	rows, err := s.alertConfig.ListDeliveries(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.AlertDelivery, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.AlertDelivery{
			Id: row.ID, DestinationId: row.DestinationID, EventKey: api.AlertEventKey(row.EventKey),
			Severity: api.AlertSeverity(row.Severity), State: api.AlertDeliveryState(row.State),
			Attempts: int(row.Attempts), SuppressedCount: int(row.SuppressedCount), LastError: row.LastError,
			SentAt: timePtr(row.SentAt), FailedAt: timePtr(row.FailedAt), CreatedAt: row.CreatedAt,
		})
	}
	return api.ListAlertDeliveries200JSONResponse{Body: out, Headers: api.ListAlertDeliveries200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) ListAlertOccurrences(ctx context.Context, req api.ListAlertOccurrencesRequestObject) (api.ListAlertOccurrencesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAlertingManage); err != nil {
		return nil, err
	}
	if s.alertConfig == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "alerting_unavailable", "alerting is temporarily unavailable")
	}
	var state alerts.EventState
	if req.Params.State != nil {
		state = alerts.EventState(*req.Params.State)
	}
	rows, err := s.alertConfig.ListOccurrences(ctx, req.OrgId, state)
	if err != nil {
		return nil, err
	}
	out := make([]api.AlertOccurrence, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.AlertOccurrence{
			Id: row.ID, EventKey: api.AlertEventKey(row.EventKey), DedupKey: row.DedupKey,
			ResourceType: api.AlertResourceType(row.ResourceType), ResourceId: row.ResourceID,
			ResourceName: row.ResourceName, Severity: api.AlertSeverity(row.Severity),
			Subject: row.Subject, Fields: row.Fields, State: api.AlertOccurrenceState(row.State),
			FirstObservedAt: row.FirstObservedAt, LastObservedAt: row.LastObservedAt,
			ResolvedAt: row.ResolvedAt, OccurrenceCount: row.OccurrenceCount,
		})
	}
	return api.ListAlertOccurrences200JSONResponse{Body: out, Headers: api.ListAlertOccurrences200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func toAPIAlertDestination(row sqlc.AlertDestination) api.AlertDestination {
	return api.AlertDestination{Id: row.ID, Kind: api.AlertDestinationKind(row.Kind), Name: row.Name, EndpointHost: row.EndpointHost, EndpointFingerprint: row.EndpointFingerprint, AllowPrivate: row.AllowPrivate, SeverityFloor: api.AlertSeverity(row.SeverityFloor), CooldownSeconds: int(row.CooldownSeconds), Archived: row.ArchivedAt.Valid, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func alertingError(err error) error {
	if errors.Is(err, alerts.ErrDestinationNotFound) {
		return apierr.NotFound("alert_destination_not_found", "alert destination not found")
	}
	if errors.Is(err, alerts.ErrInvalidDestination) {
		return apierr.BadRequest("invalid_alert_destination", "alert destination is invalid")
	}
	return err
}
