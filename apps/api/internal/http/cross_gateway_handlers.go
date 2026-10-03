package http

import (
	"context"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type crossGatewaySettingsRepository interface {
	SetCrossGatewayClientsEnabled(context.Context, uuid.UUID, bool) (sqlc.Organization, error)
}

func (s apiServer) SetCrossGatewayClientsEnabled(ctx context.Context, req api.SetCrossGatewayClientsEnabledRequestObject) (api.SetCrossGatewayClientsEnabledResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgUpdate)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if s.crossGatewaySettings == nil {
		return nil, apierr.New(503, "cross_gateway_settings_unavailable", "Cross-gateway settings are unavailable.")
	}
	org, err := s.crossGatewaySettings.SetCrossGatewayClientsEnabled(ctx, req.OrgId, req.Body.Enabled)
	if err != nil {
		return nil, err
	}
	if s.crossGatewaySettingsNotify != nil {
		s.crossGatewaySettingsNotify.InvalidateOrg(ctx, req.OrgId)
	}
	return api.SetCrossGatewayClientsEnabled200JSONResponse{Body: api.CrossGatewaySetting{Enabled: org.CrossGatewayClientsEnabled}, Headers: api.SetCrossGatewayClientsEnabled200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}
