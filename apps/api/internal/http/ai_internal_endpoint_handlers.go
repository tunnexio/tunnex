package http

import (
	"context"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

func internalEndpointUnavailable() error {
	return apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) ListAIInternalEndpoints(context.Context, api.ListAIInternalEndpointsRequestObject) (api.ListAIInternalEndpointsResponseObject, error) {
	return nil, internalEndpointUnavailable()
}
func (s apiServer) PutAIInternalEndpoint(context.Context, api.PutAIInternalEndpointRequestObject) (api.PutAIInternalEndpointResponseObject, error) {
	return nil, internalEndpointUnavailable()
}
func (s apiServer) DeleteAIInternalEndpoint(context.Context, api.DeleteAIInternalEndpointRequestObject) (api.DeleteAIInternalEndpointResponseObject, error) {
	return nil, internalEndpointUnavailable()
}
func (s apiServer) GetAIInternalEndpointCA(context.Context, api.GetAIInternalEndpointCARequestObject) (api.GetAIInternalEndpointCAResponseObject, error) {
	return nil, internalEndpointUnavailable()
}
