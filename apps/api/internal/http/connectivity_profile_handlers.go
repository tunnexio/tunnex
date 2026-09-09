package http

import (
	"context"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/connectivity"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) GetConnectivityProfile(ctx context.Context, req api.GetConnectivityProfileRequestObject) (api.GetConnectivityProfileResponseObject, error) {
	if _, err := s.connectivityPrincipal(ctx, req.OrgId); err != nil {
		return nil, err
	}
	p, err := s.connectivity.Profile(ctx, req.OrgId)
	if err != nil {
		return nil, connectivityError(err)
	}
	return api.GetConnectivityProfile200JSONResponse(toConnectivityProfile(p)), nil
}

func (s apiServer) ConfigureConnectivityProfile(ctx context.Context, req api.ConfigureConnectivityProfileRequestObject) (api.ConfigureConnectivityProfileResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermConnectivityManage); err != nil {
		return nil, err
	}
	if s.connectivity == nil || req.Body == nil {
		return nil, connectivityError(connectivity.ErrProfile)
	}
	c := connectivity.RelayConfig{Enabled: req.Body.Enabled, URL: req.Body.RelayUrl, ExpectedRevision: req.Body.ExpectedRevision}
	if req.Body.SharedSecret != nil {
		c.Secret = *req.Body.SharedSecret
	}
	if req.Body.ClearSecret != nil {
		c.ClearSecret = *req.Body.ClearSecret
	}
	p, err := s.connectivity.Configure(ctx, req.OrgId, c)
	if err != nil {
		return nil, connectivityError(err)
	}
	return api.ConfigureConnectivityProfile200JSONResponse(toConnectivityProfile(p)), nil
}

func toConnectivityProfile(p connectivity.RelayProfile) api.ConnectivityProfile {
	return api.ConnectivityProfile{Enabled: p.Enabled, RelayUrl: p.URL, SecretConfigured: p.SecretConfigured, Revision: p.Revision}
}
