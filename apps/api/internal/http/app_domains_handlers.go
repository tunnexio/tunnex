package http

import (
	"context"
	"errors"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

type appDomainsRepository interface {
	Get(context.Context) (appdomains.View, error)
	Save(context.Context, uuid.UUID, appdomains.Update) (appdomains.View, error)
	Effective(context.Context) (appdomains.Config, error)
}

func requireAppDomainsAdmin(ctx context.Context) (uuid.UUID, error) {
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if p.UserID == uuid.Nil || p.SessionID == "" || p.IsAgent() || p.IsMachine() || p.AuthMethod == authctx.AuthBearer || p.AuthMethod == authctx.AuthMachine || p.AuthMethod == authctx.AuthAgent {
		return uuid.Nil, apierr.Forbidden("human_session_required", "App Access domain settings require a human browser session.")
	}
	return p.UserID, nil
}
func appDomainsError(err error) error {
	if err == nil {
		return nil
	}
	var known *apierr.Error
	if errors.As(err, &known) {
		return err
	}
	return apierr.New(503, "app_domains_unavailable", "App Access domain settings are unavailable.")
}
func appDomainsView(v appdomains.View) api.AppAccessDomains {
	return api.AppAccessDomains{PortalUrl: v.PortalURL, AppBaseDomain: v.AppBaseDomain, Version: v.Version, Source: api.AppAccessDomainsSource(v.Source), ConfigurationReady: v.ConfigurationReady}
}
func (s apiServer) GetAppAccessDomains(ctx context.Context, _ api.GetAppAccessDomainsRequestObject) (api.GetAppAccessDomainsResponseObject, error) {
	if _, err := requireAppDomainsAdmin(ctx); err != nil {
		return nil, err
	}
	if s.appDomains == nil {
		return nil, appDomainsError(errors.New("not wired"))
	}
	v, err := s.appDomains.Get(ctx)
	if err != nil {
		return nil, appDomainsError(err)
	}
	return api.GetAppAccessDomains200JSONResponse{Body: appDomainsView(v), Headers: api.GetAppAccessDomains200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}
func (s apiServer) UpdateAppAccessDomains(ctx context.Context, req api.UpdateAppAccessDomainsRequestObject) (api.UpdateAppAccessDomainsResponseObject, error) {
	actor, err := requireAppDomainsAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.appDomains == nil {
		return nil, appDomainsError(errors.New("not wired"))
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("app_domains_invalid", "Domain settings are required.")
	}
	v, err := s.appDomains.Save(ctx, actor, appdomains.Update{PortalURL: req.Body.PortalUrl, AppBaseDomain: req.Body.AppBaseDomain, ExpectedVersion: req.Body.ExpectedVersion})
	if err != nil {
		return nil, appDomainsError(err)
	}
	return api.UpdateAppAccessDomains200JSONResponse{Body: appDomainsView(v), Headers: api.UpdateAppAccessDomains200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}
