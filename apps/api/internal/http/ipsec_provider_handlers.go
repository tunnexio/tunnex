package http

import (
	"bytes"
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"io"
	"net/http"
	"strings"
)

type ipsecProviderRepository interface {
	CreateProviderDisabled(context.Context, uuid.UUID, uuid.UUID, *crypto.Sealer, ipsec.CreateProviderRequest) (ipsec.Connection, error)
	ReadProvider(context.Context, uuid.UUID, uuid.UUID) (ipsec.ProviderConfiguration, error)
}

func (s apiServer) CreateIPsecProviderConnection(ctx context.Context, req api.CreateIPsecProviderConnectionRequestObject) (api.CreateIPsecProviderConnectionResponseObject, error) {
	ctx, err := authorizeIPsecConfigurationCheck(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || len(req.Body.TunnelIds) != 2 {
		return nil, ipsecProviderError(ipsec.ErrConnectionInvalid)
	}
	cfg, err := privateIPsecConfiguration(req.Body.Configuration)
	if err != nil {
		return nil, err
	}
	if err = ipsec.ValidateAWSStaticConfig(cfg); err != nil {
		return nil, ipsecProviderError(ipsec.ErrConnectionInvalid)
	}
	if s.ipsecProviders == nil || s.ipsecSealer == nil {
		return nil, ipsecProviderError(ipsec.ErrConnectionUnavailable)
	}
	p, _ := authctx.PrincipalFrom(ctx)
	r, err := s.ipsecProviders.CreateProviderDisabled(ctx, req.OrgId, p.UserID, s.ipsecSealer, ipsec.CreateProviderRequest{ID: req.Body.Id, Name: req.Body.Name, SiteID: req.Body.SiteId, GatewayID: req.Body.GatewayNodeId, TunnelIDs: [2]uuid.UUID{req.Body.TunnelIds[0], req.Body.TunnelIds[1]}, Config: cfg})
	if err != nil {
		return nil, ipsecProviderError(err)
	}
	return api.CreateIPsecProviderConnection201JSONResponse{Body: publicIPsecConnection(r), Headers: api.CreateIPsecProviderConnection201ResponseHeaders{ETag: connectionETag(r.DesiredRevision), Location: "/api/v1/organizations/" + req.OrgId.String() + "/ipsec/connections/" + r.ID.String(), XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) GetIPsecProviderConfiguration(ctx context.Context, req api.GetIPsecProviderConfigurationRequestObject) (api.GetIPsecProviderConfigurationResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	if s.ipsecProviders == nil {
		return nil, ipsecProviderError(ipsec.ErrConnectionUnavailable)
	}
	r, err := s.ipsecProviders.ReadProvider(ctx, req.OrgId, req.ConnectionId)
	if err != nil {
		return nil, ipsecProviderError(err)
	}
	out := api.IPsecProviderConfiguration{ProfileId: r.ProfileID, ConfigurationRevision: r.ConfigurationRevision}
	if c := r.Config; c != nil {
		out.Configuration = &api.IPsecProviderNetworkConfiguration{Mode: c.Mode, CustomerOutsideAddress: c.CustomerOutsideAddress, LocalPrefixes: c.LocalPrefixes, RemotePrefixes: c.RemotePrefixes, Tunnels: make([]api.IPsecProviderNetworkTunnel, len(c.Tunnels))}
		for i, t := range c.Tunnels {
			out.Configuration.Tunnels[i] = api.IPsecProviderNetworkTunnel{OutsideAddress: t.OutsideAddress, InsideCidr: t.InsideCIDR, CustomerInsideAddress: t.CustomerInsideAddress, CloudInsideAddress: t.CloudInsideAddress}
		}
	}
	return api.GetIPsecProviderConfiguration200JSONResponse{Body: out, Headers: api.GetIPsecProviderConfiguration200ResponseHeaders{CacheControl: "no-store", XRequestId: reqID(ctx)}}, nil
}
func ipsecProviderError(err error) error {
	switch {
	case errors.Is(err, ipsec.ErrConnectionInvalid):
		return apierr.BadRequest("invalid_ipsec_connection", "invalid IPsec connection request")
	case errors.Is(err, ipsec.ErrConnectionNotFound):
		return apierr.NotFound("ipsec_connection_not_found", "IPsec connection not found")
	case errors.Is(err, ipsec.ErrConnectionIneligible):
		return apierr.Conflict("ipsec_connection_ineligible", "IPsec connection prerequisites are unavailable")
	case errors.Is(err, ipsec.ErrConnectionConflict):
		return apierr.Conflict("ipsec_connection_conflict", "IPsec connection identity or network reservation conflicts")
	default:
		return apierr.New(http.StatusServiceUnavailable, "ipsec_connection_unavailable", "IPsec connection is unavailable")
	}
}
func isIPsecProviderRequest(r *http.Request) bool {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	return len(p) >= 6 && p[0] == "api" && p[1] == "v1" && p[2] == "organizations" && p[4] == "ipsec" && p[5] == "connections" && ((len(p) == 6 && r.Method == http.MethodPost) || (len(p) == 8 && p[7] == "configuration" && r.Method == http.MethodGet))
}
func validateIPsecProviderRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isIPsecProviderRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		p := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		org, err := uuid.Parse(p[3])
		if err != nil {
			apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
			return
		}
		var ctx context.Context
		if r.Method == http.MethodPost {
			ctx, err = authorizeIPsecConfigurationCheck(r.Context(), org)
		} else {
			ctx, err = authorize(r.Context(), org, rbac.PermOrgView)
		}
		if err != nil {
			apierr.Write(w, r, err)
			return
		}
		r = r.WithContext(ctx)
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
			if err != nil {
				apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
				return
			}
			defer clear(body)
			if !singleUniqueJSON(body) {
				apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		next.ServeHTTP(w, r)
	})
}
