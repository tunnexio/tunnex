package http

import (
	"context"
	"net/http"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) fqdnService() (*fqdnresources.Service, error) {
	if s.fqdnResources == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "fqdn_resource_service_unavailable", "FQDN resource service is unavailable")
	}
	return s.fqdnResources, nil
}
func fqdnInput(in api.FQDNResourceRequest) fqdnresources.Input {
	out := fqdnresources.Input{Name: in.Name, FQDN: in.Fqdn, Protocol: string(in.Protocol), PortLow: in.PortLow, PortHigh: in.PortHigh, Label: in.Label}
	if in.ResolverContext != nil {
		out.Context = &fqdnresources.Context{SiteID: in.ResolverContext.SiteId, GatewayID: in.ResolverContext.GatewayId}
	}
	return out
}
func toAPIFQDNResource(r fqdnresources.Resource) api.FQDNResource {
	out := api.FQDNResource{Id: r.ID, OrgId: r.OrgID, Name: r.Name, Fqdn: r.FQDN, Protocol: api.FQDNResourceProtocol(r.Protocol), PortLow: r.PortLow, PortHigh: r.PortHigh, Label: r.Label, Generation: r.Generation, State: api.FQDNResourceState(r.State), AnswerCount: r.AnswerCount, EffectiveTtlSeconds: r.EffectiveTTLSeconds, RefreshedAt: r.RefreshedAt, LastGoodAt: r.LastGoodAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, DestinationKind: "fqdn"}
	if r.Context != nil {
		out.ResolverContext = &api.FQDNResolverContext{SiteId: r.Context.SiteID, GatewayId: r.Context.GatewayID, SiteName: r.Context.SiteName, GatewayName: r.Context.GatewayName}
	}
	return out
}

func (s apiServer) ListFQDNResources(ctx context.Context, req api.ListFQDNResourcesRequestObject) (api.ListFQDNResourcesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceView); err != nil {
		return nil, err
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	rs, err := svc.List(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.FQDNResource, len(rs))
	for i, r := range rs {
		out[i] = toAPIFQDNResource(r)
	}
	return api.ListFQDNResources200JSONResponse(out), nil
}
func (s apiServer) CreateFQDNResource(ctx context.Context, req api.CreateFQDNResourceRequestObject) (api.CreateFQDNResourceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	r, err := svc.Create(ctx, req.OrgId, fqdnInput(*req.Body))
	if err != nil {
		return nil, err
	}
	return api.CreateFQDNResource201JSONResponse(toAPIFQDNResource(r)), nil
}
func (s apiServer) UpdateFQDNResource(ctx context.Context, req api.UpdateFQDNResourceRequestObject) (api.UpdateFQDNResourceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	r, err := svc.Update(ctx, req.OrgId, req.ResourceId, fqdnInput(*req.Body))
	if err != nil {
		return nil, err
	}
	return api.UpdateFQDNResource200JSONResponse(toAPIFQDNResource(r)), nil
}
func (s apiServer) GetFQDNResourceImpact(ctx context.Context, req api.GetFQDNResourceImpactRequestObject) (api.GetFQDNResourceImpactResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceView); err != nil {
		return nil, err
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	i, err := svc.Impact(ctx, req.OrgId, req.ResourceId)
	if err != nil {
		return nil, err
	}
	return api.GetFQDNResourceImpact200JSONResponse{ResourceId: req.ResourceId, ReferencingRuleCount: i.ReferencingRuleCount, GenerationWithdrawalRequired: i.GenerationWithdrawalRequired}, nil
}
func (s apiServer) DeleteFQDNResource(ctx context.Context, req api.DeleteFQDNResourceRequestObject) (api.DeleteFQDNResourceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceManage); err != nil {
		return nil, err
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	if err := svc.Delete(ctx, req.OrgId, req.ResourceId); err != nil {
		return nil, err
	}
	return api.DeleteFQDNResource204Response{}, nil
}
func (s apiServer) GetFQDNResourceSetting(ctx context.Context, req api.GetFQDNResourceSettingRequestObject) (api.GetFQDNResourceSettingResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceView); err != nil {
		return nil, err
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	enabled, err := svc.Setting(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetFQDNResourceSetting200JSONResponse{Enabled: enabled}, nil
}
func (s apiServer) SetFQDNResourceEnabled(ctx context.Context, req api.SetFQDNResourceEnabledRequestObject) (api.SetFQDNResourceEnabledResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	// Permission precedes entitlement. Disabling remains available after expiry;
	// only enabling an enforcement capability needs the named entitlement.
	if req.Body.Enabled && !licence.Has(s.licence.Evaluate(time.Now()).Tier, licence.FeatFQDNResources) {
		return nil, apierr.New(http.StatusForbidden, "entitlement_required", "FQDN enforcement requires the fqdn_resources licence feature")
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	if err := svc.SetSetting(ctx, req.OrgId, req.Body.Enabled); err != nil {
		return nil, err
	}
	return api.SetFQDNResourceEnabled200JSONResponse{Enabled: req.Body.Enabled}, nil
}
