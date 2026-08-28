package http

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

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
	out := fqdnresources.Input{Name: in.Name, FQDN: in.Fqdn, Protocol: string(in.Protocol), PortLow: in.PortLow, PortHigh: in.PortHigh, Label: in.Label, ExpectedImpactToken: in.ExpectedImpactToken}
	if in.ResolverContext != nil {
		out.Context = &fqdnresources.Context{SiteID: in.ResolverContext.SiteId, GatewayID: in.ResolverContext.GatewayId}
	}
	return out
}
func toAPIFQDNResource(r fqdnresources.Resource) api.FQDNResource {
	out := api.FQDNResource{Id: r.ID, OrgId: r.OrgID, Name: r.Name, Fqdn: r.FQDN, Protocol: api.FQDNResourceProtocol(r.Protocol), PortLow: r.PortLow, PortHigh: r.PortHigh, Label: r.Label, Generation: r.Generation, State: api.FQDNResourceState(r.State), AnswerCount: r.AnswerCount, EffectiveTtlSeconds: r.EffectiveTTLSeconds, RefreshedAt: r.RefreshedAt, LastGoodAt: r.LastGoodAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, DestinationKind: "fqdn"}
	if r.Context != nil {
		out.ResolverContext = &api.FQDNResolverContext{SiteId: r.Context.SiteID, GatewayId: r.Context.GatewayID, SiteName: r.Context.SiteName, GatewayName: r.Context.GatewayName}
		if r.Context.Config != nil {
			config := toAPIFQDNResolverConfig(*r.Context.Config)
			out.ResolverContext.ResolverConfig = &config
		}
	}
	return out
}

func toAPIFQDNResolverConfig(c fqdnresources.ResolverConfig) api.FQDNResolverContextConfig {
	endpoints := make([]api.FQDNResolverEndpoint, len(c.Endpoints))
	for i, endpoint := range c.Endpoints {
		endpoints[i] = api.FQDNResolverEndpoint{Address: endpoint.Address, Port: endpoint.Port, Transport: api.FQDNResolverEndpointTransport(endpoint.Transport)}
	}
	return api.FQDNResolverContextConfig{Id: c.ID, OrgId: c.OrgID, SiteId: c.SiteID, GatewayId: c.GatewayID, Version: c.Version, State: api.FQDNResolverContextConfigState(c.State), Endpoints: endpoints, CreatedAt: c.CreatedAt}
}

func fqdnResolverEndpoints(in []api.FQDNResolverEndpoint) []fqdnresources.ResolverEndpoint {
	out := make([]fqdnresources.ResolverEndpoint, len(in))
	for i, endpoint := range in {
		out[i] = fqdnresources.ResolverEndpoint{Address: endpoint.Address, Port: endpoint.Port, Transport: string(endpoint.Transport)}
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
	uid, sys, cause := auditActor(ctx)
	r, err := svc.Create(ctx, req.OrgId, fqdnInput(*req.Body), uid, sys, cause)
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
	uid, sys, cause := auditActor(ctx)
	r, err := svc.Update(ctx, req.OrgId, req.ResourceId, fqdnInput(*req.Body), uid, sys, cause)
	if err != nil {
		return nil, err
	}
	return api.UpdateFQDNResource200JSONResponse(toAPIFQDNResource(r)), nil
}
func (s apiServer) GetFQDNResourceDetail(ctx context.Context, req api.GetFQDNResourceDetailRequestObject) (api.GetFQDNResourceDetailResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceView); err != nil {
		return nil, err
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	d, err := svc.Detail(ctx, req.OrgId, req.ResourceId)
	if err != nil {
		return nil, err
	}
	refs := make([]api.FQDNResourceRuleReference, len(d.ReferencingRules))
	for i, ref := range d.ReferencingRules {
		refs[i] = api.FQDNResourceRuleReference{Id: ref.ID, SourceKind: api.FQDNResourceRuleReferenceSourceKind(ref.SourceKind), Enabled: ref.Enabled}
	}
	return api.GetFQDNResourceDetail200JSONResponse{Resource: toAPIFQDNResource(d.Resource), ActiveAnswerAddresses: d.ActiveAnswers, StatusSource: api.FQDNResourceDetailStatusSource(d.StatusSource), ObservedAt: d.ObservedAt, FreshUntilAt: d.FreshUntilAt, ServerReason: d.ServerReason, NextAction: api.FQDNResourceDetailNextAction(d.NextAction), ResolverReady: d.ResolverReady, ReferencingRuleCount: d.ReferencingRuleCount, ReferencingRules: refs, ReferencesTruncated: d.ReferencesTruncated, Audit: api.FQDNResourceAuditProjection{TargetType: "fqdn_resource", TargetId: req.ResourceId, LatestEventAt: d.Audit.LatestEventAt}}, nil
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
	return api.GetFQDNResourceImpact200JSONResponse{ResourceId: req.ResourceId, ReferencingRuleCount: i.ReferencingRuleCount, ReferencingRuleIds: i.ReferencingRuleIDs, GenerationWithdrawalRequired: i.GenerationWithdrawalRequired}, nil
}
func (s apiServer) PreviewFQDNResourceImpact(ctx context.Context, req api.PreviewFQDNResourceImpactRequestObject) (api.PreviewFQDNResourceImpactResponseObject, error) {
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
	p, err := svc.Preview(ctx, req.OrgId, req.ResourceId, fqdnInput(*req.Body))
	if err != nil {
		return nil, err
	}
	return api.PreviewFQDNResourceImpact200JSONResponse{ResourceId: req.ResourceId, EnforcementInputsChanged: p.EnforcementInputsChanged, ReferencingRuleCount: p.ReferencingRuleCount, ReferencingRuleIds: p.ReferencingRuleIDs, GenerationWithdrawalRequired: p.GenerationWithdrawalRequired, MutationAllowed: p.MutationAllowed, RefusalReason: p.RefusalReason, ExpectedImpactToken: p.ExpectedImpactToken}, nil
}
func (s apiServer) DeleteFQDNResource(ctx context.Context, req api.DeleteFQDNResourceRequestObject) (api.DeleteFQDNResourceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceManage); err != nil {
		return nil, err
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	uid, sys, cause := auditActor(ctx)
	if err := svc.Delete(ctx, req.OrgId, req.ResourceId, uid, sys, cause); err != nil {
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
func (s apiServer) GetFQDNResourceSettingImpact(ctx context.Context, req api.GetFQDNResourceSettingImpactRequestObject) (api.GetFQDNResourceSettingImpactResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceManage); err != nil {
		return nil, err
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	impact, err := svc.SettingImpact(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	entitled := licence.Has(s.licence.Evaluate(time.Now()).Tier, licence.FeatFQDNResources)
	return api.GetFQDNResourceSettingImpact200JSONResponse{Enabled: impact.Enabled, EnforcementReadyRuleCount: impact.EnforcementReadyRuleCount, EnforcementReadyRuleIds: impact.EnforcementReadyRuleIDs, RuleIdsTruncated: impact.RuleIDsTruncated, EntitlementAvailable: entitled, ExpectedImpactToken: impact.ExpectedImpactToken}, nil
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
	uid, sys, cause := auditActor(ctx)
	if err := svc.SetSetting(ctx, req.OrgId, req.Body.Enabled, req.Body.ExpectedImpactToken, uid, sys, cause); err != nil {
		return nil, err
	}
	// The setting transaction is durable before this wake. An opt-out therefore
	// withdraws FQDN tuples from the next authoritative desired-state fetch.
	s.notifyFQDNSettingCommitted(ctx, req.OrgId)
	return api.SetFQDNResourceEnabled200JSONResponse{Enabled: req.Body.Enabled}, nil
}

func (s apiServer) notifyFQDNSettingCommitted(ctx context.Context, orgID uuid.UUID) {
	if s.fqdnSettingNotify != nil {
		s.fqdnSettingNotify.InvalidateOrg(ctx, orgID)
	}
}

func (s apiServer) GetFQDNResolverContextConfig(ctx context.Context, req api.GetFQDNResolverContextConfigRequestObject) (api.GetFQDNResolverContextConfigResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceView); err != nil {
		return nil, err
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	config, err := svc.ResolverConfig(ctx, req.OrgId, req.SiteId, req.GatewayId)
	if err != nil {
		return nil, err
	}
	return api.GetFQDNResolverContextConfig200JSONResponse(toAPIFQDNResolverConfig(config)), nil
}

func (s apiServer) SetFQDNResolverContextConfig(ctx context.Context, req api.SetFQDNResolverContextConfigRequestObject) (api.SetFQDNResolverContextConfigResponseObject, error) {
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
	uid, sys, cause := auditActor(ctx)
	config, err := svc.SetResolverConfig(ctx, req.OrgId, req.SiteId, req.GatewayId, uid, sys, cause, fqdnResolverEndpoints(req.Body.Endpoints))
	if err != nil {
		return nil, err
	}
	return api.SetFQDNResolverContextConfig200JSONResponse(toAPIFQDNResolverConfig(config)), nil
}

func (s apiServer) DeleteFQDNResolverContextConfig(ctx context.Context, req api.DeleteFQDNResolverContextConfigRequestObject) (api.DeleteFQDNResolverContextConfigResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermFQDNResourceManage); err != nil {
		return nil, err
	}
	svc, err := s.fqdnService()
	if err != nil {
		return nil, err
	}
	uid, sys, cause := auditActor(ctx)
	if err := svc.DeleteResolverConfig(ctx, req.OrgId, req.SiteId, req.GatewayId, uid, sys, cause); err != nil {
		return nil, err
	}
	return api.DeleteFQDNResolverContextConfig204Response{}, nil
}
