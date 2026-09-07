package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) aiProviderContext(ctx context.Context, org uuid.UUID, mutate bool) (context.Context, error) {
	perm := rbac.PermAIProviderView
	if mutate {
		perm = rbac.PermAIProviderManage
	}
	ctx, err := authorize(ctx, org, perm)
	if err != nil {
		return ctx, err
	}
	if mutate {
		if _, err = aiManagementActor(ctx); err != nil {
			return ctx, err
		}
	}
	if s.aiPolicies == nil {
		return ctx, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
	}
	if mutate && !s.aiPolicies.ProviderManagementAvailable() {
		return ctx, apierr.New(503, "ai_gateway_unavailable", "AI provider management is unavailable")
	}
	return ctx, nil
}
func toAIProvider(p aigateway.ProviderConnection) api.AIProviderConnection {
	return api.AIProviderConnection{Id: p.ID, KeyId: p.KeyID, Provider: api.AIProviderConnectionProvider(p.Provider), Name: p.Name, Models: p.Models, Enabled: p.Enabled, Revision: p.Revision, AppliedRevision: p.AppliedRevision, Status: api.AIProviderConnectionStatus(p.Status), LastTestStatus: api.AIProviderConnectionLastTestStatus(p.LastTestStatus), LastTestAt: p.LastTestAt}
}
func (s apiServer) ListAIProviders(ctx context.Context, r api.ListAIProvidersRequestObject) (api.ListAIProvidersResponseObject, error) {
	ctx, err := s.aiProviderContext(ctx, r.OrgId, false)
	if err != nil {
		return nil, err
	}
	items, legacy, err := s.aiPolicies.ListProviders(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	out := api.AIProviderList{ManagementAvailable: s.aiPolicies.ProviderManagementAvailable(), LegacyKeyIds: legacy, Items: []api.AIProviderConnection{}}
	for _, p := range items {
		out.Items = append(out.Items, toAIProvider(p))
	}
	return api.ListAIProviders200JSONResponse(out), nil
}
func (s apiServer) CreateAIProvider(ctx context.Context, r api.CreateAIProviderRequestObject) (api.CreateAIProviderResponseObject, error) {
	ctx, err := s.aiProviderContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.New(400, "invalid_ai_provider", "AI provider configuration is not acceptable")
	}
	b := r.Body
	actor, _ := aiManagementActor(ctx)
	p, err := s.aiPolicies.CreateProvider(ctx, r.OrgId, actor, aigateway.ProviderInput{Provider: string(b.Provider), Name: b.Name, Models: b.Models, Enabled: b.Enabled, Secret: b.ApiKey})
	b.ApiKey = nil
	if err != nil {
		return nil, err
	}
	return api.CreateAIProvider201JSONResponse(toAIProvider(p)), nil
}
func (s apiServer) UpdateAIProvider(ctx context.Context, r api.UpdateAIProviderRequestObject) (api.UpdateAIProviderResponseObject, error) {
	ctx, err := s.aiProviderContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.New(400, "invalid_ai_provider", "AI provider configuration is not acceptable")
	}
	b := r.Body
	actor, _ := aiManagementActor(ctx)
	p, err := s.aiPolicies.UpdateProvider(ctx, r.OrgId, actor, r.ConnectionId, aigateway.ProviderInput{Provider: string(b.Provider), Name: b.Name, Models: b.Models, Enabled: b.Enabled, Secret: b.ApiKey}, b.ExpectedRevision)
	b.ApiKey = nil
	if err != nil {
		return nil, err
	}
	return api.UpdateAIProvider200JSONResponse(toAIProvider(p)), nil
}
func (s apiServer) DeleteAIProvider(ctx context.Context, r api.DeleteAIProviderRequestObject) (api.DeleteAIProviderResponseObject, error) {
	ctx, err := s.aiProviderContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.New(400, "invalid_ai_provider", "AI provider configuration is not acceptable")
	}
	actor, _ := aiManagementActor(ctx)
	if err = s.aiPolicies.DeleteProvider(ctx, r.OrgId, actor, r.ConnectionId, r.Body.ExpectedRevision); err != nil {
		return nil, err
	}
	return api.DeleteAIProvider204Response{}, nil
}
func (s apiServer) TestAIProvider(ctx context.Context, r api.TestAIProviderRequestObject) (api.TestAIProviderResponseObject, error) {
	ctx, err := s.aiProviderContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.New(400, "invalid_ai_provider", "AI provider configuration is not acceptable")
	}
	actor, _ := aiManagementActor(ctx)
	p, err := s.aiPolicies.TestProvider(ctx, r.OrgId, actor, r.ConnectionId, r.Body.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	return api.TestAIProvider200JSONResponse(toAIProvider(p)), nil
}
func (s apiServer) ListAIProviderModels(ctx context.Context, r api.ListAIProviderModelsRequestObject) (api.ListAIProviderModelsResponseObject, error) {
	ctx, err := s.aiProviderContext(ctx, r.OrgId, false)
	if err != nil {
		return nil, err
	}
	query := ""
	limit, offset := 50, 0
	if r.Params.Query != nil {
		query = *r.Params.Query
	}
	if r.Params.Limit != nil {
		limit = *r.Params.Limit
	}
	if r.Params.Offset != nil {
		offset = *r.Params.Offset
	}
	p, err := s.aiPolicies.ProviderModels(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	out := api.AIProviderModelList{Items: []api.AIProviderModel{}, Total: p.Total, Limit: limit, Offset: offset}
	for _, m := range p.Models {
		out.Items = append(out.Items, api.AIProviderModel{Id: m.ID, Name: m.Name})
	}
	return api.ListAIProviderModels200JSONResponse(out), nil
}
