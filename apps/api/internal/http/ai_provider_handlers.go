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
	return api.AIProviderConnection{Id: p.ID, KeyId: p.KeyID, EndpointUrl: p.EndpointURL, Provider: api.AIProviderConnectionProvider(p.Provider), Name: p.Name, Models: p.Models, ModelModes: toAIModelModes(p.ModelModes), Enabled: p.Enabled, Revision: p.Revision, AppliedRevision: p.AppliedRevision, Status: api.AIProviderConnectionStatus(p.Status), LastTestStatus: api.AIProviderConnectionLastTestStatus(p.LastTestStatus), LastTestAt: p.LastTestAt}
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
	definitions := []api.AIProviderDefinition{}
	for _, d := range aigateway.ProviderDefinitions() {
		definitions = append(definitions, api.AIProviderDefinition{Id: api.AIProviderDefinitionId(d.ID), Name: d.Name, CredentialLabel: d.CredentialLabel, ModelPlaceholder: d.ModelPlaceholder})
	}
	customAvailable := s.aiPolicies.CustomAvailable()
	customEndpoints := []api.AICustomEndpoint{}
	for _, endpoint := range s.aiPolicies.ApprovedCustomEndpoints() {
		customEndpoints = append(customEndpoints, api.AICustomEndpoint{Name: endpoint.Name, Url: endpoint.URL})
	}
	sageMakerAvailable := s.aiPolicies.SageMakerAvailable()
	testAvailable := s.aiPolicies.LiteLLMBridgeAvailable()
	sageMakerEndpoints := []api.AICustomEndpoint{}
	for _, endpoint := range s.aiPolicies.ApprovedSageMakerEndpoints() {
		sageMakerEndpoints = append(sageMakerEndpoints, api.AICustomEndpoint{Name: endpoint.Name, Url: endpoint.URL})
	}
	foundryAvailable := s.aiPolicies.FoundryAvailable()
	publicAvailable := s.aiPolicies.PublicEndpointsAvailable()
	foundryEndpoints := []api.AICustomEndpoint{}
	for _, endpoint := range s.aiPolicies.ApprovedFoundryEndpoints() {
		foundryEndpoints = append(foundryEndpoints, api.AICustomEndpoint{Name: endpoint.Name, Url: endpoint.URL})
	}
	out := api.AIProviderList{FoundryAvailable: &foundryAvailable, FoundryEndpoints: &foundryEndpoints, SagemakerAvailable: &sageMakerAvailable, SagemakerEndpoints: &sageMakerEndpoints, TestAvailable: &testAvailable, CustomAvailable: &customAvailable, CustomEndpoints: &customEndpoints, Definitions: &definitions, ManagementAvailable: s.aiPolicies.ProviderManagementAvailable(), LegacyKeyIds: legacy, Items: []api.AIProviderConnection{}}
	out.PublicEndpointsAvailable = &publicAvailable
	modes := []api.AIModelMode{"chat", "completion", "embedding", "audio_speech", "audio_transcription", "image_generation", "video_generation", "rerank"}
	out.SupportedModes = &modes
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
	p, err := s.aiPolicies.CreateProvider(ctx, r.OrgId, actor, aigateway.ProviderInput{Provider: string(b.Provider), Name: b.Name, Models: b.Models, ModelModes: fromAIModelModes(b.ModelModes), Enabled: b.Enabled, Secret: b.ApiKey, EndpointURL: b.EndpointUrl})
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
	p, err := s.aiPolicies.UpdateProvider(ctx, r.OrgId, actor, r.ConnectionId, aigateway.ProviderInput{Provider: string(b.Provider), Name: b.Name, Models: b.Models, ModelModes: fromAIModelModes(b.ModelModes), Enabled: b.Enabled, Secret: b.ApiKey, EndpointURL: b.EndpointUrl}, b.ExpectedRevision)
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
	provider := "openrouter"
	if r.Params.Provider != nil {
		provider = string(*r.Params.Provider)
	}
	mode := fromAIMode(r.Params.Mode)
	if !aigateway.ValidModelMode(mode) {
		return nil, apierr.BadRequest("invalid_ai_provider", "Unsupported model mode")
	}
	var p aigateway.ProviderModelPage
	if provider == "azure_foundry" && r.Params.ConnectionId == nil {
		p, err = aigateway.FoundryReferenceModelsForMode(mode, query, limit, offset)
	} else if provider == "custom" || provider == "sagemaker" || provider == "azure_foundry" {
		if r.Params.ConnectionId == nil {
			return nil, apierr.BadRequest("invalid_ai_provider", "Select a connection before browsing its models")
		}
		p, err = s.aiPolicies.CustomProviderModelsForMode(ctx, r.OrgId, *r.Params.ConnectionId, mode, query, limit, offset)
	} else {
		if r.Params.ConnectionId != nil {
			return nil, apierr.BadRequest("invalid_ai_provider", "Connection-scoped catalog requires a custom, SageMaker or Foundry provider")
		}
		if mode == aigateway.ModeChat {
			p, err = s.aiPolicies.ProviderModels(ctx, provider, query, limit, offset)
		} else {
			p, err = aigateway.ProviderReferenceModels(provider, mode, query, limit, offset)
		}
	}
	if err != nil {
		return nil, err
	}
	out := api.AIProviderModelList{Items: []api.AIProviderModel{}, Total: p.Total, Limit: limit, Offset: offset}
	for _, m := range p.Models {
		out.Items = append(out.Items, api.AIProviderModel{Id: m.ID, Name: m.Name})
	}
	return api.ListAIProviderModels200JSONResponse(out), nil
}

func (s apiServer) TestAIProviderConnection(ctx context.Context, r api.TestAIProviderConnectionRequestObject) (api.TestAIProviderConnectionResponseObject, error) {
	ctx, err := s.aiProviderContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_ai_provider", "AI provider configuration is not acceptable")
	}
	actor, _ := aiManagementActor(ctx)
	b := r.Body
	if (b.ConnectionId == nil && (b.ApiKey == nil || b.ExpectedRevision != nil)) || (b.ConnectionId != nil && (b.ApiKey != nil || b.EndpointUrl != nil || b.ExpectedRevision == nil)) {
		return nil, apierr.BadRequest("invalid_ai_provider", "Choose either new or saved credentials for this test")
	}
	secret := ""
	if b.ApiKey != nil {
		secret = *b.ApiKey
	}
	result, err := s.aiPolicies.ProbeProvider(ctx, r.OrgId, actor, aigateway.ProviderProbeInput{Provider: string(b.Provider), Model: b.Model, Mode: fromAIMode(b.Mode), Secret: secret, EndpointURL: b.EndpointUrl, ConnectionID: b.ConnectionId, ExpectedRevision: b.ExpectedRevision})
	b.ApiKey = nil
	if err != nil {
		return nil, err
	}
	return api.TestAIProviderConnection200JSONResponse(api.AIProviderProbeResult{Status: api.AIProviderProbeResultStatus(result.Status), DurationMs: result.DurationMS}), nil
}

func (s apiServer) SearchAIProviderCatalog(ctx context.Context, r api.SearchAIProviderCatalogRequestObject) (api.SearchAIProviderCatalogResponseObject, error) {
	ctx, err := s.aiProviderContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil || r.Body.ApiKey == nil {
		return nil, apierr.BadRequest("invalid_ai_provider", "AI provider configuration is not acceptable")
	}
	b := r.Body
	actor, _ := aiManagementActor(ctx)
	in := aigateway.ProviderCatalogInput{Provider: string(b.Provider), Mode: fromAIMode(b.Mode), Secret: *b.ApiKey, EndpointURL: b.EndpointUrl, Limit: 50}
	if b.Query != nil {
		in.Query = *b.Query
	}
	if b.Limit != nil {
		in.Limit = *b.Limit
	}
	if b.Offset != nil {
		in.Offset = *b.Offset
	}
	b.ApiKey = nil
	page, err := s.aiPolicies.SearchProviderCatalog(ctx, r.OrgId, actor, in)
	if err != nil {
		return nil, err
	}
	out := api.AIProviderModelList{Items: []api.AIProviderModel{}, Total: page.Total, Limit: in.Limit, Offset: in.Offset}
	for _, m := range page.Models {
		out.Items = append(out.Items, api.AIProviderModel{Id: m.ID, Name: m.Name})
	}
	return api.SearchAIProviderCatalog200JSONResponse(out), nil
}

func fromAIMode(mode *api.AIModelMode) aigateway.ModelMode {
	if mode == nil {
		return aigateway.ModeChat
	}
	return aigateway.ModelMode(*mode)
}
func fromAIModelModes(m *api.AIModelModes) map[string]aigateway.ModelMode {
	if m == nil {
		return nil
	}
	out := make(map[string]aigateway.ModelMode, len(*m))
	for k, v := range *m {
		out[k] = aigateway.ModelMode(v)
	}
	return out
}
func toAIModelModes(m map[string]aigateway.ModelMode) *api.AIModelModes {
	out := make(api.AIModelModes, len(m))
	for k, v := range m {
		out[k] = api.AIModelMode(v)
	}
	return &out
}
