package http

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AI-READY-1: model prices, cost settings and the request log.

// authorizeAIUsageRead admits ai_provider:view or ai_gateway:view (the usage
// permission). A member without either gets the first refusal unchanged.
func authorizeAIUsageRead(ctx context.Context, org uuid.UUID) (context.Context, error) {
	out, err := authorize(ctx, org, rbac.PermAIProviderView)
	if err == nil {
		return out, nil
	}
	var domain *apierr.Error
	if !errors.As(err, &domain) || domain.Code != "forbidden" {
		return ctx, err
	}
	if out, second := authorize(ctx, org, rbac.PermAIGatewayView); second == nil {
		return out, nil
	}
	return ctx, err
}

func (s apiServer) aiPoliciesAvailable() error {
	if s.aiPolicies == nil {
		return apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
	}
	return nil
}

func toAIModelPrice(v aigateway.ModelPrice) api.AIModelPrice {
	return api.AIModelPrice{Model: v.Model, InputCostPerToken: v.InputCostPerToken, OutputCostPerToken: v.OutputCostPerToken, Removed: v.Removed, Revision: v.Revision, AppliedRevision: v.AppliedRevision, Status: api.AIModelPriceStatus(v.Status), UpdatedAt: v.UpdatedAt}
}

func (s apiServer) ListAIModelPrices(ctx context.Context, req api.ListAIModelPricesRequestObject) (api.ListAIModelPricesResponseObject, error) {
	ctx, err := authorizeAIUsageRead(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if err := s.aiPoliciesAvailable(); err != nil {
		return nil, err
	}
	var models []string
	if req.Params.Model != nil {
		models = *req.Params.Model
	}
	prices, effective, err := s.aiPolicies.ListModelPrices(ctx, req.OrgId, models)
	if err != nil {
		return nil, err
	}
	out := api.AIModelPriceList{Prices: make([]api.AIModelPrice, 0, len(prices)), Effective: make([]api.AIEffectiveModelPrice, 0, len(effective))}
	for _, p := range prices {
		out.Prices = append(out.Prices, toAIModelPrice(p))
	}
	for _, e := range effective {
		out.Effective = append(out.Effective, api.AIEffectiveModelPrice{Model: e.Model, Source: api.AIEffectiveModelPriceSource(e.Source), InputCostPerToken: e.InputCostPerToken, OutputCostPerToken: e.OutputCostPerToken})
	}
	return api.ListAIModelPrices200JSONResponse(out), nil
}

func (s apiServer) aiPriceManager(ctx context.Context, org uuid.UUID) (context.Context, uuid.UUID, error) {
	ctx, err := authorize(ctx, org, rbac.PermAIProviderManage)
	if err != nil {
		return ctx, uuid.Nil, err
	}
	actor, err := aiManagementActor(ctx)
	if err != nil {
		return ctx, uuid.Nil, err
	}
	return ctx, actor, s.aiPoliciesAvailable()
}

func (s apiServer) PutAIModelPrice(ctx context.Context, req api.PutAIModelPriceRequestObject) (api.PutAIModelPriceResponseObject, error) {
	ctx, actor, err := s.aiPriceManager(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	input := req.Body.InputCostPerToken
	v, err := s.aiPolicies.PutModelPrice(ctx, req.OrgId, actor, req.Body.Model, &input, req.Body.OutputCostPerToken, req.Body.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	return api.PutAIModelPrice200JSONResponse(toAIModelPrice(v)), nil
}

func (s apiServer) DeleteAIModelPrice(ctx context.Context, req api.DeleteAIModelPriceRequestObject) (api.DeleteAIModelPriceResponseObject, error) {
	ctx, actor, err := s.aiPriceManager(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	v, err := s.aiPolicies.RemoveModelPrice(ctx, req.OrgId, actor, req.Params.Model, req.Params.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	return api.DeleteAIModelPrice200JSONResponse(toAIModelPrice(v)), nil
}

func toAICostSettings(v aigateway.CostSettings) api.AICostSettings {
	return api.AICostSettings{UnknownPricePolicy: api.AICostSettingsUnknownPricePolicy(v.UnknownPricePolicy), RequestLogRetentionDays: v.RequestLogRetentionDays, Revision: v.Revision, UpdatedAt: v.UpdatedAt}
}

func (s apiServer) GetAICostSettings(ctx context.Context, req api.GetAICostSettingsRequestObject) (api.GetAICostSettingsResponseObject, error) {
	ctx, err := authorizeAIUsageRead(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if err := s.aiPoliciesAvailable(); err != nil {
		return nil, err
	}
	v, err := s.aiPolicies.CostSettings(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetAICostSettings200JSONResponse(toAICostSettings(v)), nil
}

func (s apiServer) PutAICostSettings(ctx context.Context, req api.PutAICostSettingsRequestObject) (api.PutAICostSettingsResponseObject, error) {
	ctx, err := s.aiPolicyContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	actor, _ := aiManagementActor(ctx)
	v, err := s.aiPolicies.PutCostSettings(ctx, req.OrgId, actor, string(req.Body.UnknownPricePolicy), req.Body.RequestLogRetentionDays, req.Body.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	return api.PutAICostSettings200JSONResponse(toAICostSettings(v)), nil
}

func (s apiServer) ListAIRequests(ctx context.Context, req api.ListAIRequestsRequestObject) (api.ListAIRequestsResponseObject, error) {
	ctx, err := authorizeAIUsageRead(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if err := s.aiPoliciesAvailable(); err != nil {
		return nil, err
	}
	p := req.Params
	f := aigateway.RequestLogFilter{From: p.From, To: p.To, SubjectID: p.SubjectId}
	if p.SubjectKind != nil {
		f.SubjectKind = string(*p.SubjectKind)
	}
	if p.Outcome != nil {
		f.Outcome = string(*p.Outcome)
	}
	if p.Model != nil {
		f.Model = *p.Model
	}
	limit, cursor := 50, ""
	if p.Limit != nil {
		limit = *p.Limit
	}
	if p.Cursor != nil {
		cursor = *p.Cursor
	}
	rows, next, err := s.aiPolicies.ListRequests(ctx, req.OrgId, f, limit, cursor)
	if err != nil {
		return nil, err
	}
	out := api.AIRequestLogPage{Items: make([]api.AIRequestLogEntry, 0, len(rows))}
	if next != "" {
		out.NextCursor = &next
	}
	for _, e := range rows {
		item := api.AIRequestLogEntry{Id: e.ID, OccurredAt: e.OccurredAt, SubjectKind: api.AIRequestLogEntrySubjectKind(e.SubjectKind), SubjectId: e.SubjectID, SubjectName: e.SubjectName, GroupId: e.GroupID, GroupName: e.GroupName, InstanceId: e.InstanceID, Model: e.Model, Mode: e.Mode, Ingress: api.AIRequestLogEntryIngress(e.Ingress), StatusCode: e.StatusCode, Outcome: api.AIRequestLogEntryOutcome(e.Outcome), RefusalCode: e.RefusalCode, LatencyMs: e.LatencyMS, PromptTokens: e.PromptTokens, CompletionTokens: e.CompletionTokens, CostUsd: e.CostUSD, CostState: api.AIRequestLogEntryCostState(e.CostState), RequestId: e.RequestID}
		if e.GroupKind != nil {
			kind := api.AIRequestLogEntryGroupKind(*e.GroupKind)
			item.GroupKind = &kind
		}
		out.Items = append(out.Items, item)
	}
	return api.ListAIRequests200JSONResponse(out), nil
}
