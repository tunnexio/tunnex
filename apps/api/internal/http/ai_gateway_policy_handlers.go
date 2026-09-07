package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"time"
)

func aiManagementActor(ctx context.Context) (uuid.UUID, error) {
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return uuid.Nil, apierr.New(401, "unauthenticated", "authentication required")
	}
	if p.IsMachine() {
		return uuid.Nil, apierr.New(403, "human_admin_required", "AI configuration requires a human administrator")
	}
	return p.UserID, nil
}
func (s apiServer) aiPolicyContext(ctx context.Context, org uuid.UUID, mutate bool) (context.Context, error) {
	perm := rbac.PermAIGatewayView
	if mutate {
		perm = rbac.PermAIGatewayManage
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
	return ctx, nil
}
func toAITeam(v aigateway.TeamPolicy) api.AITeamPolicy {
	return api.AITeamPolicy{TeamId: v.TeamID, Models: v.Models, KeyIds: v.KeyIDs, DailyCostLimit: v.DailyCostLimit, Revision: v.Revision}
}
func toAIAssignment(v aigateway.Assignment) api.AIAssignment {
	override := v.ModelsOverride
	if override == nil {
		override = []string{}
	}
	return api.AIAssignment{DeviceId: v.DeviceID, TeamId: v.TeamID, Enabled: v.Enabled, ModelsOverride: override, Revision: v.Revision, AppliedRevision: v.AppliedRevision, AppliedTeamRevision: v.AppliedTeamRevision, Status: api.AIAssignmentStatus(v.Status)}
}
func (s apiServer) ListAITeamPolicies(ctx context.Context, r api.ListAITeamPoliciesRequestObject) (api.ListAITeamPoliciesResponseObject, error) {
	ctx, err := s.aiPolicyContext(ctx, r.OrgId, false)
	if err != nil {
		return nil, err
	}
	values, err := s.aiPolicies.ListTeams(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	out := make(api.ListAITeamPolicies200JSONResponse, 0, len(values))
	for _, v := range values {
		out = append(out, toAITeam(v))
	}
	return out, nil
}
func (s apiServer) PutAITeamPolicy(ctx context.Context, r api.PutAITeamPolicyRequestObject) (api.PutAITeamPolicyResponseObject, error) {
	ctx, err := s.aiPolicyContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	actor, _ := aiManagementActor(ctx)
	v, err := s.aiPolicies.PutTeam(ctx, r.OrgId, actor, r.TeamId, r.Body.Models, r.Body.KeyIds, r.Body.DailyCostLimit, r.Body.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	workCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = s.aiPolicies.ReconcileTeam(workCtx, r.OrgId, r.TeamId, 16)
	return api.PutAITeamPolicy200JSONResponse(toAITeam(v)), nil
}
func (s apiServer) ListAIAssignments(ctx context.Context, r api.ListAIAssignmentsRequestObject) (api.ListAIAssignmentsResponseObject, error) {
	ctx, err := s.aiPolicyContext(ctx, r.OrgId, false)
	if err != nil {
		return nil, err
	}
	values, err := s.aiPolicies.ListAssignments(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	out := make(api.ListAIAssignments200JSONResponse, 0, len(values))
	for _, v := range values {
		out = append(out, toAIAssignment(v))
	}
	return out, nil
}
func (s apiServer) PutAIAssignment(ctx context.Context, r api.PutAIAssignmentRequestObject) (api.PutAIAssignmentResponseObject, error) {
	ctx, err := s.aiPolicyContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	actor, _ := aiManagementActor(ctx)
	v, err := s.aiPolicies.PutAssignment(ctx, r.OrgId, actor, r.DeviceId, r.Body.TeamId, r.Body.Enabled, r.Body.ModelsOverride, r.Body.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	// Desired state is already durable. A failed synchronization stays visible and
	// is retried by the worker; never pretend the persisted edit was rolled back.
	if applied, e := s.aiPolicies.Reconcile(ctx, r.OrgId, r.DeviceId); e == nil {
		v = applied
	}
	return api.PutAIAssignment200JSONResponse(toAIAssignment(v)), nil
}
func (s apiServer) ReconcileAIAssignment(ctx context.Context, r api.ReconcileAIAssignmentRequestObject) (api.ReconcileAIAssignmentResponseObject, error) {
	ctx, err := s.aiPolicyContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	v, err := s.aiPolicies.Reconcile(ctx, r.OrgId, r.DeviceId)
	if err != nil {
		return nil, err
	}
	return api.ReconcileAIAssignment200JSONResponse(toAIAssignment(v)), nil
}
func (s apiServer) GetAIUsage(ctx context.Context, r api.GetAIUsageRequestObject) (api.GetAIUsageResponseObject, error) {
	ctx, err := s.aiPolicyContext(ctx, r.OrgId, false)
	if err != nil {
		return nil, err
	}
	to := time.Now().UTC()
	from := time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, time.UTC)
	if r.Params.From != nil {
		from = *r.Params.From
	}
	if r.Params.To != nil {
		to = *r.Params.To
	}
	v, err := s.aiPolicies.Usage(ctx, r.OrgId, r.Params.TeamId, r.Params.DeviceId, from, to)
	if err != nil {
		return nil, err
	}
	return api.GetAIUsage200JSONResponse{From: from, To: to, TotalRequests: v.TotalRequests, TotalTokens: v.TotalTokens, PromptTokens: v.PromptTokens, CompletionTokens: v.CompletionTokens, TotalCost: v.TotalCost, UncostedRequests: v.UncostedRequests, Semantics: api.ObservedEstimate}, nil
}
