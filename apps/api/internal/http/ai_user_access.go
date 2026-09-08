package http

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) ListAIUserGroups(ctx context.Context, req api.ListAIUserGroupsRequestObject) (api.ListAIUserGroupsResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAIModelAccessView)
	if err != nil {
		return nil, err
	}
	values, err := s.aiPolicies.ListUserGroups(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := api.ListAIUserGroups200JSONResponse{}
	for _, v := range values {
		out = append(out, api.AIUserGroup{Id: v.ID, Name: v.Name, Members: v.Members})
	}
	return out, nil
}
func toAIUserModelGrant(v aigateway.UserModelGrant) api.AIUserModelGrant {
	return api.AIUserModelGrant{Id: v.ID, GroupId: v.GroupID, GroupName: v.GroupName, ConnectionId: v.ConnectionID, Model: v.Model, Mode: api.AIModelMode(v.Mode), Enabled: v.Enabled, Revision: v.Revision, AppliedRevision: v.AppliedRevision, Status: api.AIUserModelGrantStatus(v.Status)}
}
func (s apiServer) ListAIUserModelGrants(ctx context.Context, req api.ListAIUserModelGrantsRequestObject) (api.ListAIUserModelGrantsResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAIModelAccessView)
	if err != nil {
		return nil, err
	}
	values, err := s.aiPolicies.ListUserModelGrants(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := api.ListAIUserModelGrants200JSONResponse{}
	for _, v := range values {
		out = append(out, toAIUserModelGrant(v))
	}
	return out, nil
}
func (s apiServer) PutAIUserModelGrant(ctx context.Context, req api.PutAIUserModelGrantRequestObject) (api.PutAIUserModelGrantResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAIModelAccessManage)
	if err != nil {
		return nil, err
	}
	actor, err := aiManagementActor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	b := req.Body
	v, err := s.aiPolicies.PutUserModelGrant(ctx, req.OrgId, actor, b.GroupId, b.ConnectionId, b.Model, b.Enabled, b.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	return api.PutAIUserModelGrant200JSONResponse(toAIUserModelGrant(v)), nil
}
func (s apiServer) ListMyAIModels(ctx context.Context, req api.ListMyAIModelsRequestObject) (api.ListMyAIModelsResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAIModelUse)
	if err != nil {
		return nil, err
	}
	p, err := requireVerifiedUser(ctx)
	if err != nil {
		return nil, err
	}
	if p.UserID == uuid.Nil || p.IsMachine() || p.IsAgent() {
		return nil, apierr.New(403, "human_required", "Tunnex user login required")
	}
	values, err := s.aiPolicies.UserModels(ctx, req.OrgId, p.UserID)
	if err != nil {
		return nil, err
	}
	out := api.ListMyAIModels200JSONResponse{}
	for _, v := range values {
		out = append(out, api.AIUserModel{Model: v.Model, Mode: api.AIModelMode(v.Mode)})
	}
	return out, nil
}

// Human inference runs after cookie CSRF and MFA gates, before JSON schema
// buffering. The shared adapter owns bounded JSON/multipart validation and SSE.
func aiUserInferenceMiddleware(adapter *aigateway.Adapter, policies *aigateway.Policies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/v1/organizations/"), "/", 2)
			if !strings.HasPrefix(r.URL.Path, "/api/v1/organizations/") || len(parts) != 2 || !strings.HasPrefix(parts[1], "ai-gateway/inference/") {
				next.ServeHTTP(w, r)
				return
			}
			org, err := uuid.Parse(parts[0])
			if err != nil || org.String() != parts[0] {
				apierr.Write(w, r, apierr.BadRequest("invalid_request", "invalid organization"))
				return
			}
			ctx, err := authorize(r.Context(), org, rbac.PermAIModelUse)
			if err != nil {
				apierr.Write(w, r, err)
				return
			}
			p, err := requireVerifiedUser(ctx)
			if err != nil {
				apierr.Write(w, r, err)
				return
			}
			if p.UserID == uuid.Nil || p.IsMachine() || p.IsAgent() {
				apierr.Write(w, r, apierr.New(403, "human_required", "Tunnex user login required"))
				return
			}
			if adapter == nil || policies == nil {
				apierr.Write(w, r, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable"))
				return
			}
			clone := r.Clone(ctx)
			clone.URL.Path = "/" + strings.TrimPrefix(parts[1], "ai-gateway/inference/")
			adapter.ServeAuthorized(w, clone, func(ctx context.Context, _ string, model string) (aigateway.Grant, error) {
				return policies.ResolveUserModel(ctx, org, p.UserID, model)
			})
		})
	}
}

func (s apiServer) AiUserChatCompletion(context.Context, api.AiUserChatCompletionRequestObject) (api.AiUserChatCompletionResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiUserCompletion(context.Context, api.AiUserCompletionRequestObject) (api.AiUserCompletionResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiUserEmbedding(context.Context, api.AiUserEmbeddingRequestObject) (api.AiUserEmbeddingResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiUserSpeech(context.Context, api.AiUserSpeechRequestObject) (api.AiUserSpeechResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiUserTranscription(context.Context, api.AiUserTranscriptionRequestObject) (api.AiUserTranscriptionResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiUserImageGeneration(context.Context, api.AiUserImageGenerationRequestObject) (api.AiUserImageGenerationResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiUserVideoGeneration(context.Context, api.AiUserVideoGenerationRequestObject) (api.AiUserVideoGenerationResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiUserRerank(context.Context, api.AiUserRerankRequestObject) (api.AiUserRerankResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiUserVideoStatus(context.Context, api.AiUserVideoStatusRequestObject) (api.AiUserVideoStatusResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiUserVideoContent(context.Context, api.AiUserVideoContentRequestObject) (api.AiUserVideoContentResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiUserAnthropicMessage(context.Context, api.AiUserAnthropicMessageRequestObject) (api.AiUserAnthropicMessageResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}
