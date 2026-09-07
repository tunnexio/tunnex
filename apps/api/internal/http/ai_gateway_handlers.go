package http

import (
	"context"
	"net/http"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type aiRuntimeBearerContextKey struct{}

func (s apiServer) IssueAICredential(ctx context.Context, _ api.IssueAICredentialRequestObject) (api.IssueAICredentialResponseObject, error) {
	if s.aiCredentials == nil {
		return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
	}
	raw, _ := ctx.Value(aiRuntimeBearerContextKey{}).(string)
	credential, err := s.aiCredentials.Issue(ctx, raw)
	if err != nil {
		return nil, err
	}
	return api.IssueAICredential201JSONResponse{Body: api.AICredential{Token: credential.Token, Audience: api.AICredentialAudience(credential.Audience), ExpiresAt: credential.ExpiresAt, Endpoint: credential.Endpoint}, Headers: api.IssueAICredential201ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) GetAIGatewaySettings(ctx context.Context, req api.GetAIGatewaySettingsRequestObject) (api.GetAIGatewaySettingsResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAIGatewayView)
	if err != nil {
		return nil, err
	}
	if s.aiCredentials == nil {
		return api.GetAIGatewaySettings200JSONResponse{Enabled: false, Available: false, Revision: 0}, nil
	}
	v, err := s.aiCredentials.Settings(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetAIGatewaySettings200JSONResponse{Enabled: v.Enabled, Available: v.Available, Revision: v.Revision}, nil
}

func (s apiServer) SetAIGatewaySettings(ctx context.Context, req api.SetAIGatewaySettingsRequestObject) (api.SetAIGatewaySettingsResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAIGatewayManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	if s.aiCredentials == nil {
		return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
	}
	actor, err := aiManagementActor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := s.aiCredentials.SetEnabled(ctx, req.OrgId, actor, req.Body.Enabled)
	if err != nil {
		return nil, err
	}
	return api.SetAIGatewaySettings200JSONResponse{Enabled: v.Enabled, Available: v.Available, Revision: v.Revision}, nil
}

// The generated contract documents these paths. The raw transport below owns
// authentication, bounded body validation and SSE delivery without decoding or
// buffering through the strict JSON server. These fallback methods fail closed
// if a composition omits that transport.
func (s apiServer) AiChatCompletion(context.Context, api.AiChatCompletionRequestObject) (api.AiChatCompletionResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}
func (s apiServer) AiAnthropicMessage(context.Context, api.AiAnthropicMessageRequestObject) (api.AiAnthropicMessageResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func aiInferenceMiddleware(adapter *aigateway.Adapter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ai/v1/chat/completions" && r.URL.Path != "/ai/anthropic/v1/messages" {
				next.ServeHTTP(w, r)
				return
			}
			if adapter == nil {
				auth := r.Header.Values("Authorization")
				if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth[0], "Bearer ")) == "" {
					apierr.Write(w, r, apierr.New(401, "unauthenticated", "authentication required"))
					return
				}
				apierr.Write(w, r, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable"))
				return
			}
			clone := r.Clone(r.Context())
			clone.URL.Path = strings.TrimPrefix(r.URL.Path, "/ai")
			adapter.ServeHTTP(w, clone)
		})
	}
}
