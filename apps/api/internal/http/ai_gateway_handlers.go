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

type aiRuntimeBearerContextKey struct{}

// In-app pages that hold the control fixing each reason the AI Gateway is off.
const (
	aiGatewayFixEnableHref    = "/ai-gateway/settings"
	aiGatewayFixTransportHref = "/settings?section=ai-transport"
	aiGatewayFixProviderHref  = "/ai-gateway/models/new"
)

// aiGatewayStatusInput is what the settings, the transport policy, the provider store and the engine
// configuration already know. ProviderKnown is false when the provider store could not be asked; the
// missing-provider reason is then not claimed.
type aiGatewayStatusInput struct {
	Manageable      bool // the organization switch can be read and saved here
	Enabled         bool
	TransportOK     bool
	ProviderKnown   bool
	HasProvider     bool
	EngineAvailable bool
}

// aiGatewayStatus reports whether the gateway works for the organization and, when it does not, the one
// reason and the control that fixes it. The order is fixed: not enabled, transport, provider, engine.
func aiGatewayStatus(in aiGatewayStatusInput) api.AIGatewayStatus {
	off := func(reason api.AIGatewayStatusReason, kind api.AIGatewayFixKind, href string, serverAdmin bool) api.AIGatewayStatus {
		fix := api.AIGatewayFix{Kind: kind}
		if href != "" {
			fix.Href = &href
		}
		if serverAdmin {
			fix.RequiresServerAdmin = &serverAdmin
		}
		return api.AIGatewayStatus{On: false, Reason: &reason, Fix: &fix}
	}
	switch {
	case !in.Manageable:
		// Nothing an organization administrator can switch: the installation has no AI backend wired.
		return off(api.AIGatewayOffEngineNotInstalled, api.AIGatewayFixInstallEngine, "", true)
	case !in.Enabled:
		return off(api.AIGatewayOffNotEnabled, api.AIGatewayFixEnable, aiGatewayFixEnableHref, false)
	case !in.TransportOK:
		return off(api.AIGatewayOffTransportRequired, api.AIGatewayFixChooseTransport, aiGatewayFixTransportHref, true)
	case in.ProviderKnown && !in.HasProvider:
		return off(api.AIGatewayOffNoProvider, api.AIGatewayFixAddProvider, aiGatewayFixProviderHref, false)
	case !in.EngineAvailable:
		return off(api.AIGatewayOffEngineNotInstalled, api.AIGatewayFixInstallEngine, "", true)
	}
	return api.AIGatewayStatus{On: true}
}

// withAIGatewayStatus adds the read-only status to a settings answer. Every existing field is left as
// aiGatewaySettings computed it. engineAvailable is the engine configuration before the transport check.
func (s apiServer) withAIGatewayStatus(ctx context.Context, orgID uuid.UUID, out api.AIGatewaySettings, engineAvailable bool) api.AIGatewaySettings {
	in := aiGatewayStatusInput{Manageable: s.aiCredentials != nil, Enabled: out.Enabled, EngineAvailable: engineAvailable,
		TransportOK: out.UnavailableReason == nil || *out.UnavailableReason != api.HttpsRequired}
	if s.aiPolicies != nil {
		if has, err := s.aiPolicies.HasProvider(ctx, orgID); err == nil {
			in.ProviderKnown, in.HasProvider = true, has
		}
	}
	status := aiGatewayStatus(in)
	out.Status = &status
	return out
}

func (s apiServer) aiGatewaySettings(ctx context.Context, enabled, available bool, revision int64) (api.AIGatewaySettings, error) {
	installed := s.aiEngineInstalled || available
	allowHTTP := false
	if s.aiTransport != nil {
		settings, err := s.aiTransport.Get(ctx)
		if err != nil {
			return api.AIGatewaySettings{}, aiTransportError(err)
		}
		allowHTTP = settings.AllowHTTP
	}
	// Retain the legacy field in the response, but report the effective saved
	// policy rather than allowing an old environment flag to override it.
	out := api.AIGatewaySettings{Enabled: enabled, Available: available, Revision: revision, EngineInstalled: &installed, HttpAllowed: &allowHTTP, PrivateHttpAllowed: &allowHTTP}
	secure, known := requestHTTPS(ctx)
	if !(known && secure) && !allowHTTP {
		out.Available = false
		reason := api.HttpsRequired
		out.UnavailableReason = &reason
	} else if !available {
		reason := api.EngineNotConfigured
		out.UnavailableReason = &reason
	}
	return out, nil
}

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
	out, err := s.aiGatewaySettingsWithStatus(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetAIGatewaySettings200JSONResponse(out), nil
}

// aiGatewaySettingsWithStatus is the settings answer with its status, for a caller that is already authorized.
func (s apiServer) aiGatewaySettingsWithStatus(ctx context.Context, orgID uuid.UUID) (api.AIGatewaySettings, error) {
	if s.aiCredentials == nil {
		v, err := s.aiGatewaySettings(ctx, false, false, 0)
		if err != nil {
			return api.AIGatewaySettings{}, err
		}
		return s.withAIGatewayStatus(ctx, orgID, v, false), nil
	}
	v, err := s.aiCredentials.Settings(ctx, orgID)
	if err != nil {
		return api.AIGatewaySettings{}, err
	}
	out, err := s.aiGatewaySettings(ctx, v.Enabled, v.Available, v.Revision)
	if err != nil {
		return api.AIGatewaySettings{}, err
	}
	return s.withAIGatewayStatus(ctx, orgID, out, v.Available), nil
}

// aiGatewayStatusReasonOnly keeps whether the gateway works and the one reason, and drops the control
// that fixes it: that control and its link are for people who may read the settings.
func aiGatewayStatusReasonOnly(status api.AIGatewayStatus) api.AIGatewayStatus {
	return api.AIGatewayStatus{On: status.On, Reason: status.Reason}
}

// GetAIGatewayStatus tells a person who may use a model, and nothing more, why no model can answer. It
// is authorized by the permission the list of their own models already needs, and returns no setting.
func (s apiServer) GetAIGatewayStatus(ctx context.Context, req api.GetAIGatewayStatusRequestObject) (api.GetAIGatewayStatusResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAIModelUse)
	if err != nil {
		return nil, err
	}
	out, err := s.aiGatewaySettingsWithStatus(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if out.Status == nil {
		return api.GetAIGatewayStatus200JSONResponse(api.AIGatewayStatus{On: out.Enabled && out.Available}), nil
	}
	return api.GetAIGatewayStatus200JSONResponse(aiGatewayStatusReasonOnly(*out.Status)), nil
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
	out, err := s.aiGatewaySettings(ctx, v.Enabled, v.Available, v.Revision)
	if err != nil {
		return nil, err
	}
	return api.SetAIGatewaySettings200JSONResponse(s.withAIGatewayStatus(ctx, req.OrgId, out, v.Available)), nil
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
			_, inference := aigateway.InferencePathMode(strings.TrimPrefix(r.URL.Path, "/ai"))
			if !strings.HasPrefix(r.URL.Path, "/ai/") || !inference && !strings.HasPrefix(r.URL.Path, "/ai/v1/videos/") {
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

func (s apiServer) AiCompletion(context.Context, api.AiCompletionRequestObject) (api.AiCompletionResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiEmbedding(context.Context, api.AiEmbeddingRequestObject) (api.AiEmbeddingResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiSpeech(context.Context, api.AiSpeechRequestObject) (api.AiSpeechResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiTranscription(context.Context, api.AiTranscriptionRequestObject) (api.AiTranscriptionResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiImageGeneration(context.Context, api.AiImageGenerationRequestObject) (api.AiImageGenerationResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiVideoGeneration(context.Context, api.AiVideoGenerationRequestObject) (api.AiVideoGenerationResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiRerank(context.Context, api.AiRerankRequestObject) (api.AiRerankResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiVideoStatus(context.Context, api.AiVideoStatusRequestObject) (api.AiVideoStatusResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

func (s apiServer) AiVideoContent(context.Context, api.AiVideoContentRequestObject) (api.AiVideoContentResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}
