package http

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/go-chi/chi/v5/middleware"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AI-KEYS-1: static API keys for workloads. Reads need ai_workload:view and
// writes ai_workload:manage, as for every other workload action.

func (s apiServer) staticKeyContext(ctx context.Context, org uuid.UUID, write bool) (context.Context, uuid.UUID, error) {
	ctx, actor, err := s.workloadContext(ctx, org, write)
	if err != nil {
		return ctx, actor, err
	}
	if s.aiStaticKeys == nil {
		return ctx, actor, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
	}
	return ctx, actor, nil
}

func (s apiServer) ListAIWorkloadStaticKeys(ctx context.Context, r api.ListAIWorkloadStaticKeysRequestObject) (api.ListAIWorkloadStaticKeysResponseObject, error) {
	ctx, _, err := s.staticKeyContext(ctx, r.OrgId, false)
	if err != nil {
		return nil, err
	}
	after, limit := uuid.Nil, 50
	if r.Params.After != nil {
		after = *r.Params.After
	}
	if r.Params.Limit != nil {
		limit = *r.Params.Limit
	}
	out, err := s.aiStaticKeys.List(ctx, r.OrgId, r.WorkloadId, after, limit)
	if err != nil {
		return nil, err
	}
	return api.ListAIWorkloadStaticKeys200JSONResponse{Body: out, Headers: api.ListAIWorkloadStaticKeys200ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) CreateAIWorkloadStaticKey(ctx context.Context, r api.CreateAIWorkloadStaticKeyRequestObject) (api.CreateAIWorkloadStaticKeyResponseObject, error) {
	ctx, actor, err := s.staticKeyContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	out, err := s.aiStaticKeys.Create(ctx, r.OrgId, actor, r.WorkloadId, *r.Body)
	if err != nil {
		return nil, err
	}
	return api.CreateAIWorkloadStaticKey201JSONResponse{Body: out, Headers: api.CreateAIWorkloadStaticKey201ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) UpdateAIWorkloadStaticKey(ctx context.Context, r api.UpdateAIWorkloadStaticKeyRequestObject) (api.UpdateAIWorkloadStaticKeyResponseObject, error) {
	ctx, actor, err := s.staticKeyContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	out, err := s.aiStaticKeys.Update(ctx, r.OrgId, actor, r.WorkloadId, r.KeyId, *r.Body)
	if err != nil {
		return nil, err
	}
	return api.UpdateAIWorkloadStaticKey200JSONResponse{Body: out, Headers: api.UpdateAIWorkloadStaticKey200ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) RotateAIWorkloadStaticKey(ctx context.Context, r api.RotateAIWorkloadStaticKeyRequestObject) (api.RotateAIWorkloadStaticKeyResponseObject, error) {
	ctx, actor, err := s.staticKeyContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	out, err := s.aiStaticKeys.Rotate(ctx, r.OrgId, actor, r.WorkloadId, r.KeyId, *r.Body)
	if err != nil {
		return nil, err
	}
	return api.RotateAIWorkloadStaticKey201JSONResponse{Body: out, Headers: api.RotateAIWorkloadStaticKey201ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) RevokeAIWorkloadStaticKey(ctx context.Context, r api.RevokeAIWorkloadStaticKeyRequestObject) (api.RevokeAIWorkloadStaticKeyResponseObject, error) {
	ctx, actor, err := s.staticKeyContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if err = s.aiStaticKeys.Revoke(ctx, r.OrgId, actor, r.WorkloadId, r.KeyId); err != nil {
		return nil, err
	}
	return api.RevokeAIWorkloadStaticKey204Response{}, nil
}

func (s apiServer) GetAIStaticKeySettings(ctx context.Context, r api.GetAIStaticKeySettingsRequestObject) (api.GetAIStaticKeySettingsResponseObject, error) {
	ctx, _, err := s.staticKeyContext(ctx, r.OrgId, false)
	if err != nil {
		return nil, err
	}
	allowed, err := s.aiStaticKeys.PublicAllowed(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetAIStaticKeySettings200JSONResponse{Body: api.AIStaticKeySettings{PublicStaticKeysAllowed: allowed}, Headers: api.GetAIStaticKeySettings200ResponseHeaders{CacheControl: "no-store"}}, nil
}

// SetAIStaticKeySettings is an AI Gateway setting: ai_gateway:manage
// (founder decision 3).
func (s apiServer) SetAIStaticKeySettings(ctx context.Context, r api.SetAIStaticKeySettingsRequestObject) (api.SetAIStaticKeySettingsResponseObject, error) {
	ctx, err := authorize(ctx, r.OrgId, rbac.PermAIGatewayManage)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	actor, err := aiManagementActor(ctx)
	if err != nil {
		return nil, err
	}
	if s.aiStaticKeys == nil {
		return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
	}
	allowed, err := s.aiStaticKeys.SetPublicAllowed(ctx, r.OrgId, actor, r.Body.PublicStaticKeysAllowed)
	if err != nil {
		return nil, err
	}
	return api.SetAIStaticKeySettings200JSONResponse{Body: api.AIStaticKeySettings{PublicStaticKeysAllowed: allowed}, Headers: api.SetAIStaticKeySettings200ResponseHeaders{CacheControl: "no-store"}}, nil
}

// staticCredential returns the one static key credential of a request, or
// claimed=false when the request does not present one. A request that claims
// a static key with anything but exactly one credential header is refused:
// `Authorization: Bearer tnx_sk_...` anywhere, or `x-api-key: tnx_sk_...` on
// the messages route only (founder decision 5).
func staticCredential(r *http.Request, messagesPath string) (raw string, claimed, ok bool) {
	auth, keys := r.Header.Values("Authorization"), r.Header.Values("X-Api-Key")
	for _, v := range auth {
		if strings.HasPrefix(v, "Bearer "+aigateway.StaticKeyPrefix) {
			claimed = true
		}
	}
	for _, v := range keys {
		if aigateway.LooksLikeStaticKey(strings.TrimSpace(v)) {
			claimed = true
		}
	}
	if !claimed {
		return "", false, false
	}
	if len(auth)+len(keys) != 1 {
		return "", true, false
	}
	if len(auth) == 1 {
		return strings.TrimPrefix(auth[0], "Bearer "), true, true
	}
	if r.URL.Path != messagesPath {
		return "", true, false
	}
	return keys[0], true, true
}

// staticKeyMiddleware is the dedicated public route for static keys (D5/D6).
// It runs before the workload and human paths so a static key never reaches
// the adapter's default closure, and builds the Public ingress itself.
func staticKeyMiddleware(keys *aigateway.StaticKeys, adapter *aigateway.Adapter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/ai/") {
				next.ServeHTTP(w, r)
				return
			}
			raw, claimed, ok := staticCredential(r, "/ai/anthropic/v1/messages")
			if !claimed {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			if !ok {
				apierr.Write(w, r, apierr.New(401, "unauthenticated", "authentication required"))
				return
			}
			// HTTPS only, whatever "Allow HTTP" says, checked on the observed
			// transport before any lookup. Unknown transport refuses.
			if secure, known := requestHTTPS(r.Context()); !known || !secure {
				apierr.Write(w, r, apierr.New(403, "ai_policy_denied", "AI access is not available under the current policy"))
				return
			}
			if keys == nil || adapter == nil {
				apierr.Write(w, r, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable"))
				return
			}
			path := strings.TrimPrefix(r.URL.Path, "/ai")
			// Videos need the video job routes; static keys do not use them.
			if path == "/v1/videos" || strings.HasPrefix(path, "/v1/videos/") {
				apierr.Write(w, r, apierr.New(404, "not_found", "inference route not found"))
				return
			}
			client, _ := requestClientAddr(r.Context())
			ingress := aigateway.PublicIngress(client)
			if path == "/v1/models" {
				serveStaticKeyModels(w, r, keys, raw, ingress)
				return
			}
			clone := r.Clone(r.Context())
			clone.URL.Path = path
			tw, traced, _, finish := adapter.RequestLog().Begin(w, clone, aigateway.IngressWorkload, middleware.GetReqID(r.Context()))
			defer finish()
			adapter.ServeAuthorized(tw, traced, aigateway.TraceAuthorize(func(ctx context.Context, _ string, model string) (aigateway.Grant, error) {
				return keys.Authorize(ctx, raw, model, ingress)
			}))
		})
	}
}

func serveStaticKeyModels(w http.ResponseWriter, r *http.Request, keys *aigateway.StaticKeys, raw string, ingress aigateway.StaticKeyIngress) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		apierr.Write(w, r, apierr.New(404, "not_found", "inference route not found"))
		return
	}
	models, err := keys.Models(r.Context(), raw, ingress)
	if err != nil {
		writeStaticKeyRefusal(w, r, err)
		return
	}
	data := []map[string]string{}
	for _, m := range models {
		data = append(data, map[string]string{"id": m.Model, "object": "model", "owned_by": "tunnex", "mode": string(m.Mode)})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
}

// writeStaticKeyRefusal renders only the adapter's fixed public messages.
func writeStaticKeyRefusal(w http.ResponseWriter, r *http.Request, err error) {
	var domain *apierr.Error
	status := 403
	if errors.As(err, &domain) {
		switch domain.Status {
		case 401, 503:
			status = domain.Status
		}
	}
	switch status {
	case 401:
		apierr.Write(w, r, apierr.New(401, "unauthenticated", "authentication required"))
	case 503:
		apierr.Write(w, r, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable"))
	default:
		apierr.Write(w, r, apierr.New(403, "ai_policy_denied", "AI access is not available under the current policy"))
	}
}
