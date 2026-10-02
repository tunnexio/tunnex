package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aitransport"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type aiTransportRepository interface {
	Get(context.Context) (aitransport.Settings, error)
	Save(context.Context, uuid.UUID, aitransport.Settings) (aitransport.Settings, error)
}

func aiTransportError(err error) error {
	var known *apierr.Error
	if errors.As(err, &known) {
		return err
	}
	return apierr.New(503, "ai_transport_settings_unavailable", "AI transport settings are unavailable. Try again.")
}
func aiTransportView(v aitransport.Settings) api.AITransportSettings {
	return api.AITransportSettings{AllowHttp: v.AllowHTTP, Revision: v.Revision}
}
func (s apiServer) GetAITransportSettings(ctx context.Context, _ api.GetAITransportSettingsRequestObject) (api.GetAITransportSettingsResponseObject, error) {
	if _, err := requireCPAdmin(ctx); err != nil {
		return nil, err
	}
	if s.aiTransport == nil {
		return nil, aiTransportError(nil)
	}
	v, err := s.aiTransport.Get(ctx)
	if err != nil {
		return nil, aiTransportError(err)
	}
	return api.GetAITransportSettings200JSONResponse{Body: aiTransportView(v), Headers: api.GetAITransportSettings200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}
func (s apiServer) UpdateAITransportSettings(ctx context.Context, req api.UpdateAITransportSettingsRequestObject) (api.UpdateAITransportSettingsResponseObject, error) {
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.aiTransport == nil {
		return nil, aiTransportError(nil)
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("ai_transport_settings_invalid", "AI transport settings are required.")
	}
	v, err := s.aiTransport.Save(ctx, p.UserID, aitransport.Settings{AllowHTTP: req.Body.AllowHttp, Revision: req.Body.Revision})
	if err != nil {
		return nil, aiTransportError(err)
	}
	return api.UpdateAITransportSettings200JSONResponse{Body: aiTransportView(v), Headers: api.UpdateAITransportSettings200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func isAITransportRequest(r *http.Request) bool {
	path := r.URL.Path
	if strings.HasPrefix(path, "/ai/") || strings.HasPrefix(path, "/api/v1/workload/") || path == "/api/v1/agent/runtime/ai-credential" {
		return true
	}
	if !strings.HasPrefix(path, "/api/v1/organizations/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/organizations/"), "/")
	if len(parts) < 2 || parts[1] != "ai-gateway" {
		return false
	}
	// This read reports the prerequisite so users can reach server settings.
	return !(r.Method == http.MethodGet && len(parts) == 2)
}

func aiTransportMiddleware(settings aiTransportRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isAITransportRequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			secure, known := requestHTTPS(r.Context())
			if known && secure {
				next.ServeHTTP(w, r)
				return
			}
			if err := requireAIHTTP(r.Context(), settings); err != nil {
				apierr.Write(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// The relay-to-CP leg is mTLS, but the dedicated relay route represents HTTP
// inside WireGuard. It must consult the same current saved policy as public HTTP.
func requireAIHTTP(ctx context.Context, settings aiTransportRepository) error {
	if settings == nil {
		return aiTransportError(nil)
	}
	v, err := settings.Get(ctx)
	if err != nil {
		return aiTransportError(err)
	}
	if !v.AllowHTTP {
		return apierr.New(403, "ai_https_required", "AI access over HTTP is disabled. Use HTTPS or ask a server administrator to enable HTTP in AI Gateway transport settings.")
	}
	return nil
}
