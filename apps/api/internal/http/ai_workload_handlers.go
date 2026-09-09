package http

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"io"
	"net/http"
	"strings"
	"time"
)

func (s apiServer) workloadContext(ctx context.Context, org uuid.UUID, write bool) (context.Context, uuid.UUID, error) {
	perm := rbac.PermAIWorkloadView
	if write {
		perm = rbac.PermAIWorkloadManage
	}
	ctx, err := authorize(ctx, org, perm)
	if err != nil {
		return ctx, uuid.Nil, err
	}
	actor := uuid.Nil
	if write {
		actor, err = aiManagementActor(ctx)
		if err != nil {
			return ctx, actor, err
		}
	}
	if s.aiWorkloads == nil {
		return ctx, actor, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
	}
	return ctx, actor, nil
}
func (s apiServer) ListAIWorkloads(ctx context.Context, r api.ListAIWorkloadsRequestObject) (api.ListAIWorkloadsResponseObject, error) {
	ctx, actor, err := s.workloadContext(ctx, r.OrgId, false)
	_ = actor
	if err != nil {
		return nil, err
	}
	out, err := s.aiWorkloads.List(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	return api.ListAIWorkloads200JSONResponse{Body: out, Headers: api.ListAIWorkloads200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) CreateAIWorkload(ctx context.Context, r api.CreateAIWorkloadRequestObject) (api.CreateAIWorkloadResponseObject, error) {
	ctx, actor, err := s.workloadContext(ctx, r.OrgId, true)
	_ = actor
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	out, err := s.aiWorkloads.Put(ctx, r.OrgId, actor, uuid.Nil, *r.Body)
	if err != nil {
		return nil, err
	}
	return api.CreateAIWorkload201JSONResponse{Body: out, Headers: api.CreateAIWorkload201ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) UpdateAIWorkload(ctx context.Context, r api.UpdateAIWorkloadRequestObject) (api.UpdateAIWorkloadResponseObject, error) {
	ctx, actor, err := s.workloadContext(ctx, r.OrgId, true)
	_ = actor
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	out, err := s.aiWorkloads.Put(ctx, r.OrgId, actor, r.WorkloadId, *r.Body)
	if err != nil {
		return nil, err
	}
	return api.UpdateAIWorkload200JSONResponse{Body: out, Headers: api.UpdateAIWorkload200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) CreateAIWorkloadKey(ctx context.Context, r api.CreateAIWorkloadKeyRequestObject) (api.CreateAIWorkloadKeyResponseObject, error) {
	ctx, actor, err := s.workloadContext(ctx, r.OrgId, true)
	_ = actor
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	out, err := s.aiWorkloads.CreateKey(ctx, r.OrgId, actor, r.WorkloadId, *r.Body)
	if err != nil {
		return nil, err
	}
	return api.CreateAIWorkloadKey201JSONResponse{Body: out, Headers: api.CreateAIWorkloadKey201ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) ListAIWorkloadKeys(ctx context.Context, r api.ListAIWorkloadKeysRequestObject) (api.ListAIWorkloadKeysResponseObject, error) {
	ctx, actor, err := s.workloadContext(ctx, r.OrgId, false)
	_ = actor
	if err != nil {
		return nil, err
	}
	after := uuid.Nil
	limit := 50
	if r.Params.After != nil {
		after = *r.Params.After
	}
	if r.Params.Limit != nil {
		limit = *r.Params.Limit
	}
	out, err := s.aiWorkloads.ListKeys(ctx, r.OrgId, r.WorkloadId, after, limit)
	if err != nil {
		return nil, err
	}
	return api.ListAIWorkloadKeys200JSONResponse{Body: out, Headers: api.ListAIWorkloadKeys200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) ListAIWorkloadInstances(ctx context.Context, r api.ListAIWorkloadInstancesRequestObject) (api.ListAIWorkloadInstancesResponseObject, error) {
	ctx, actor, err := s.workloadContext(ctx, r.OrgId, false)
	_ = actor
	if err != nil {
		return nil, err
	}
	after := uuid.Nil
	limit := 50
	if r.Params.After != nil {
		after = *r.Params.After
	}
	if r.Params.Limit != nil {
		limit = *r.Params.Limit
	}
	out, err := s.aiWorkloads.ListInstances(ctx, r.OrgId, r.WorkloadId, after, limit)
	if err != nil {
		return nil, err
	}
	return api.ListAIWorkloadInstances200JSONResponse{Body: out, Headers: api.ListAIWorkloadInstances200ResponseHeaders{CacheControl: "no-store"}}, nil
}
func (s apiServer) RevokeAIWorkloadKey(ctx context.Context, r api.RevokeAIWorkloadKeyRequestObject) (api.RevokeAIWorkloadKeyResponseObject, error) {
	ctx, actor, err := s.workloadContext(ctx, r.OrgId, true)
	_ = actor
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	if err = s.aiWorkloads.RevokeKey(ctx, r.OrgId, actor, r.WorkloadId, r.KeyId, r.Body.RevokeInstances); err != nil {
		return nil, err
	}
	return api.RevokeAIWorkloadKey204Response{}, nil
}
func (s apiServer) RevokeAIWorkloadInstance(ctx context.Context, r api.RevokeAIWorkloadInstanceRequestObject) (api.RevokeAIWorkloadInstanceResponseObject, error) {
	ctx, actor, err := s.workloadContext(ctx, r.OrgId, true)
	_ = actor
	if err != nil {
		return nil, err
	}
	if err = s.aiWorkloads.RevokeInstance(ctx, r.OrgId, actor, r.WorkloadId, r.InstanceId); err != nil {
		return nil, err
	}
	return api.RevokeAIWorkloadInstance204Response{}, nil
}
func (s apiServer) EnrollWorkload(context.Context, api.EnrollWorkloadRequestObject) (api.EnrollWorkloadResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}
func (s apiServer) ExchangeWorkloadToken(context.Context, api.ExchangeWorkloadTokenRequestObject) (api.ExchangeWorkloadTokenResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}
func (s apiServer) RotateWorkloadKey(context.Context, api.RotateWorkloadKeyRequestObject) (api.RotateWorkloadKeyResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}
func (s apiServer) RetireWorkloadInstance(context.Context, api.RetireWorkloadInstanceRequestObject) (api.RetireWorkloadInstanceResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}
func (s apiServer) ListWorkloadModels(context.Context, api.ListWorkloadModelsRequestObject) (api.ListWorkloadModelsResponseObject, error) {
	return nil, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}

// Machine routes do not consume cookies or human CLI credentials. Install before
// human bearer parsing; raw transport also enforces bounds absent in forms.
func workloadMiddleware(service *aigateway.Workloads, adapter *aigateway.Adapter) func(http.Handler) http.Handler {
	admission := make(chan struct{}, 32)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			if strings.HasPrefix(path, "/ai/") && path != "/ai/v1/models" && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tnx_wai_") {
				if service == nil || adapter == nil {
					apierr.Write(w, r, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable"))
					return
				}
				clone := r.Clone(r.Context())
				clone.URL.Path = strings.TrimPrefix(path, "/ai")
				// ServeAuthorized deliberately supplies no bearer to its trusted
				// callback. Bind the sole workload bearer here, as the human route
				// binds its authenticated principal rather than changing that seam.
				headers := r.Header.Values("Authorization")
				if len(headers) != 1 {
					apierr.Write(w, r, apierr.New(401, "unauthenticated", "authentication required"))
					return
				}
				bearer := strings.TrimPrefix(headers[0], "Bearer ")
				adapter.ServeAuthorized(w, clone, func(ctx context.Context, _ string, model string) (aigateway.Grant, error) {
					return service.Authorize(ctx, bearer, model)
				})
				return
			}
			if !strings.HasPrefix(path, "/api/v1/workload/") && path != "/ai/v1/models" {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			if service == nil {
				apierr.Write(w, r, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable"))
				return
			}
			select {
			case admission <- struct{}{}:
				defer func() { <-admission }()
			default:
				apierr.Write(w, r, apierr.New(429, "rate_limited", "Too many authentication requests"))
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()
			r = r.WithContext(ctx)
			bad := func() { apierr.Write(w, r, apierr.New(401, "unauthenticated", "authentication required")) }
			if r.URL.RawQuery != "" || r.URL.RawPath != "" {
				bad()
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 20<<10)
			decode := func(out any) bool {
				d := json.NewDecoder(r.Body)
				d.DisallowUnknownFields()
				if d.Decode(out) != nil {
					return false
				}
				var extra any
				return d.Decode(&extra) == io.EOF
			}
			var result any
			var err error
			bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if len(r.Header.Values("Authorization")) != 1 || bearer == r.Header.Get("Authorization") {
				bearer = ""
			}
			if path == "/ai/v1/models" && r.Method == http.MethodGet {
				var models []aigateway.UserModel
				models, err = service.Models(ctx, bearer)
				data := []map[string]string{}
				for _, m := range models {
					data = append(data, map[string]string{"id": m.Model, "object": "model", "owned_by": "tunnex", "mode": string(m.Mode)})
				}
				result = map[string]any{"object": "list", "data": data}
			} else if r.Method == http.MethodPost {
				switch path {
				case "/api/v1/workload/enroll":
					var in api.AIWorkloadEnrollInput
					if !decode(&in) {
						bad()
						return
					}
					result, err = service.Enroll(ctx, in)
				case "/api/v1/workload/token":
					if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.ParseForm() != nil || len(r.PostForm) != 4 {
						bad()
						return
					}
					for _, values := range r.PostForm {
						if len(values) != 1 {
							bad()
							return
						}
					}
					id, e := uuid.Parse(r.PostForm.Get("client_id"))
					if e != nil {
						bad()
						return
					}
					result, err = service.Token(ctx, api.AIWorkloadTokenInput{ClientId: id, GrantType: api.AIWorkloadTokenInputGrantType(r.PostForm.Get("grant_type")), ClientAssertionType: api.AIWorkloadTokenInputClientAssertionType(r.PostForm.Get("client_assertion_type")), ClientAssertion: r.PostForm.Get("client_assertion")})
				case "/api/v1/workload/rotate":
					var in api.AIWorkloadRotationInput
					if !decode(&in) {
						bad()
						return
					}
					result, err = service.Rotate(ctx, in)
				case "/api/v1/workload/retire":
					err = service.Retire(ctx, bearer)
				default:
					http.NotFound(w, r)
					return
				}
			} else {
				http.NotFound(w, r)
				return
			}
			if err != nil {
				if path == "/api/v1/workload/token" {
					var e *apierr.Error
					status := 503
					code := "temporarily_unavailable"
					if errors.As(err, &e) && e.Status < 500 {
						status = 401
						code = "invalid_client"
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
					return
				}
				apierr.Write(w, r, err)
				return
			}
			if path == "/api/v1/workload/retire" {
				w.WriteHeader(204)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(result)
		})
	}
}
