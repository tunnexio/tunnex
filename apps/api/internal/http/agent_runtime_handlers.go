package http

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) PrepareAgentRuntimeCredential(ctx context.Context, req api.PrepareAgentRuntimeCredentialRequestObject) (api.PrepareAgentRuntimeCredentialResponseObject, error) {
	id, ok := agentruntime.IdentityFromContext(ctx)
	if !ok || req.Body == nil {
		return nil, runtimeUnauthorized()
	}
	if err := s.agentRuntime.PrepareCredentialCandidate(ctx, id, req.Body.Revision, req.Body.TokenHash); err != nil {
		return nil, runtimeMachineError(err)
	}
	return api.PrepareAgentRuntimeCredential204Response{Headers: api.PrepareAgentRuntimeCredential204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) PrepareAgentRuntimeWireGuard(ctx context.Context, req api.PrepareAgentRuntimeWireGuardRequestObject) (api.PrepareAgentRuntimeWireGuardResponseObject, error) {
	id, ok := agentruntime.IdentityFromContext(ctx)
	if !ok || req.Body == nil {
		return nil, runtimeUnauthorized()
	}
	if err := s.agentRuntime.PrepareWireGuardCandidate(ctx, id, req.Body.Revision, req.Body.PublicKey); err != nil {
		return nil, runtimeMachineError(err)
	}
	// The assigned gateway must fetch the warm empty-AllowedIPs peer before the
	// runtime may switch. This is a best-effort fast path; its watch interval is
	// the durable fallback.
	if s.devices != nil {
		s.devices.PushOrgNodes(ctx, id.OrgID)
	}
	return api.PrepareAgentRuntimeWireGuard204Response{Headers: api.PrepareAgentRuntimeWireGuard204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) PollAgentRuntime(ctx context.Context, req api.PollAgentRuntimeRequestObject) (api.PollAgentRuntimeResponseObject, error) {
	id, ok := agentruntime.IdentityFromContext(ctx)
	if !ok {
		return nil, runtimeUnauthorized()
	}
	wait := time.Duration(0)
	if req.Params.WaitSeconds != nil {
		wait = time.Duration(*req.Params.WaitSeconds) * time.Second
	}
	wgRevision := int64(1)
	if req.Params.WireguardRevision != nil {
		wgRevision = *req.Params.WireguardRevision
	}
	cfg, unchanged, err := s.agentRuntime.PollWait(ctx, id, req.Params.AppliedRevision, wgRevision, req.Params.ClientVersion, wait)
	if err != nil {
		return nil, runtimeMachineError(err)
	}
	if unchanged {
		return api.PollAgentRuntime204Response{Headers: api.PollAgentRuntime204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
	}
	return api.PollAgentRuntime200JSONResponse{
		Body: api.ManagedAgentConfig{Revision: cfg.Revision, DeviceId: cfg.DeviceID, OrgId: cfg.OrgID,
			Address: cfg.Address, GatewayEndpoint: cfg.GatewayEndpoint, GatewayPublicKey: cfg.GatewayPublicKey,
			AllowedIps: cfg.AllowedIPs, Dns: cfg.DNS, PersistentKeepalive: cfg.PersistentKeepalive,
			CredentialRotationRevision: cfg.CredentialRotationRevision,
			WireguardCurrentRevision:   cfg.WireGuardCurrentRevision,
			WireguardRotationRevision:  cfg.WireGuardRotationRevision,
			WireguardRotationState:     runtimeWireGuardState(cfg.WireGuardRotationState)},
		Headers: api.PollAgentRuntime200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

func runtimeWireGuardState(state *string) *api.ManagedAgentConfigWireguardRotationState {
	if state == nil {
		return nil
	}
	v := api.ManagedAgentConfigWireguardRotationState(*state)
	return &v
}

func (s apiServer) ReportAgentRuntime(ctx context.Context, req api.ReportAgentRuntimeRequestObject) (api.ReportAgentRuntimeResponseObject, error) {
	id, ok := agentruntime.IdentityFromContext(ctx)
	if !ok || req.Body == nil {
		return nil, runtimeUnauthorized()
	}
	if err := s.agentRuntime.Report(ctx, id, req.Body.AppliedRevision, req.Body.AttemptedRevision, req.Body.ClientVersion, string(req.Body.ErrorCode)); err != nil {
		return nil, runtimeMachineError(err)
	}
	return api.ReportAgentRuntime204Response{Headers: api.ReportAgentRuntime204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) GetAgentRuntimeStatus(ctx context.Context, req api.GetAgentRuntimeStatusRequestObject) (api.GetAgentRuntimeStatusResponseObject, error) {
	// Permission and edition/opt-in gates precede the device/state lookup. This
	// preserves the existing no-oracle ordering and does not mint an F04 RBAC name.
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	status, err := s.agentRuntime.Status(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, runtimeHumanError(err)
	}
	var lastError *api.AgentRuntimeStatusLastErrorCode
	if status.LastErrorCode != nil {
		v := api.AgentRuntimeStatusLastErrorCode(*status.LastErrorCode)
		lastError = &v
	}
	return api.GetAgentRuntimeStatus200JSONResponse{Body: api.AgentRuntimeStatus{
		DeviceId: req.DeviceId, DesiredRevision: status.DesiredRevision, AppliedRevision: status.AppliedRevision,
		LastAttemptedRevision: status.LastAttemptedRevision, ClientVersion: status.ClientVersion,
		Connectivity: api.AgentRuntimeStatusConnectivity(status.Connectivity), Health: api.AgentRuntimeStatusHealth(status.Health), Stale: status.Stale,
		LastSeenAt: status.LastSeenAt, LastErrorCode: lastError, LastErrorRevision: status.LastErrorRevision,
	}, Headers: api.GetAgentRuntimeStatus200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func runtimeUnauthorized() error {
	return apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
}

func runtimeMachineError(err error) error {
	switch {
	case errors.Is(err, agentruntime.ErrUnauthorized), errors.Is(err, agentruntime.ErrOptedOut):
		return runtimeUnauthorized()
	case errors.Is(err, agentruntime.ErrOptInUnavailable):
		return apierr.New(http.StatusForbidden, "edition_required", "managed agent runtime synchronization is unavailable in this edition")
	case errors.Is(err, agentruntime.ErrInvalidReport):
		return apierr.New(http.StatusBadRequest, "invalid_runtime_report", "runtime report is not acceptable")
	default:
		return apierr.New(http.StatusServiceUnavailable, "runtime_unavailable", "managed agent runtime is temporarily unavailable")
	}
}

func runtimeHumanError(err error) error {
	if errors.Is(err, agentruntime.ErrOptedOut) {
		return apierr.New(http.StatusForbidden, "f04_runtime_opt_in_required", "managed agent runtime synchronization is not enabled for this organization")
	}
	return runtimeMachineError(err)
}

func runtimeAuthMiddleware(svc *agentruntime.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isRuntimeChannelPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			var id agentruntime.Identity
			var err error
			if r.URL.Path == "/api/v1/agent/runtime/credential-candidate" || r.URL.Path == "/api/v1/agent/runtime/wireguard-candidate" {
				id, err = svc.AuthenticateCurrent(r.Context(), strings.TrimSpace(raw))
			} else {
				id, err = svc.Authenticate(r.Context(), strings.TrimSpace(raw))
			}
			if err != nil {
				apierr.Write(w, r, runtimeUnauthorized())
				return
			}
			next.ServeHTTP(w, r.WithContext(agentruntime.WithIdentity(r.Context(), id)))
		})
	}
}

func isRuntimeChannelPath(path string) bool {
	return path == "/api/v1/agent/runtime/poll" || path == "/api/v1/agent/runtime/report" || path == "/api/v1/agent/runtime/credential-candidate" || path == "/api/v1/agent/runtime/wireguard-candidate"
}
