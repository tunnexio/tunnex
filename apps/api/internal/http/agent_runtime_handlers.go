package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
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

func (s apiServer) GetAgentMCPInventory(ctx context.Context, req api.GetAgentMCPInventoryRequestObject) (api.GetAgentMCPInventoryResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	row, err := s.system.GetAgentMCPInventory(ctx, sqlc.GetAgentMCPInventoryParams{DeviceID: req.DeviceId, OrgID: req.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apierr.NotFound("mcp_inventory_not_found", "MCP inventory has not been observed")
	}
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_inventory_unavailable", "MCP inventory is temporarily unavailable")
	}
	var snapshot map[string]interface{}
	if err := json.Unmarshal(row.Snapshot, &snapshot); err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_inventory_unavailable", "MCP inventory is temporarily unavailable")
	}
	return api.GetAgentMCPInventory200JSONResponse{DeviceId: row.DeviceID, ObservedAt: row.ObservedAt, Snapshot: snapshot}, nil
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
	if req.Body.McpInventory != nil {
		inventory := *req.Body.McpInventory
		if req.Body.McpOauthDiscovery != nil {
			// Keep F13 discovery co-located with the F12 runtime-owned snapshot.
			// It is deliberately metadata only: no authorization header, code,
			// client secret, access token, refresh token, or session may enter it.
			if !validMCPInventoryValue(*req.Body.McpOauthDiscovery) {
				return nil, apierr.New(http.StatusBadRequest, "invalid_mcp_oauth_discovery", "MCP OAuth discovery is not acceptable")
			}
			inventory["oauth_discovery"] = *req.Body.McpOauthDiscovery
		}
		if prior, err := s.system.GetAgentMCPInventory(ctx, sqlc.GetAgentMCPInventoryParams{DeviceID: id.DeviceID, OrgID: id.OrgID}); err == nil {
			var previous map[string]interface{}
			if json.Unmarshal(prior.Snapshot, &previous) == nil {
				annotateMCPInventory(previous, inventory, time.Now().UTC())
			}
		} else {
			annotateMCPInventory(nil, inventory, time.Now().UTC())
		}
		body, err := json.Marshal(inventory)
		if err != nil || len(body) > 512<<10 || !validMCPInventoryValue(*req.Body.McpInventory) {
			return nil, apierr.New(http.StatusBadRequest, "invalid_mcp_inventory", "MCP inventory is not acceptable")
		}
		if _, err := s.system.UpsertAgentMCPInventory(ctx, sqlc.UpsertAgentMCPInventoryParams{DeviceID: id.DeviceID, OrgID: id.OrgID, Snapshot: body, ObservedAt: time.Now().UTC()}); err != nil {
			return nil, apierr.New(http.StatusServiceUnavailable, "mcp_inventory_unavailable", "MCP inventory is temporarily unavailable")
		}
	}
	return api.ReportAgentRuntime204Response{Headers: api.ReportAgentRuntime204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func annotateMCPInventory(previous, current map[string]interface{}, now time.Time) {
	seen := now.Format(time.RFC3339Nano)
	previousServers := inventoryBy(previous, "servers", "endpoint")
	for _, server := range inventoryObjects(current, "servers") {
		prior := previousServers[fmt.Sprint(server["endpoint"])]
		stampMCPItem(prior, server, seen)
		for _, group := range []struct{ key, identity string }{{"tools", "name"}, {"resources", "uri"}, {"prompts", "name"}} {
			oldItems := inventoryBy(prior, group.key, group.identity)
			for _, item := range inventoryObjects(server, group.key) {
				stampMCPItem(oldItems[fmt.Sprint(item[group.identity])], item, seen)
			}
		}
	}
}

func inventoryObjects(source map[string]interface{}, key string) []map[string]interface{} {
	if source == nil {
		return nil
	}
	values, _ := source[key].([]interface{})
	out := make([]map[string]interface{}, 0, len(values))
	for _, value := range values {
		if object, ok := value.(map[string]interface{}); ok {
			out = append(out, object)
		}
	}
	return out
}
func inventoryBy(source map[string]interface{}, key, identity string) map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	for _, object := range inventoryObjects(source, key) {
		out[fmt.Sprint(object[identity])] = object
	}
	return out
}
func stampMCPItem(previous, current map[string]interface{}, now string) {
	current["last_seen_at"] = now
	if previous == nil {
		current["first_seen_at"], current["changed"] = now, true
		return
	}
	current["first_seen_at"] = previous["first_seen_at"]
	current["changed"] = !sameMCPMetadata(previous, current)
}
func sameMCPMetadata(left, right map[string]interface{}) bool {
	scrub := func(value map[string]interface{}) []byte {
		copy := map[string]interface{}{}
		for k, v := range value {
			if k != "first_seen_at" && k != "last_seen_at" && k != "changed" {
				copy[k] = v
			}
		}
		b, _ := json.Marshal(copy)
		return b
	}
	return string(scrub(left)) == string(scrub(right))
}

func validMCPInventoryValue(value interface{}) bool {
	// Modern JSON Schema frequently nests properties through anyOf/items beyond
	// the old ten-level generic payload limit. Keep the report bounded without
	// rejecting a valid inventory merely because its schema is expressive.
	const maxDepth = 32
	var walk func(interface{}, int, bool, bool) bool
	walk = func(v interface{}, depth int, inSchema, schemaProperties bool) bool {
		if depth > maxDepth {
			return false
		}
		switch x := v.(type) {
		case map[string]interface{}:
			for key, child := range x {
				switch strings.ToLower(key) {
				case "authorization", "credential", "credentials", "token", "access_token", "refresh_token", "session", "session_id", "content", "contents", "messages", "result":
					// JSON Schema property names are inventory metadata, not MCP
					// response content. Modern servers commonly declare a property
					// named "result" (and may declare "content") in input/output
					// schemas; preserve that existing F12 contract while continuing
					// to reject those names everywhere else in the report.
					if !inSchema || !schemaProperties {
						return false
					}
				}
				lowerKey := strings.ToLower(key)
				childInSchema := inSchema || lowerKey == "input_schema" || lowerKey == "output_schema"
				childSchemaProperties := childInSchema && lowerKey == "properties"
				if len(key) > 128 || !walk(child, depth+1, childInSchema, childSchemaProperties) {
					return false
				}
			}
		case []interface{}:
			if len(x) > 2048 {
				return false
			}
			for _, child := range x {
				if !walk(child, depth+1, inSchema, schemaProperties) {
					return false
				}
			}
		case string:
			return len(x) <= 4096
		}
		return true
	}
	return walk(value, 0, false, false)
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
			if r.URL.Path == "/api/v1/agent/runtime/credential-candidate" || r.URL.Path == "/api/v1/agent/runtime/wireguard-candidate" || r.URL.Path == "/api/v1/agent/runtime/workflow-signing-key" || r.URL.Path == "/api/v1/agent/runtime/workflow-provenance" {
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
	return path == "/api/v1/agent/runtime/poll" || path == "/api/v1/agent/runtime/report" || path == "/api/v1/agent/runtime/credential-candidate" || path == "/api/v1/agent/runtime/wireguard-candidate" || path == "/api/v1/agent/runtime/mcp-tool-policy" || path == "/api/v1/agent/runtime/mcp-oauth-lease" || path == "/api/v1/agent/runtime/mcp-tool-approval-permit" || path == "/api/v1/agent/runtime/workflow-signing-key" || path == "/api/v1/agent/runtime/workflow-provenance"
}
