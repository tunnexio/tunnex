package http

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolpolicy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) GetRuntimeMCPToolPolicy(ctx context.Context, req api.GetRuntimeMCPToolPolicyRequestObject) (api.GetRuntimeMCPToolPolicyResponseObject, error) {
	id, ok := agentruntime.IdentityFromContext(ctx)
	if !ok {
		return nil, runtimeUnauthorized()
	}
	if s.mcpToolPolicy == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_policy_unavailable", "MCP tool policy is temporarily unavailable")
	}
	p, err := s.mcpToolPolicy.Runtime(ctx, id.OrgID, id.DeviceID, time.Now())
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_policy_unavailable", "MCP tool policy is temporarily unavailable")
	}
	return api.GetRuntimeMCPToolPolicy200JSONResponse(toAPIRuntimeMCPToolPolicy(p)), nil
}

func (s apiServer) GetRuntimeMCPOAuthLease(ctx context.Context, req api.GetRuntimeMCPOAuthLeaseRequestObject) (api.GetRuntimeMCPOAuthLeaseResponseObject, error) {
	id, ok := agentruntime.IdentityFromContext(ctx)
	if !ok {
		return nil, runtimeUnauthorized()
	}
	if s.mcpOAuth == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_oauth_unavailable", "MCP OAuth is temporarily unavailable")
	}
	token, expires, err := s.mcpOAuth.Lease(ctx, id.OrgID, id.DeviceID, req.Params.Endpoint)
	if err != nil {
		// A runtime caller learns only that it cannot use a credential. It gets
		// no connection identifier, issuer detail, or sealed-material distinction.
		return nil, apierr.New(http.StatusBadGateway, "mcp_oauth_lease_unavailable", "MCP OAuth authorization is unavailable")
	}
	return api.GetRuntimeMCPOAuthLease200JSONResponse{
		Body:    api.RuntimeMCPOAuthLease{AccessToken: &token, ExpiresAt: expires},
		Headers: api.GetRuntimeMCPOAuthLease200ResponseHeaders{CacheControl: "no-store"},
	}, nil
}

func (s apiServer) GetAgentMCPToolPolicy(ctx context.Context, req api.GetAgentMCPToolPolicyRequestObject) (api.GetAgentMCPToolPolicyResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	if s.mcpToolPolicy == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_policy_unavailable", "MCP tool policy is temporarily unavailable")
	}
	p, err := s.mcpToolPolicy.Get(ctx, req.OrgId, req.DeviceId)
	if errors.Is(err, mcptoolpolicy.ErrNotFound) {
		return nil, apierr.NotFound("mcp_tool_policy_not_found", "MCP tool policy has not been configured")
	}
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_policy_unavailable", "MCP tool policy is temporarily unavailable")
	}
	return api.GetAgentMCPToolPolicy200JSONResponse(toAPIMCPToolPolicy(p)), nil
}

func (s apiServer) ReplaceAgentMCPToolPolicy(ctx context.Context, req api.ReplaceAgentMCPToolPolicyRequestObject) (api.ReplaceAgentMCPToolPolicyResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolPolicyManage); err != nil {
		return nil, err
	}
	if req.Body == nil || s.mcpToolPolicy == nil {
		return nil, apierr.BadRequest("invalid_mcp_tool_policy", "MCP tool policy rules are required")
	}
	rules := make([]mcptoolpolicy.Rule, 0, len(req.Body.Rules))
	for _, rule := range req.Body.Rules {
		rules = append(rules, mcptoolpolicy.Rule{Endpoint: rule.Endpoint, ServerName: rule.ServerName, ToolName: rule.ToolName, InputSchemaHash: rule.InputSchemaHash})
	}
	p, err := s.mcpToolPolicy.Replace(ctx, req.OrgId, req.DeviceId, actorID(ctx), rules)
	if errors.Is(err, mcptoolpolicy.ErrNotFound) {
		return nil, apierr.NotFound("mcp_inventory_not_found", "MCP inventory has not been observed")
	}
	if errors.Is(err, mcptoolpolicy.ErrInvalid) {
		return nil, apierr.BadRequest("invalid_mcp_tool_policy", "MCP tool policy is not acceptable")
	}
	if errors.Is(err, mcptoolpolicy.ErrUnobservedTool) {
		return nil, apierr.BadRequest("unobserved_mcp_tool", "MCP tool policy may only allow tools in the observed inventory")
	}
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_policy_unavailable", "MCP tool policy is temporarily unavailable")
	}
	return api.ReplaceAgentMCPToolPolicy200JSONResponse(toAPIMCPToolPolicy(p)), nil
}

func toAPIMCPToolPolicy(p mcptoolpolicy.Policy) api.AgentMCPToolPolicy {
	rules := make([]api.MCPToolPolicyRule, 0, len(p.Rules))
	for _, rule := range p.Rules {
		rules = append(rules, api.MCPToolPolicyRule{Endpoint: rule.Endpoint, ServerName: rule.ServerName, ToolName: rule.ToolName, InputSchemaHash: rule.InputSchemaHash})
	}
	return api.AgentMCPToolPolicy{Version: p.Version, Rules: rules, InventoryObservedAt: p.InventoryObservedAt, CreatedAt: p.CreatedAt}
}

func toAPIRuntimeMCPToolPolicy(p mcptoolpolicy.Policy) api.RuntimeMCPToolPolicy {
	rules := make([]api.MCPToolPolicyRule, 0, len(p.Rules))
	for _, rule := range p.Rules {
		rules = append(rules, api.MCPToolPolicyRule{Endpoint: rule.Endpoint, ServerName: rule.ServerName, ToolName: rule.ToolName, InputSchemaHash: rule.InputSchemaHash})
	}
	return api.RuntimeMCPToolPolicy{Version: p.Version, Rules: rules, InventoryObservedAt: &p.InventoryObservedAt}
}
