package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpoauth"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) ListAgentMCPOAuthConnections(ctx context.Context, req api.ListAgentMCPOAuthConnectionsRequestObject) (api.ListAgentMCPOAuthConnectionsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	if s.mcpOAuth == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_oauth_unavailable", "MCP OAuth is temporarily unavailable")
	}
	rows, err := s.mcpOAuth.List(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_oauth_unavailable", "MCP OAuth is temporarily unavailable")
	}
	out := make(api.ListAgentMCPOAuthConnections200JSONResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAPIMCPOAuthConnection(row))
	}
	return out, nil
}

func (s apiServer) StartAgentMCPOAuthConnection(ctx context.Context, req api.StartAgentMCPOAuthConnectionRequestObject) (api.StartAgentMCPOAuthConnectionResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentManage); err != nil {
		return nil, err
	}
	if req.Body == nil || s.mcpOAuth == nil {
		return nil, apierr.BadRequest("invalid_request", "MCP OAuth connection details are required")
	}
	if !observedMCPTrust(ctx, s.system, req.OrgId, req.DeviceId, req.Body.Endpoint, req.Body.ProtectedResource, req.Body.Issuer) {
		return nil, apierr.BadRequest("unobserved_mcp_trust", "the requested MCP protected-resource trust was not observed on this agent")
	}
	secret := ""
	if req.Body.ClientSecret != nil {
		secret = *req.Body.ClientSecret
	}
	started, err := s.mcpOAuth.Start(ctx, mcpoauth.StartInput{OrgID: req.OrgId, DeviceID: req.DeviceId, ActorID: actorID(ctx), Endpoint: req.Body.Endpoint, Resource: req.Body.ProtectedResource, Issuer: req.Body.Issuer, Scopes: req.Body.Scopes, ClientID: req.Body.ClientId, ClientSecret: secret})
	if err != nil {
		return nil, mapMCPOAuthError(err)
	}
	return api.StartAgentMCPOAuthConnection201JSONResponse(api.AgentMCPOAuthConsentStart{ConnectionId: started.ConnectionID, AuthorizationUrl: started.RedirectURL, State: api.AgentMCPOAuthConsentStartStatePendingConsent}), nil
}

type mcpOAuthCallbackResponse struct{ location string }

func (r mcpOAuthCallbackResponse) VisitMcpOAuthCallbackResponse(w http.ResponseWriter) error {
	w.Header().Set("Location", r.location)
	w.WriteHeader(http.StatusFound)
	return nil
}

func (s apiServer) McpOAuthCallback(ctx context.Context, req api.McpOAuthCallbackRequestObject) (api.McpOAuthCallbackResponseObject, error) {
	if s.mcpOAuth == nil {
		return mcpOAuthCallbackResponse{location: s.appBaseURL + "/agents?mcp_oauth=failed"}, nil
	}
	if err := s.mcpOAuth.Complete(ctx, req.Params.State, req.Params.Code); err != nil {
		return mcpOAuthCallbackResponse{location: s.appBaseURL + "/agents?mcp_oauth=failed"}, nil
	}
	return mcpOAuthCallbackResponse{location: s.appBaseURL + "/agents?mcp_oauth=connected"}, nil
}

func toAPIMCPOAuthConnection(row mcpoauth.Connection) api.AgentMCPOAuthConnection {
	return api.AgentMCPOAuthConnection{Id: row.ID, Endpoint: row.Endpoint, ProtectedResource: row.Resource, Issuer: row.Issuer, Scopes: row.Scopes, ClientId: row.ClientID, ClientSecretFingerprint: row.ClientSecretFingerprint, State: api.AgentMCPOAuthConnectionState(row.State), FailureCode: row.FailureCode, TokenExpiresAt: row.TokenExpiresAt, ConnectedAt: row.ConnectedAt, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func mapMCPOAuthError(err error) error {
	if errors.Is(err, mcpoauth.ErrAlreadyConnected) {
		return apierr.Conflict("mcp_oauth_already_connected", "this MCP OAuth connection is already connected")
	}
	if errors.Is(err, mcpoauth.ErrInvalidInput) || errors.Is(err, mcpoauth.ErrMetadata) {
		return apierr.BadRequest("invalid_mcp_oauth", "MCP OAuth issuer metadata or connection details are not acceptable")
	}
	return apierr.New(http.StatusServiceUnavailable, "mcp_oauth_unavailable", "MCP OAuth is temporarily unavailable")
}

func observedMCPTrust(ctx context.Context, queries *sqlc.Queries, orgID, deviceID uuid.UUID, endpoint, resource, issuer string) bool {
	if queries == nil {
		return false
	}
	row, err := queries.GetAgentMCPInventory(ctx, sqlc.GetAgentMCPInventoryParams{OrgID: orgID, DeviceID: deviceID})
	if err != nil {
		return false
	}
	var snapshot struct {
		OAuthDiscovery struct {
			Servers []struct {
				Endpoint             string   `json:"endpoint"`
				Status               string   `json:"status"`
				ProtectedResource    string   `json:"protected_resource"`
				AuthorizationServers []string `json:"authorization_servers"`
			} `json:"servers"`
		} `json:"oauth_discovery"`
	}
	if json.Unmarshal(row.Snapshot, &snapshot) != nil {
		return false
	}
	for _, server := range snapshot.OAuthDiscovery.Servers {
		if server.Endpoint == endpoint && server.Status == "protected" && server.ProtectedResource == resource {
			for _, candidate := range server.AuthorizationServers {
				if strings.TrimSuffix(candidate, "/") == strings.TrimSuffix(issuer, "/") {
					return true
				}
			}
		}
	}
	return false
}
