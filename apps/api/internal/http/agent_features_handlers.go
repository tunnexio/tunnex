package http

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

// AI-UX-1: the agent and MCP switches, whether the current plan can use each one, and the live status of
// an install token.

// requireAgentRuntimePlan refuses when the deployment's plan does not include runtime synchronization. It
// reads the same licence manager, with the same rule, that the runtime service applies on every poll, so
// a switch that saves is a switch that works.
func (s apiServer) requireAgentRuntimePlan() error {
	if !tenancy.AgentRuntimeUnlocked(s.licence.Evaluate(time.Now()).Tier) {
		return tenancy.AgentRuntimeFeatureRequired()
	}
	return nil
}

// GetOrganizationMCPSetting GET /api/v1/organizations/{orgId}/mcp-settings.
func (s apiServer) GetOrganizationMCPSetting(ctx context.Context, req api.GetOrganizationMCPSettingRequestObject) (api.GetOrganizationMCPSettingResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if s.orgs == nil {
		return nil, apierr.Internal()
	}
	enabled, err := s.orgs.MCPEnabled(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetOrganizationMCPSetting200JSONResponse{Body: api.MCPSetting{Enabled: enabled}, Headers: api.GetOrganizationMCPSetting200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// SetOrganizationMCPEnabled PUT /api/v1/organizations/{orgId}/mcp-settings. MCP is part of every plan, so
// there is no plan refusal here today; the organization only has to turn it on.
func (s apiServer) SetOrganizationMCPEnabled(ctx context.Context, req api.SetOrganizationMCPEnabledRequestObject) (api.SetOrganizationMCPEnabledResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermMCPManage)
	if err != nil {
		return nil, err
	}
	if s.agentTemplates == nil {
		return nil, agentTemplateServiceUnavailable()
	}
	if s.orgs == nil {
		return nil, apierr.Internal()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	enabled, err := s.orgs.SetMCPEnabled(ctx, req.OrgId, req.Body.Enabled)
	if err != nil {
		return nil, err
	}
	return api.SetOrganizationMCPEnabled200JSONResponse{Body: api.MCPSetting{Enabled: enabled}, Headers: api.SetOrganizationMCPEnabled200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// agentFeatureSwitches is each organization switch as saved.
type agentFeatureSwitches struct {
	runtimeSync, agentGroups, mcp, agentJIT bool
}

// paidPlans are the plans a deployment can move to, lowest first. A trial is not one of them.
var paidPlans = []licence.Tier{licence.TierStarter, licence.TierGrowth, licence.TierScale}

// lowestPlan names the lowest plan that passes includes.
func lowestPlan(includes func(licence.Tier) bool) *string {
	for _, tier := range paidPlans {
		if includes(tier) {
			name := string(tier)
			return &name
		}
	}
	return nil
}

// agentFeatureItems is the fixed-order answer of GET agent-features for a plan. Each `available` is
// computed by the same rule the feature's own switch enforces, so the page never offers a switch that
// fails after the click. Agent groups and MCP are part of every plan.
func agentFeatureItems(tier licence.Tier, on agentFeatureSwitches) []api.AgentFeature {
	item := func(key api.AgentFeatureKey, enabled bool, includes func(licence.Tier) bool) api.AgentFeature {
		out := api.AgentFeature{Key: key, Enabled: enabled, Available: includes(tier)}
		if !out.Available {
			out.RequiredPlan = lowestPlan(includes)
		}
		return out
	}
	everyPlan := func(licence.Tier) bool { return true }
	return []api.AgentFeature{
		item(api.AgentFeatureRuntimeSync, on.runtimeSync, tenancy.AgentRuntimeUnlocked),
		item(api.AgentFeatureAgentGroups, on.agentGroups, everyPlan),
		item(api.AgentFeatureMCP, on.mcp, everyPlan),
		item(api.AgentFeatureAgentJIT, on.agentJIT, func(t licence.Tier) bool { return licence.Has(t, licence.FeatAgentJITAccess) }),
	}
}

// ListAgentFeatures GET /api/v1/organizations/{orgId}/agent-features.
func (s apiServer) ListAgentFeatures(ctx context.Context, req api.ListAgentFeaturesRequestObject) (api.ListAgentFeaturesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if s.orgs == nil {
		return nil, apierr.Internal()
	}
	org, err := s.orgs.GetOrganization(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	mcp, err := s.orgs.MCPEnabled(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	items := agentFeatureItems(s.licence.Evaluate(time.Now()).Tier, agentFeatureSwitches{
		runtimeSync: org.ManagedAgentRuntimeEnabled, agentGroups: org.AgentPolicyTemplatesEnabled,
		mcp: mcp, agentJIT: org.AgentJitAccessEnabled,
	})
	return api.ListAgentFeatures200JSONResponse{Body: api.AgentFeatureList{Items: items}, Headers: api.ListAgentFeatures200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// GetAgentBootstrapTokenStatus GET /api/v1/organizations/{orgId}/agents/bootstrap-tokens/{tokenId}: what
// became of one install token. Same permission as issuing one. A token of another organization is not
// found, and the answer never carries the token value or its hash.
func (s apiServer) GetAgentBootstrapTokenStatus(ctx context.Context, req api.GetAgentBootstrapTokenStatusRequestObject) (api.GetAgentBootstrapTokenStatusResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentEnroll); err != nil {
		return nil, err
	}
	if s.system == nil {
		return nil, apierr.Internal()
	}
	row, err := s.system.GetAgentBootstrapTokenStatus(ctx, sqlc.GetAgentBootstrapTokenStatusParams{ID: req.TokenId, OrgID: req.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apierr.NotFound("bootstrap_token_not_found", "This install token was not found.")
	}
	if err != nil {
		return nil, apierr.Internal()
	}
	return api.GetAgentBootstrapTokenStatus200JSONResponse{Body: toAPIBootstrapTokenStatus(row, time.Now()), Headers: api.GetAgentBootstrapTokenStatus200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// toAPIBootstrapTokenStatus derives the state and the tunnel facts. A used token is enrolled whatever
// happened afterwards; otherwise a revoked one is revoked and one past its time is expired.
//
// The tunnel facts use the agents list's own helpers (deviceOnline, agentGatewayReporting), so the install
// step and the list can never disagree about the same handshake. When the gateway is not reporting,
// `connected` is unknown rather than offline; the caller reads gateway_reporting first.
func toAPIBootstrapTokenStatus(row sqlc.GetAgentBootstrapTokenStatusRow, now time.Time) api.AgentBootstrapTokenStatus {
	out := api.AgentBootstrapTokenStatus{Id: row.ID, AgentName: row.AgentName, ExpiresAt: row.ExpiresAt}
	switch {
	case row.ConsumedAt.Valid:
		out.State = api.AgentBootstrapTokenEnrolled
		enrolledAt := row.ConsumedAt.Time
		out.EnrolledAt = &enrolledAt
	case row.RevokedAt.Valid:
		out.State = api.AgentBootstrapTokenRevoked
	case !row.ExpiresAt.After(now):
		out.State = api.AgentBootstrapTokenExpired
	default:
		out.State = api.AgentBootstrapTokenPending
	}
	// DeviceID is set only while the agent the token enrolled still exists.
	if out.State != api.AgentBootstrapTokenEnrolled || !row.DeviceID.Valid {
		return out
	}
	deviceID := uuid.UUID(row.DeviceID.Bytes)
	out.DeviceId = &deviceID
	tunnel := api.AgentBootstrapTunnelStatus{GatewayReporting: agentGatewayReporting(row.StatusReportedAt, row.GatewayLastSeenAt)}
	if row.LastHandshakeAt.Valid {
		handshake := row.LastHandshakeAt.Time
		tunnel.LastHandshakeAt = &handshake
	}
	tunnel.Connected = deviceOnline(tunnel.LastHandshakeAt)
	out.Tunnel = &tunnel
	return out
}
