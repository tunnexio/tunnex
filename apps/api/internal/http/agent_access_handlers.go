package http

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type accessCheckBuilder struct {
	checks       []api.AgentAccessCheck
	firstBlocker *string
	hasFail      bool
	hasUnknown   bool
}

func (b *accessCheckBuilder) add(status api.AgentAccessCheckStatus, code, message string, facts map[string]string) {
	if status == api.AgentAccessCheckStatusFail {
		b.hasFail = true
	}
	if status == api.AgentAccessCheckStatusInconclusive {
		b.hasUnknown = true
	}
	if b.firstBlocker == nil && status != api.AgentAccessCheckStatusPass {
		v := code
		b.firstBlocker = &v
	}
	var factPtr *map[string]string
	if len(facts) > 0 {
		factPtr = &facts
	}
	b.checks = append(b.checks, api.AgentAccessCheck{Status: status, Code: code, Message: message, Facts: factPtr})
}

func (b *accessCheckBuilder) overall() api.AgentAccessDiagnosticOverall {
	if b.hasFail {
		return api.AgentAccessDiagnosticOverallDenied
	}
	if b.hasUnknown {
		return api.AgentAccessDiagnosticOverallInconclusive
	}
	return api.AgentAccessDiagnosticOverallAllowed
}

func (s apiServer) TestAgentAccess(ctx context.Context, req api.TestAgentAccessRequestObject) (api.TestAgentAccessResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, apierr.New(503, "agent_diagnostic_unavailable", "agent policy diagnostic service is unavailable")
	}
	if s.nodes == nil || s.agentRuntime == nil {
		return nil, apierr.New(500, "agent_diagnostic_unavailable", "agent diagnostic services are unavailable")
	}

	agents, err := s.nodes.ListAgents(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	var agentFound bool
	var agentAddress string
	var agentStatus string
	var nodeID uuid.UUID
	var gatewayName string
	var gatewayReporting bool
	for _, row := range agents {
		if row.DeviceID != req.DeviceId {
			continue
		}
		agentFound = true
		agentStatus = row.Status
		nodeID = row.NodeID
		gatewayName = row.GatewayName
		gatewayReporting = agentGatewayReporting(row.StatusReportedAt, row.GatewayLastSeenAt)
		if row.Address != nil {
			agentAddress = *row.Address
		}
		break
	}
	if !agentFound {
		return nil, apierr.NotFound("agent_not_found", "agent not found")
	}

	destination := strings.TrimSpace(req.Params.Destination)
	protocol := string(req.Params.Protocol)
	if destination == "" || len(destination) > 253 || (protocol != "tcp" && protocol != "udp") || req.Params.Port < 1 || req.Params.Port > 65535 {
		return nil, apierr.New(400, "invalid_agent_access_tuple", "destination, protocol, or port is invalid")
	}
	b := accessCheckBuilder{}
	if agentStatus == "active" && agentAddress != "" {
		b.add(api.AgentAccessCheckStatusPass, "agent_active", "Agent identity is active and has a tunnel address.", map[string]string{"address": agentAddress})
	} else {
		b.add(api.AgentAccessCheckStatusFail, "agent_not_active", "Agent lifecycle is not active.", map[string]string{"status": agentStatus})
	}

	runtimeStatus, runtimeErr := s.agentRuntime.Status(ctx, req.OrgId, req.DeviceId)
	if errors.Is(runtimeErr, agentruntime.ErrOptedOut) {
		b.add(api.AgentAccessCheckStatusFail, "runtime_not_enabled", "Managed runtime synchronization is disabled for this organization.", nil)
	} else if runtimeErr != nil {
		b.add(api.AgentAccessCheckStatusInconclusive, "runtime_status_unavailable", "Managed runtime status is unavailable.", nil)
	} else if runtimeStatus.Health == "ready" && !runtimeStatus.Stale && runtimeStatus.AppliedRevision == runtimeStatus.DesiredRevision {
		b.add(api.AgentAccessCheckStatusPass, "runtime_ready", "Runtime has freshly applied the desired configuration.", map[string]string{
			"desired_revision": strconv.FormatInt(runtimeStatus.DesiredRevision, 10), "applied_revision": strconv.FormatInt(runtimeStatus.AppliedRevision, 10),
		})
	} else {
		b.add(api.AgentAccessCheckStatusFail, "runtime_not_ready", "Runtime configuration is stale, unapplied, or not ready.", map[string]string{
			"health": runtimeStatus.Health, "desired_revision": strconv.FormatInt(runtimeStatus.DesiredRevision, 10), "applied_revision": strconv.FormatInt(runtimeStatus.AppliedRevision, 10),
		})
	}

	if gatewayReporting {
		b.add(api.AgentAccessCheckStatusPass, "gateway_reporting", "Assigned gateway is reporting agent status.", map[string]string{"gateway": gatewayName})
	} else {
		b.add(api.AgentAccessCheckStatusFail, "gateway_not_reporting", "Assigned gateway is not providing fresh agent status.", map[string]string{"gateway": gatewayName})
	}

	dstIP, dstErr := netip.ParseAddr(destination)
	if dstErr == nil {
		b.add(api.AgentAccessCheckStatusPass, "destination_ip", "Destination is a literal IP; DNS is not required.", map[string]string{"ip": dstIP.String()})
	} else {
		b.add(api.AgentAccessCheckStatusInconclusive, "agent_dns_not_observed", "Tunnex has no agent-side DNS observation for this hostname; enter its resolved IP to continue.", nil)
	}

	nodeRows, nodeErr := s.nodes.ListNodes(ctx, req.OrgId)
	var assigned *nodes.PolicyHealth
	var assignedNode *sqlc.Node
	var policyReported bool
	var policyResult policyspec.AccessEvaluation
	var gatewayRoutes []string
	policyErr := nodeErr
	if nodeErr == nil {
		batch := s.nodes.LoadSiteTopoBatch(ctx, req.OrgId, nodeRows)
		health := s.nodes.PolicyHealthForNodes(ctx, req.OrgId, nodeRows, batch)
		for i := range nodeRows {
			if nodeRows[i].ID != nodeID {
				continue
			}
			assignedNode = &nodeRows[i]
			h := health[nodeID]
			assigned = &h
			policyReported = nodeRows[i].PolicyReportedAt.Valid
			break
		}
		if assignedNode == nil {
			policyErr = errors.New("assigned gateway unavailable")
		} else {
			policyResult, gatewayRoutes, policyErr = s.nodes.EvaluateAgentAccess(ctx, req.OrgId, req.DeviceId, *assignedNode, agentAddress, destination, protocol, req.Params.Port, batch)
		}
	}

	if dstErr != nil {
		b.add(api.AgentAccessCheckStatusInconclusive, "route_destination_unresolved", "Route intent cannot be evaluated without the agent-resolved destination IP.", nil)
	} else if intent, routeErr := s.agentRuntime.RouteIntent(ctx, req.OrgId, req.DeviceId); routeErr != nil {
		b.add(api.AgentAccessCheckStatusInconclusive, "route_intent_unavailable", "Current managed route intent is unavailable.", nil)
	} else if agentRoute := matchingPrefix(intent.AllowedIPs, dstIP); agentRoute != "" {
		facts := map[string]string{"agent_allowed_ip": agentRoute}
		if gatewayRoute := matchingPrefix(gatewayRoutes, dstIP); gatewayRoute != "" {
			facts["gateway_route"] = gatewayRoute
		}
		b.add(api.AgentAccessCheckStatusPass, "route_configured", "Current managed agent configuration routes the destination through its gateway.", facts)
	} else {
		b.add(api.AgentAccessCheckStatusFail, "route_not_configured", "Current managed agent configuration has no route for the destination.", nil)
	}
	if policyErr != nil {
		b.add(api.AgentAccessCheckStatusInconclusive, "compiled_policy_unavailable", "The exact compiled policy could not be evaluated.", nil)
	} else if dstErr != nil {
		b.add(api.AgentAccessCheckStatusInconclusive, "policy_destination_unresolved", "Compiled policy requires the agent-resolved destination IP.", policyFacts(policyResult))
	} else if policyResult.Allowed {
		code := "matching_grant"
		message := "The exact compiled policy permits this tuple."
		if policyResult.Mode == "off" {
			code, message = "policy_not_enforcing", "Zero Trust enforcement is off; the compiled mesh permits this tuple."
		}
		b.add(api.AgentAccessCheckStatusPass, code, message, policyFacts(policyResult))
	} else {
		b.add(api.AgentAccessCheckStatusFail, "no_matching_grant", "No active compiled grant permits this tuple.", policyFacts(policyResult))
	}

	if policyResult.Mode == "off" {
		b.add(api.AgentAccessCheckStatusPass, "applied_policy_not_required", "Zero Trust enforcement is off; no applied enforcement hash is required.", nil)
	} else if assigned == nil || !assigned.PushKnown || !policyReported || assigned.AppliedHash == "" || assigned.PushedHash == "" {
		b.add(api.AgentAccessCheckStatusInconclusive, "applied_policy_not_observed", "Gateway has not reported enough applied-policy evidence.", nil)
	} else if assigned.Degraded || assigned.AppliedHash != assigned.PushedHash {
		b.add(api.AgentAccessCheckStatusFail, "applied_policy_mismatch", "Gateway applied policy does not agree with the current compiled policy.", map[string]string{"health": string(assigned.Kind)})
	} else {
		b.add(api.AgentAccessCheckStatusPass, "applied_policy_current", "Gateway reports the current compiled policy in force.", map[string]string{"policy_hash": assigned.PushedHash})
	}

	body := api.AgentAccessDiagnostic{DeviceId: req.DeviceId, Destination: destination, Protocol: api.AgentAccessDiagnosticProtocol(protocol), Port: req.Params.Port,
		Overall: b.overall(), FirstBlocker: b.firstBlocker, Checks: b.checks}
	return api.TestAgentAccess200JSONResponse{Body: body, Headers: api.TestAgentAccess200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func matchingPrefix(prefixes []string, addr netip.Addr) string {
	for _, raw := range prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(addr) {
			return raw
		}
	}
	return ""
}

func policyFacts(result policyspec.AccessEvaluation) map[string]string {
	facts := map[string]string{"mode": result.Mode}
	if result.PolicyVersion > 0 {
		facts["version"] = strconv.Itoa(result.PolicyVersion)
	}
	if result.PolicyHash != "" {
		facts["policy_hash"] = result.PolicyHash
	}
	if result.RuleID != "" {
		facts["rule_id"] = result.RuleID
	}
	return facts
}
