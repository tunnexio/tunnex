package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agenttemplates"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type agentTemplatePort interface {
	ListGroups(context.Context, uuid.UUID) ([]sqlc.ListAgentGroupsRow, error)
	CreateGroup(context.Context, uuid.UUID, uuid.UUID, string, string) (sqlc.AgentGroup, error)
	UpdateGroup(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, string) (sqlc.AgentGroup, error)
	ArchiveGroup(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (agenttemplates.RemovalImpact, error)
	ListMembers(context.Context, uuid.UUID, uuid.UUID) ([]sqlc.ListAgentGroupMembersRow, error)
	AddMember(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (bool, error)
	RemoveMember(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (agenttemplates.RemovalImpact, error)
	ListTemplates(context.Context, uuid.UUID) ([]sqlc.AgentPolicyTemplate, error)
	ListVersions(context.Context, uuid.UUID, uuid.UUID) ([]sqlc.AgentPolicyTemplateVersion, error)
	CreateTemplate(context.Context, uuid.UUID, uuid.UUID, string, string) (sqlc.AgentPolicyTemplate, error)
	UpdateTemplate(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, string) (sqlc.AgentPolicyTemplate, error)
	ArchiveTemplate(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error
	CreateVersion(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, []agenttemplates.ItemInput) (sqlc.AgentPolicyTemplateVersion, error)
	Preview(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (agenttemplates.Preview, error)
	Apply(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, string, string) (agenttemplates.ApplyResult, error)
	ListAssignments(context.Context, uuid.UUID) ([]agenttemplates.Assignment, error)
	RemoveAssignment(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (agenttemplates.RemovalImpact, error)
	SetEnabled(context.Context, uuid.UUID, uuid.UUID, bool) (bool, error)
	ListMCPAssignments(context.Context, uuid.UUID, *string) ([]agenttemplates.MCPAssignment, error)
	PreviewMCPProfileImpact(context.Context, uuid.UUID, uuid.UUID, *uuid.UUID) (agenttemplates.MCPImpact, error)
	SetGroupMCPProfile(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (agenttemplates.MCPMutation, error)
	UnassignGroupMCPProfile(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (agenttemplates.MCPMutation, error)
	ArchiveMCPProfile(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error
	CreateMCPProfile(context.Context, uuid.UUID, uuid.UUID, string, string) (sqlc.AgentMcpProfile, error)
}

func agentTemplateServiceUnavailable() error {
	return apierr.New(http.StatusServiceUnavailable, "agent_templates_unavailable", "agent groups and profiles are temporarily unavailable")
}

func requireAgentTemplates(s apiServer, ctx context.Context, orgID uuid.UUID) error {
	if s.agentTemplates == nil {
		return agentTemplateServiceUnavailable()
	}
	if s.system == nil {
		return apierr.Internal()
	}
	enabled, err := s.system.GetOrganizationAgentPolicyTemplatesEnabled(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.NotFound("org_not_found", "organization not found")
	}
	if err != nil {
		return err
	}
	if !enabled {
		return apierr.Forbidden("opt_in_required", "enable agent groups and policy templates in organization settings first")
	}
	return nil
}

func (s apiServer) requireAgentTemplates(ctx context.Context, orgID uuid.UUID) error {
	return requireAgentTemplates(s, ctx, orgID)
}

func (s apiServer) ListAgentMCPProfiles(ctx context.Context, req api.ListAgentMCPProfilesRequestObject) (api.ListAgentMCPProfilesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.system.ListAgentMCPProfiles(ctx, req.OrgId)
	if err != nil {
		return nil, apierr.Internal()
	}
	out := make([]api.AgentMCPProfile, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAPIAgentMCPProfile(row))
	}
	return api.ListAgentMCPProfiles200JSONResponse{Body: out, Headers: api.ListAgentMCPProfiles200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// GetAgentEffectiveMCPProfile exposes inheritance only. MCP profiles are assigned to groups; there is no
// individual-agent assignment path or fallback selection when an invariant violation is encountered.
func (s apiServer) GetAgentEffectiveMCPProfile(ctx context.Context, req api.GetAgentEffectiveMCPProfileRequestObject) (api.GetAgentEffectiveMCPProfileResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	if s.system == nil {
		return nil, apierr.Internal()
	}
	assignments, err := s.system.ListActiveMCPAssignmentsForDevice(ctx, sqlc.ListActiveMCPAssignmentsForDeviceParams{OrgID: req.OrgId, DeviceID: req.DeviceId})
	if err != nil {
		return nil, apierr.Internal()
	}
	if len(assignments) == 0 {
		return api.GetAgentEffectiveMCPProfile200JSONResponse{Assigned: false}, nil
	}
	if len(assignments) != 1 {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_profile_unavailable", "multiple active MCP profiles are assigned to this agent")
	}
	matched := assignments[0]
	return api.GetAgentEffectiveMCPProfile200JSONResponse{
		Assigned: true, ProfileId: &matched.ProfileID, ProfileName: &matched.ProfileName, Endpoint: &matched.Endpoint,
		GroupId: &matched.AgentGroupID, GroupName: &matched.GroupName,
	}, nil
}

func (s apiServer) CreateAgentMCPProfile(ctx context.Context, req api.CreateAgentMCPProfileRequestObject) (api.CreateAgentMCPProfileResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	name, endpoint := strings.TrimSpace(req.Body.Name), strings.TrimSpace(req.Body.Endpoint)
	u, parseErr := url.Parse(endpoint)
	if name == "" || parseErr != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, apierr.BadRequest("invalid_request", "name and credential-free absolute MCP endpoint are required")
	}
	row, err := s.agentTemplates.CreateMCPProfile(ctx, req.OrgId, actorID(ctx), name, endpoint)
	if isUniqueViolation(err) {
		return nil, apierr.Conflict("mcp_profile_conflict", "MCP profile name already exists")
	}
	if err != nil {
		return nil, apierr.Internal()
	}
	return api.CreateAgentMCPProfile201JSONResponse{Body: toAPIAgentMCPProfile(row), Headers: api.CreateAgentMCPProfile201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) AssignAgentMCPProfile(ctx context.Context, req api.AssignAgentMCPProfileRequestObject) (api.AssignAgentMCPProfileResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	m, err := s.agentTemplates.SetGroupMCPProfile(ctx, req.OrgId, req.Body.GroupId, req.ProfileId, actorID(ctx))
	if lifecycleErr := mcpLifecycleError(err); lifecycleErr != nil {
		return nil, lifecycleErr
	}
	if errors.Is(err, agenttemplates.ErrConflict) {
		return nil, apierr.Conflict("mcp_profile_assignment_conflict", "an agent may have only one MCP profile")
	}
	if err != nil {
		return nil, apierr.Internal()
	}
	if m.Assignment == nil {
		return nil, apierr.Internal()
	}
	return api.AssignAgentMCPProfile201JSONResponse{Body: toAPIMCPAssignment(*m.Assignment), Headers: api.AssignAgentMCPProfile201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func mcpLifecycleError(err error) error {
	switch {
	case errors.Is(err, agenttemplates.ErrMCPProfileNotFound):
		return apierr.NotFound("mcp_profile_not_found", "MCP profile was not found")
	case errors.Is(err, agenttemplates.ErrAgentGroupNotFound):
		return apierr.NotFound("agent_group_not_found", "agent group was not found")
	default:
		return nil
	}
}

func toAPIMCPAssignment(x agenttemplates.MCPAssignment) api.AgentMCPProfileAssignment {
	return api.AgentMCPProfileAssignment{Id: x.ID, OrgId: x.OrgID, ProfileId: x.ProfileID, ProfileName: x.ProfileName, GroupId: x.GroupID, GroupName: x.GroupName, State: api.AgentMCPProfileAssignmentState(x.State), AssignedAt: x.AssignedAt, EndedAt: x.EndedAt, QuarantineReason: x.QuarantineReason}
}
func toAPIMCPImpact(x agenttemplates.MCPImpact) api.AgentMCPProfileImpact {
	return api.AgentMCPProfileImpact{GroupId: *x.GroupID, CurrentProfileId: x.CurrentProfileID, ProposedProfileId: x.ProposedProfileID, AffectedAgentCount: int32(x.AffectedAgentCount), AffectedAgentIds: x.AffectedAgentIDs, EffectiveUpstreamChanges: x.EffectiveUpstreamChanges, DesiredRuntimeUpdatesQueued: x.DesiredRuntimeUpdatesQueued, MutationAllowed: x.MutationAllowed, Conflict: x.Conflict}
}

func (s apiServer) ListAgentMCPAssignments(ctx context.Context, req api.ListAgentMCPAssignmentsRequestObject) (api.ListAgentMCPAssignmentsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	var state *string
	if req.Params.State != nil {
		v := string(*req.Params.State)
		state = &v
	}
	rows, err := s.agentTemplates.ListMCPAssignments(ctx, req.OrgId, state)
	if err != nil {
		return nil, apierr.Internal()
	}
	out := make([]api.AgentMCPProfileAssignment, 0, len(rows))
	for _, x := range rows {
		out = append(out, toAPIMCPAssignment(x))
	}
	return api.ListAgentMCPAssignments200JSONResponse(out), nil
}

func (s apiServer) PreviewAgentGroupMCPProfileImpact(ctx context.Context, req api.PreviewAgentGroupMCPProfileImpactRequestObject) (api.PreviewAgentGroupMCPProfileImpactResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	var p *uuid.UUID
	if req.Body != nil && req.Body.ProfileId != nil {
		p = req.Body.ProfileId
	}
	i, err := s.agentTemplates.PreviewMCPProfileImpact(ctx, req.OrgId, req.GroupId, p)
	if lifecycleErr := mcpLifecycleError(err); lifecycleErr != nil {
		return nil, lifecycleErr
	}
	if err != nil {
		return nil, apierr.Internal()
	}
	return api.PreviewAgentGroupMCPProfileImpact200JSONResponse(toAPIMCPImpact(i)), nil
}

func (s apiServer) ReplaceAgentGroupMCPProfile(ctx context.Context, req api.ReplaceAgentGroupMCPProfileRequestObject) (api.ReplaceAgentGroupMCPProfileResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "profile_id is required")
	}
	m, err := s.agentTemplates.SetGroupMCPProfile(ctx, req.OrgId, req.GroupId, req.Body.ProfileId, actorID(ctx))
	if lifecycleErr := mcpLifecycleError(err); lifecycleErr != nil {
		return nil, lifecycleErr
	}
	if errors.Is(err, agenttemplates.ErrConflict) {
		return nil, apierr.Conflict("mcp_profile_assignment_conflict", "profile is archived or assignment conflicts")
	}
	if err != nil {
		return nil, apierr.Internal()
	}
	impact := toAPIMCPImpact(m.MCPImpact)
	r := api.AgentMCPProfileMutationResult{AffectedAgentCount: impact.AffectedAgentCount, AffectedAgentIds: impact.AffectedAgentIds, Conflict: impact.Conflict, CurrentProfileId: impact.CurrentProfileId, DesiredRuntimeUpdatesQueued: impact.DesiredRuntimeUpdatesQueued, EffectiveUpstreamChanges: impact.EffectiveUpstreamChanges, GroupId: impact.GroupId, MutationAllowed: impact.MutationAllowed, ProposedProfileId: impact.ProposedProfileId}
	if m.Assignment != nil {
		v := toAPIMCPAssignment(*m.Assignment)
		r.Assignment = &v
	}
	return api.ReplaceAgentGroupMCPProfile200JSONResponse(r), nil
}

func (s apiServer) UnassignAgentGroupMCPProfile(ctx context.Context, req api.UnassignAgentGroupMCPProfileRequestObject) (api.UnassignAgentGroupMCPProfileResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	m, err := s.agentTemplates.UnassignGroupMCPProfile(ctx, req.OrgId, req.GroupId, actorID(ctx))
	if lifecycleErr := mcpLifecycleError(err); lifecycleErr != nil {
		return nil, lifecycleErr
	}
	if err != nil {
		return nil, apierr.Internal()
	}
	impact := toAPIMCPImpact(m.MCPImpact)
	return api.UnassignAgentGroupMCPProfile200JSONResponse(api.AgentMCPProfileMutationResult{AffectedAgentCount: impact.AffectedAgentCount, AffectedAgentIds: impact.AffectedAgentIds, Conflict: impact.Conflict, CurrentProfileId: impact.CurrentProfileId, DesiredRuntimeUpdatesQueued: impact.DesiredRuntimeUpdatesQueued, EffectiveUpstreamChanges: impact.EffectiveUpstreamChanges, GroupId: impact.GroupId, MutationAllowed: impact.MutationAllowed, ProposedProfileId: impact.ProposedProfileId}), nil
}

func (s apiServer) ArchiveAgentMCPProfile(ctx context.Context, req api.ArchiveAgentMCPProfileRequestObject) (api.ArchiveAgentMCPProfileResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	archiveErr := s.agentTemplates.ArchiveMCPProfile(ctx, req.OrgId, req.ProfileId, actorID(ctx))
	var blocked *agenttemplates.MCPArchiveBlockedError
	if errors.As(archiveErr, &blocked) {
		return api.ArchiveAgentMCPProfile409JSONResponse{
			Body: api.AgentMCPProfileArchiveConflict{
				Code:               api.McpProfileInUse,
				ActiveGroupCount:   int32(blocked.Groups),
				AffectedAgentCount: int32(blocked.Agents),
			},
			Headers: api.ArchiveAgentMCPProfile409ResponseHeaders{XRequestId: reqID(ctx)},
		}, nil
	}
	if lifecycleErr := mcpLifecycleError(archiveErr); lifecycleErr != nil {
		return nil, lifecycleErr
	}
	if archiveErr != nil {
		return nil, apierr.Internal()
	}
	row, err := s.system.GetAgentMCPProfile(ctx, sqlc.GetAgentMCPProfileParams{ID: req.ProfileId, OrgID: req.OrgId})
	if err != nil {
		return nil, apierr.Internal()
	}
	return api.ArchiveAgentMCPProfile200JSONResponse(toAPIAgentMCPProfile(row)), nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isProfileAssignmentConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "23505" || pgErr.Code == "P0001")
}

func actorID(ctx context.Context) uuid.UUID {
	p, _ := authctx.PrincipalFrom(ctx)
	if p == nil {
		return uuid.Nil
	}
	return p.UserID
}

func (s apiServer) SetOrganizationAgentPolicyTemplatesEnabled(ctx context.Context, req api.SetOrganizationAgentPolicyTemplatesEnabledRequestObject) (api.SetOrganizationAgentPolicyTemplatesEnabledResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if s.agentTemplates == nil {
		return nil, agentTemplateServiceUnavailable()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	enabled, err := s.agentTemplates.SetEnabled(ctx, req.OrgId, actorID(ctx), req.Body.Enabled)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.SetOrganizationAgentPolicyTemplatesEnabled200JSONResponse{Body: api.AgentPolicyTemplateSetting{Enabled: enabled}, Headers: api.SetOrganizationAgentPolicyTemplatesEnabled200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) GetAgentPolicyTemplateDestinationImpact(ctx context.Context, req api.GetAgentPolicyTemplateDestinationImpactRequestObject) (api.GetAgentPolicyTemplateDestinationImpactResponseObject, error) {
	permission := rbac.PermPolicyManage
	switch req.Params.DestinationKind {
	case "resource", "group":
	case "site":
		permission = rbac.PermSiteManage
	case "k8s_service":
		permission = rbac.PermK8sManage
	default:
		return nil, apierr.BadRequest("invalid_agent_policy_template", "unsupported template destination kind")
	}
	ctx, err := authorize(ctx, req.OrgId, permission)
	if err != nil {
		return nil, err
	}
	if s.system == nil {
		return nil, apierr.Internal()
	}
	destinationID := pgtype.UUID{Bytes: req.Params.DestinationId, Valid: true}
	var versions int64
	switch req.Params.DestinationKind {
	case "resource":
		versions, err = s.system.CountAgentPolicyTemplateResourceReferences(ctx, sqlc.CountAgentPolicyTemplateResourceReferencesParams{OrgID: req.OrgId, DstResourceID: destinationID})
	case "group":
		versions, err = s.system.CountAgentPolicyTemplateGroupReferences(ctx, sqlc.CountAgentPolicyTemplateGroupReferencesParams{OrgID: req.OrgId, DstGroupID: destinationID})
	case "site":
		versions, err = s.system.CountAgentPolicyTemplateSiteReferences(ctx, sqlc.CountAgentPolicyTemplateSiteReferencesParams{OrgID: req.OrgId, DstSiteID: destinationID})
	case "k8s_service":
		versions, err = s.system.CountAgentPolicyTemplateK8sServiceReferences(ctx, sqlc.CountAgentPolicyTemplateK8sServiceReferencesParams{OrgID: req.OrgId, DstK8sServiceID: destinationID})
	}
	if err != nil {
		return nil, err
	}
	return api.GetAgentPolicyTemplateDestinationImpact200JSONResponse{
		Body:    api.AgentPolicyTemplateDestinationImpact{VersionCount: int(versions)},
		Headers: api.GetAgentPolicyTemplateDestinationImpact200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

func (s apiServer) ListAgentGroups(ctx context.Context, req api.ListAgentGroupsRequestObject) (api.ListAgentGroupsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := requireAgentTemplates(s, ctx, req.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.agentTemplates.ListGroups(ctx, req.OrgId)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	out := make([]api.AgentGroup, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAPIAgentGroupList(row))
	}
	return api.ListAgentGroups200JSONResponse{Body: out, Headers: api.ListAgentGroups200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) CreateAgentGroup(ctx context.Context, req api.CreateAgentGroupRequestObject) (api.CreateAgentGroupResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	row, err := s.agentTemplates.CreateGroup(ctx, req.OrgId, actorID(ctx), req.Body.Name, deref(req.Body.Description))
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	group, err := s.agentGroupListResponse(ctx, req.OrgId, row.ID)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.CreateAgentGroup201JSONResponse{Body: group, Headers: api.CreateAgentGroup201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) UpdateAgentGroup(ctx context.Context, req api.UpdateAgentGroupRequestObject) (api.UpdateAgentGroupResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	row, err := s.agentTemplates.UpdateGroup(ctx, req.OrgId, req.GroupId, actorID(ctx), req.Body.Name, deref(req.Body.Description))
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	group, err := s.agentGroupListResponse(ctx, req.OrgId, row.ID)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.UpdateAgentGroup200JSONResponse{Body: group, Headers: api.UpdateAgentGroup200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ArchiveAgentGroup(ctx context.Context, req api.ArchiveAgentGroupRequestObject) (api.ArchiveAgentGroupResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	impact, err := s.agentTemplates.ArchiveGroup(ctx, req.OrgId, req.GroupId, actorID(ctx))
	if errors.Is(err, agenttemplates.ErrConflict) {
		return nil, apierr.Conflict("agent_group_not_empty", fmt.Sprintf("remove %d members, %d policy-template assignments, and %d active MCP profile assignments (%d generated rules) before archiving", impact.Members, impact.Assignments, impact.MCPAssignments, impact.GeneratedRules))
	}
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.ArchiveAgentGroup204Response{}, nil
}

func (s apiServer) ListAgentGroupMembers(ctx context.Context, req api.ListAgentGroupMembersRequestObject) (api.ListAgentGroupMembersResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.agentTemplates.ListMembers(ctx, req.OrgId, req.GroupId)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	out := make([]api.AgentGroupMember, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.AgentGroupMember{DeviceId: row.ID, Name: row.Name, Status: api.AgentGroupMemberStatus(row.Status), NodeId: row.NodeID, AssignedIp: row.AssignedIp, AddedAt: row.CreatedAt})
	}
	return api.ListAgentGroupMembers200JSONResponse{Body: out, Headers: api.ListAgentGroupMembers200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) AddAgentGroupMember(ctx context.Context, req api.AddAgentGroupMemberRequestObject) (api.AddAgentGroupMemberResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if _, err := s.agentTemplates.AddMember(ctx, req.OrgId, req.GroupId, req.Body.DeviceId, actorID(ctx)); err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.AddAgentGroupMember204Response{}, nil
}

func (s apiServer) RemoveAgentGroupMember(ctx context.Context, req api.RemoveAgentGroupMemberRequestObject) (api.RemoveAgentGroupMemberResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	impact, err := s.agentTemplates.RemoveMember(ctx, req.OrgId, req.GroupId, req.DeviceId, actorID(ctx))
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.RemoveAgentGroupMember200JSONResponse{Body: toAPIAgentTemplateRemovalImpact(impact), Headers: api.RemoveAgentGroupMember200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ListAgentPolicyTemplates(ctx context.Context, req api.ListAgentPolicyTemplatesRequestObject) (api.ListAgentPolicyTemplatesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.agentTemplates.ListTemplates(ctx, req.OrgId)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	out := make([]api.AgentPolicyTemplate, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAPIAgentPolicyTemplate(row))
	}
	return api.ListAgentPolicyTemplates200JSONResponse{Body: out, Headers: api.ListAgentPolicyTemplates200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) CreateAgentPolicyTemplate(ctx context.Context, req api.CreateAgentPolicyTemplateRequestObject) (api.CreateAgentPolicyTemplateResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	row, err := s.agentTemplates.CreateTemplate(ctx, req.OrgId, actorID(ctx), req.Body.Name, deref(req.Body.Description))
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.CreateAgentPolicyTemplate201JSONResponse{Body: toAPIAgentPolicyTemplate(row), Headers: api.CreateAgentPolicyTemplate201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) UpdateAgentPolicyTemplate(ctx context.Context, req api.UpdateAgentPolicyTemplateRequestObject) (api.UpdateAgentPolicyTemplateResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	row, err := s.agentTemplates.UpdateTemplate(ctx, req.OrgId, req.TemplateId, actorID(ctx), req.Body.Name, deref(req.Body.Description))
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.UpdateAgentPolicyTemplate200JSONResponse{Body: toAPIAgentPolicyTemplate(row), Headers: api.UpdateAgentPolicyTemplate200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ArchiveAgentPolicyTemplate(ctx context.Context, req api.ArchiveAgentPolicyTemplateRequestObject) (api.ArchiveAgentPolicyTemplateResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if err := s.agentTemplates.ArchiveTemplate(ctx, req.OrgId, req.TemplateId, actorID(ctx)); err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.ArchiveAgentPolicyTemplate204Response{}, nil
}

func (s apiServer) ListAgentPolicyTemplateVersions(ctx context.Context, req api.ListAgentPolicyTemplateVersionsRequestObject) (api.ListAgentPolicyTemplateVersionsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.agentTemplates.ListVersions(ctx, req.OrgId, req.TemplateId)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	out := make([]api.AgentPolicyTemplateVersion, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.AgentPolicyTemplateVersion{Id: row.ID, TemplateId: row.TemplateID, Version: int(row.Version), CreatedAt: row.CreatedAt})
	}
	return api.ListAgentPolicyTemplateVersions200JSONResponse{Body: out, Headers: api.ListAgentPolicyTemplateVersions200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) CreateAgentPolicyTemplateVersion(ctx context.Context, req api.CreateAgentPolicyTemplateVersionRequestObject) (api.CreateAgentPolicyTemplateVersionResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	items := make([]agenttemplates.ItemInput, 0, len(req.Body.Items))
	for _, item := range req.Body.Items {
		items = append(items, agenttemplates.ItemInput{DestinationKind: string(item.DestinationKind), DestinationID: item.DestinationId})
	}
	row, err := s.agentTemplates.CreateVersion(ctx, req.OrgId, req.TemplateId, actorID(ctx), items)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.CreateAgentPolicyTemplateVersion201JSONResponse{Body: api.AgentPolicyTemplateVersion{Id: row.ID, TemplateId: row.TemplateID, Version: int(row.Version), CreatedAt: row.CreatedAt}, Headers: api.CreateAgentPolicyTemplateVersion201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) PreviewAgentPolicyTemplate(ctx context.Context, req api.PreviewAgentPolicyTemplateRequestObject) (api.PreviewAgentPolicyTemplateResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	p, err := s.agentTemplates.Preview(ctx, req.OrgId, req.Body.GroupId, req.Body.TemplateVersionId)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.PreviewAgentPolicyTemplate200JSONResponse{Body: toAPIAgentTemplatePreview(p), Headers: api.PreviewAgentPolicyTemplate200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ApplyAgentPolicyTemplate(ctx context.Context, req api.ApplyAgentPolicyTemplateRequestObject) (api.ApplyAgentPolicyTemplateResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	for _, perm := range []rbac.Permission{rbac.PermPolicyManage, rbac.PermAgentGrantAccess} {
		if _, err := authorize(ctx, req.OrgId, perm); err != nil {
			return nil, err
		}
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	result, err := s.agentTemplates.Apply(ctx, req.OrgId, req.Body.GroupId, req.Body.TemplateVersionId, actorID(ctx), req.Body.PreviewDigest, req.Body.IdempotencyKey)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.ApplyAgentPolicyTemplate200JSONResponse{Body: api.AgentPolicyTemplateApplyResult{AssignmentId: result.AssignmentID, NoOp: result.NoOp, Preview: toAPIAgentTemplatePreview(result.Preview)}, Headers: api.ApplyAgentPolicyTemplate200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ListAgentPolicyTemplateAssignments(ctx context.Context, req api.ListAgentPolicyTemplateAssignmentsRequestObject) (api.ListAgentPolicyTemplateAssignmentsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage); err != nil {
		return nil, err
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.agentTemplates.ListAssignments(ctx, req.OrgId)
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	out := make([]api.AgentPolicyTemplateAssignment, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.AgentPolicyTemplateAssignment{Id: row.ID, GroupId: row.GroupID, GroupName: row.GroupName, TemplateId: row.TemplateID, TemplateName: row.TemplateName, TemplateVersionId: row.TemplateVersionID, Version: row.Version, RuleCount: row.RuleCount, AppliedAt: row.AppliedAt})
	}
	return api.ListAgentPolicyTemplateAssignments200JSONResponse{Body: out, Headers: api.ListAgentPolicyTemplateAssignments200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) RemoveAgentPolicyTemplateAssignment(ctx context.Context, req api.RemoveAgentPolicyTemplateAssignmentRequestObject) (api.RemoveAgentPolicyTemplateAssignmentResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	if err != nil {
		return nil, err
	}
	for _, perm := range []rbac.Permission{rbac.PermPolicyManage, rbac.PermAgentGrantAccess} {
		if _, err := authorize(ctx, req.OrgId, perm); err != nil {
			return nil, err
		}
	}
	if err := s.requireAgentTemplates(ctx, req.OrgId); err != nil {
		return nil, err
	}
	impact, err := s.agentTemplates.RemoveAssignment(ctx, req.OrgId, req.AssignmentId, actorID(ctx))
	if err != nil {
		return nil, mapAgentTemplateError(err)
	}
	return api.RemoveAgentPolicyTemplateAssignment200JSONResponse{Body: toAPIAgentTemplateRemovalImpact(impact), Headers: api.RemoveAgentPolicyTemplateAssignment200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func toAPIAgentGroupList(row sqlc.ListAgentGroupsRow) api.AgentGroup {
	return api.AgentGroup{Id: row.ID, OrgId: row.OrgID, Name: row.Name, Description: row.Description, MemberCount: int(row.MemberCount), CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

// agentGroupListResponse deliberately uses the bounded list projection for
// create/update responses too. A mutation must not report zero merely because
// its RETURNING row does not join current memberships.
func (s apiServer) agentGroupListResponse(ctx context.Context, orgID, groupID uuid.UUID) (api.AgentGroup, error) {
	rows, err := s.agentTemplates.ListGroups(ctx, orgID)
	if err != nil {
		return api.AgentGroup{}, err
	}
	for _, row := range rows {
		if row.ID == groupID {
			return toAPIAgentGroupList(row), nil
		}
	}
	return api.AgentGroup{}, agenttemplates.ErrNotFound
}

func toAPIAgentMCPProfile(row sqlc.AgentMcpProfile) api.AgentMCPProfile {
	var archivedAt *time.Time
	if row.ArchivedAt.Valid {
		archivedAt = &row.ArchivedAt.Time
	}
	return api.AgentMCPProfile{Id: row.ID, OrgId: row.OrgID, Name: row.Name, Endpoint: row.Endpoint, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ArchivedAt: archivedAt}
}

func toAPIAgentPolicyTemplate(row sqlc.AgentPolicyTemplate) api.AgentPolicyTemplate {
	return api.AgentPolicyTemplate{Id: row.ID, OrgId: row.OrgID, Name: row.Name, Description: row.Description, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func toAPIAgentTemplatePreview(p agenttemplates.Preview) api.AgentPolicyTemplatePreview {
	toTuples := func(in []agenttemplates.Tuple) []api.AgentPolicyTemplateTuple {
		out := make([]api.AgentPolicyTemplateTuple, 0, len(in))
		for _, t := range in {
			out = append(out, api.AgentPolicyTemplateTuple{DeviceId: t.DeviceID, NodeId: t.NodeID, DestinationCidr: t.CIDR, Protocol: api.AgentPolicyTemplateTupleProtocol(t.Protocol), PortLow: t.PortLow, PortHigh: t.PortHigh})
		}
		return out
	}
	return api.AgentPolicyTemplatePreview{Digest: p.Digest, AffectedAgents: p.AffectedAgents, CreatedRules: p.CreatedRules, ReusedRules: p.ReusedRules, RemovedRules: p.RemovedRules, ChangedGateways: p.ChangedGateways, Added: toTuples(p.Added), Removed: toTuples(p.Removed)}
}

func toAPIAgentTemplateRemovalImpact(p agenttemplates.RemovalImpact) api.AgentPolicyTemplateRemovalImpact {
	return api.AgentPolicyTemplateRemovalImpact{Members: p.Members, Assignments: p.Assignments, GeneratedRules: p.GeneratedRules, WithdrawnTuples: p.WithdrawnTuples, ChangedGateways: p.ChangedGateways}
}

func mapAgentTemplateError(err error) error {
	switch {
	case errors.Is(err, agenttemplates.ErrInvalid):
		return apierr.BadRequest("invalid_agent_policy_template", "agent group or template input is invalid")
	case errors.Is(err, agenttemplates.ErrNotFound):
		return apierr.NotFound("agent_policy_template_not_found", "agent group or template not found")
	case errors.Is(err, agenttemplates.ErrStalePreview):
		return apierr.Conflict("stale_preview", "the group or policy inputs changed; preview again before applying")
	case errors.Is(err, agenttemplates.ErrConflict):
		return apierr.Conflict("agent_policy_template_conflict", "the requested template change conflicts with current state")
	default:
		return err
	}
}
