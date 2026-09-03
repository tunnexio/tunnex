package http

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// policyPort is the one-binary Zero Trust policy service. Production wiring always
// provides it; a nil port is an internal configuration fault, never a plan decision.
// It returns sqlc rows; the handlers map them to API types.
type policyPort interface {
	ListGroups(ctx context.Context, orgID uuid.UUID) ([]sqlc.ListUserGroupsByOrgRow, error)
	CreateGroup(ctx context.Context, orgID uuid.UUID, name, description string) (sqlc.UserGroup, error)
	UpdateGroup(ctx context.Context, orgID, groupID uuid.UUID, name, description string) (sqlc.UserGroup, error)
	DeleteGroup(ctx context.Context, orgID, groupID uuid.UUID) error
	ListGroupMembers(ctx context.Context, orgID, groupID uuid.UUID) ([]sqlc.ListGroupMembersRow, error)
	AddGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID) error
	RemoveGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID) error
	ListResources(ctx context.Context, orgID uuid.UUID) ([]sqlc.Resource, error)
	CreateResource(ctx context.Context, orgID uuid.UUID, in policyspec.ResourceInput, label *string) (sqlc.Resource, error)
	UpdateResource(ctx context.Context, orgID, resourceID uuid.UUID, in policyspec.ResourceInput, label *string) (sqlc.Resource, error)
	DeleteResource(ctx context.Context, orgID, resourceID uuid.UUID) error
	ListPolicyRules(ctx context.Context, orgID uuid.UUID) ([]sqlc.PolicyRule, error)
	// DeviceFQDNForwards returns only resolver suffixes derived from active FQDN
	// parent rules matching this device. The routed-ranges handler validates
	// device ownership first; older requests without device_id never call it.
	DeviceFQDNForwards(ctx context.Context, orgID, deviceID uuid.UUID, routedRanges []string) ([]policyspec.DNSForward, error)
	AgentTemplateManagedRuleIDs(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]bool, error)
	AgentAccessManagedRules(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]uuid.UUID, error)
	CreatePolicyRule(ctx context.Context, orgID uuid.UUID, in policyspec.RuleInput, managedByMachine, actorUserID uuid.UUID, actorSystem, cause string) (sqlc.PolicyRule, error)
	// PolicyRuleCidrWarnings returns per-rule-id the S8.7 cidr_outside_org_ranges warning (a src_kind='cidr'
	// rule that places nowhere — no containing site with a bound gateway). Read-time derived; takes the
	// already-fetched rules ([15] — no re-query of the rule set).
	PolicyRuleCidrWarnings(ctx context.Context, orgID uuid.UUID, rules []sqlc.PolicyRule) (map[uuid.UUID]bool, error)
	DeletePolicyRule(ctx context.Context, orgID, ruleID, actorUserID uuid.UUID, actorSystem, cause string) error
	ExtendGrant(ctx context.Context, orgID, ruleID uuid.UUID, newExpiresAt time.Time) (sqlc.PolicyRule, error)
	// SetPolicyRuleEnabled toggles a rule's enabled state (F3); disabling withdraws its allow (in-hash push).
	SetPolicyRuleEnabled(ctx context.Context, orgID, ruleID uuid.UUID, enabled bool) (sqlc.PolicyRule, error)
	GetMode(ctx context.Context, orgID uuid.UUID) (string, error)
	SetMode(ctx context.Context, orgID uuid.UUID, mode string) (mode_ string, affected []policyspec.AffectedDevice, err error)
}

// EgressPolicyDenied is the NAMED state for a device whose internet egress is denied
// by Zero Trust POLICY on a gateway that IS egress-capable (S7.2 decision 2-coherence)
// -- deliberately distinct from gateway_no_egress (the gateway cannot egress at all).
// The two refusal paths must never be conflated in status/error surfaces.
const EgressPolicyDenied = "egress_policy_denied"

func policyServiceUnavailable() error {
	return apierr.New(http.StatusServiceUnavailable, "policy_service_unavailable", "Zero Trust policy service is unavailable")
}

// reqID is a short alias for the request-id header value.
func reqID(ctx context.Context) string { return middleware.GetReqID(ctx) }

// ── groups ──────────────────────────────────────────────────────────────────────

func (s apiServer) ListGroups(ctx context.Context, req api.ListGroupsRequestObject) (api.ListGroupsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	gs, err := s.policy.ListGroups(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	var managedAgentCounts map[uuid.UUID]int64
	if _, manageErr := authorize(ctx, req.OrgId, rbac.PermPolicyManage); manageErr == nil {
		if s.devices == nil {
			return nil, apierr.New(http.StatusInternalServerError, "agent_service_unavailable", "agent service unavailable")
		}
		managedAgentCounts, err = s.devices.AgentManagingGroupCounts(ctx, req.OrgId)
		if err != nil {
			return nil, err
		}
	}
	out := make([]api.UserGroup, 0, len(gs))
	for _, g := range gs {
		item := toAPIGroupList(g)
		if managedAgentCounts != nil {
			count := int(managedAgentCounts[g.ID])
			item.ManagedAgentCount = &count
		}
		out = append(out, item)
	}
	return api.ListGroups200JSONResponse{Body: out, Headers: api.ListGroups200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) CreateGroup(ctx context.Context, req api.CreateGroupRequestObject) (api.CreateGroupResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	g, err := s.policy.CreateGroup(ctx, req.OrgId, req.Body.Name, deref(req.Body.Description))
	if err != nil {
		return nil, err
	}
	group, err := s.groupListResponse(ctx, req.OrgId, g.ID)
	if err != nil {
		return nil, err
	}
	return api.CreateGroup201JSONResponse{Body: group, Headers: api.CreateGroup201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) UpdateGroup(ctx context.Context, req api.UpdateGroupRequestObject) (api.UpdateGroupResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	g, err := s.policy.UpdateGroup(ctx, req.OrgId, req.GroupId, req.Body.Name, deref(req.Body.Description))
	if err != nil {
		return nil, err
	}
	group, err := s.groupListResponse(ctx, req.OrgId, g.ID)
	if err != nil {
		return nil, err
	}
	return api.UpdateGroup200JSONResponse{Body: group, Headers: api.UpdateGroup200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) DeleteGroup(ctx context.Context, req api.DeleteGroupRequestObject) (api.DeleteGroupResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if err := s.policy.DeleteGroup(ctx, req.OrgId, req.GroupId); err != nil {
		return nil, err
	}
	return api.DeleteGroup204Response{Headers: api.DeleteGroup204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// ── group members ───────────────────────────────────────────────────────────────

func (s apiServer) ListGroupMembers(ctx context.Context, req api.ListGroupMembersRequestObject) (api.ListGroupMembersResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	ms, err := s.policy.ListGroupMembers(ctx, req.OrgId, req.GroupId)
	if err != nil {
		return nil, err
	}
	out := make([]api.GroupMember, 0, len(ms))
	for _, m := range ms {
		out = append(out, api.GroupMember{UserId: m.ID, Email: m.Email, Name: m.Name, AddedAt: m.CreatedAt})
	}
	return api.ListGroupMembers200JSONResponse{Body: out, Headers: api.ListGroupMembers200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) AddGroupMember(ctx context.Context, req api.AddGroupMemberRequestObject) (api.AddGroupMemberResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if err := s.policy.AddGroupMember(ctx, req.OrgId, req.GroupId, req.Body.UserId); err != nil {
		return nil, err
	}
	return api.AddGroupMember204Response{Headers: api.AddGroupMember204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) RemoveGroupMember(ctx context.Context, req api.RemoveGroupMemberRequestObject) (api.RemoveGroupMemberResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if err := s.policy.RemoveGroupMember(ctx, req.OrgId, req.GroupId, req.UserId); err != nil {
		return nil, err
	}
	return api.RemoveGroupMember204Response{Headers: api.RemoveGroupMember204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// ── resources ───────────────────────────────────────────────────────────────────

func (s apiServer) ListResources(ctx context.Context, req api.ListResourcesRequestObject) (api.ListResourcesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	rs, err := s.policy.ListResources(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.Resource, 0, len(rs))
	for _, r := range rs {
		out = append(out, toAPIResource(r))
	}
	return api.ListResources200JSONResponse{Body: out, Headers: api.ListResources200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) CreateResource(ctx context.Context, req api.CreateResourceRequestObject) (api.CreateResourceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	r, err := s.policy.CreateResource(ctx, req.OrgId, resourceInput(*req.Body), req.Body.Label)
	if err != nil {
		return nil, err
	}
	return api.CreateResource201JSONResponse{Body: toAPIResource(r), Headers: api.CreateResource201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) UpdateResource(ctx context.Context, req api.UpdateResourceRequestObject) (api.UpdateResourceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	r, err := s.policy.UpdateResource(ctx, req.OrgId, req.ResourceId, resourceInput(*req.Body), req.Body.Label)
	if err != nil {
		return nil, err
	}
	return api.UpdateResource200JSONResponse{Body: toAPIResource(r), Headers: api.UpdateResource200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) DeleteResource(ctx context.Context, req api.DeleteResourceRequestObject) (api.DeleteResourceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if err := s.policy.DeleteResource(ctx, req.OrgId, req.ResourceId); err != nil {
		return nil, err
	}
	return api.DeleteResource204Response{Headers: api.DeleteResource204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// ── rules ───────────────────────────────────────────────────────────────────────

// requireSpecialPermissionsForExistingRule preserves the named capability
// boundaries of policy rows that have a dedicated management surface. A
// generic policy mutation must never become a lower-permission bypass.
func (s apiServer) requireSpecialPermissionsForExistingRule(ctx context.Context, orgID, ruleID uuid.UUID) error {
	rules, err := s.policy.ListPolicyRules(ctx, orgID)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if rule.ID != ruleID {
			continue
		}
		if rule.SrcKind == "agent" {
			if _, err := authorize(ctx, orgID, rbac.PermAgentGrantAccess); err != nil {
				return err
			}
		}
		if rule.DstKind == "k8s_cluster_scope" {
			if _, err := authorize(ctx, orgID, rbac.PermK8sScopeManage); err != nil {
				return err
			}
			p, ok := authctx.PrincipalFrom(ctx)
			if !ok || p.UserID == uuid.Nil || p.IsMachine() || p.AuthMethod == authctx.AuthAgent || p.NodeID != uuid.Nil {
				return apierr.Forbidden("human_actor_required", "a verified human organization member is required")
			}
			// Cluster scopes own revision checks, membership-count semantics, and
			// their audit contract. Letting an authorized caller mutate the
			// backing policy row here would bypass all three, so callers must use
			// the dedicated scope endpoint even after crossing the named
			// permission and human-actor boundaries above.
			return apierr.Conflict("cluster_scope_dedicated_api_required", "Kubernetes cluster scopes must be changed through the dedicated cluster-scope API with expected_revision")
		}
		return nil
	}
	// Preserve the existing service's normalized not-found response; this
	// helper must not invent a second existence oracle.
	return nil
}

func (s apiServer) ListPolicyRules(ctx context.Context, req api.ListPolicyRulesRequestObject) (api.ListPolicyRulesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	rs, err := s.policy.ListPolicyRules(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	_, mayViewAgentTemplates := authorize(ctx, req.OrgId, rbac.PermAgentTemplateManage)
	filtered := rs[:0]
	for _, rule := range rs {
		if mayViewAgentTemplates != nil && rule.SrcKind == "agent_group" {
			continue
		}
		// Cluster scopes are governed through their dedicated API. Exposing their
		// backing rows here would make the generic policy UI look authoritative
		// and invite a create-then-delete edit that the mutation boundary rejects.
		if rule.DstKind == "k8s_cluster_scope" {
			continue
		}
		filtered = append(filtered, rule)
	}
	rs = filtered
	warn, err := s.policy.PolicyRuleCidrWarnings(ctx, req.OrgId, rs) // S8.7 read-time warn (D1); reuse the fetched rules ([15])
	if err != nil {
		return nil, err
	}
	vanished, err := s.k8sVanishedMap(ctx, req.OrgId, rs) // S10.3 read-time vanished-Service warn
	if err != nil {
		return nil, err
	}
	templateManaged := map[uuid.UUID]bool{}
	if mayViewAgentTemplates == nil {
		templateManaged, err = s.policy.AgentTemplateManagedRuleIDs(ctx, req.OrgId)
		if err != nil {
			return nil, err
		}
	}
	jitManaged, err := s.policy.AgentAccessManagedRules(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	fqdnStatus := s.fqdnDestinationStatusMap(ctx, req.OrgId, rs)
	out := make([]api.PolicyRule, 0, len(rs))
	for _, r := range rs {
		out = append(out, toAPIRuleWithFQDNStatus(r, warn[r.ID], vanished[r.ID], fqdnStatus[r.ID], policyRuleOwnership{
			agentTemplate: templateManaged[r.ID], agentAccessRequestID: jitManaged[r.ID],
		}))
	}
	return api.ListPolicyRules200JSONResponse{Body: out, Headers: api.ListPolicyRules200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) CreatePolicyRule(ctx context.Context, req api.CreatePolicyRuleRequestObject) (api.CreatePolicyRuleResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if req.Body != nil && req.Body.SrcKind != nil && string(*req.Body.SrcKind) == "agent" {
		if _, err := authorize(ctx, req.OrgId, rbac.PermAgentGrantAccess); err != nil {
			return nil, err
		}
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	in := policyspec.RuleInput{
		SrcUserID:         req.Body.SrcUserId,
		SrcSiteID:         req.Body.SrcSiteId,   // S8.2: src_kind=site
		SrcCIDR:           req.Body.SrcCidr,     // S8.7: src_kind=cidr
		SrcAgentDeviceID:  req.Body.SrcDeviceId, // S15.3: src_kind=agent
		DstKind:           string(req.Body.DstKind),
		DstResourceID:     req.Body.DstResourceId,
		DstGroupID:        req.Body.DstGroupId,
		DstSiteID:         req.Body.DstSiteId,       // S8.1: dst_kind=site
		DstK8sServiceID:   req.Body.DstK8sServiceId, // S10.3: dst_kind=k8s_service
		DstFQDNResourceID: req.Body.DstFqdnResourceId,
		ExpiresAt:         req.Body.ExpiresAt,
	}
	if req.Body.SrcKind != nil {
		in.SrcKind = string(*req.Body.SrcKind)
	}
	if req.Body.SrcGroupId != nil {
		in.SrcGroupID = *req.Body.SrcGroupId
	}
	uid, sys, cause := auditActor(ctx)
	r, err := s.policy.CreatePolicyRule(ctx, req.OrgId, in, machineID(ctx), uid, sys, cause)
	if err != nil {
		return nil, err
	}
	warn, err := s.policy.PolicyRuleCidrWarnings(ctx, req.OrgId, []sqlc.PolicyRule{r}) // S8.7 warn for the created rule
	if err != nil {
		return nil, err
	}
	van, err := s.k8sVanishedMap(ctx, req.OrgId, []sqlc.PolicyRule{r})
	if err != nil {
		return nil, err
	}
	fqdnStatus := s.fqdnDestinationStatusMap(ctx, req.OrgId, []sqlc.PolicyRule{r})
	return api.CreatePolicyRule201JSONResponse{Body: toAPIRuleWithFQDNStatus(r, warn[r.ID], van[r.ID], fqdnStatus[r.ID]), Headers: api.CreatePolicyRule201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) DeletePolicyRule(ctx context.Context, req api.DeletePolicyRuleRequestObject) (api.DeletePolicyRuleResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if err := s.requireSpecialPermissionsForExistingRule(ctx, req.OrgId, req.RuleId); err != nil {
		return nil, err
	}
	uid, sys, cause := auditActor(ctx)
	if err := s.policy.DeletePolicyRule(ctx, req.OrgId, req.RuleId, uid, sys, cause); err != nil {
		return nil, err
	}
	return api.DeletePolicyRule204Response{Headers: api.DeletePolicyRule204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// ExtendGrant PUT .../policies/{ruleId} — extend a temporary grant's window (S7.5.4).
func (s apiServer) ExtendGrant(ctx context.Context, req api.ExtendGrantRequestObject) (api.ExtendGrantResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if err := s.requireSpecialPermissionsForExistingRule(ctx, req.OrgId, req.RuleId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	r, err := s.policy.ExtendGrant(ctx, req.OrgId, req.RuleId, req.Body.ExpiresAt)
	if err != nil {
		return nil, err
	}
	warn, err := s.policy.PolicyRuleCidrWarnings(ctx, req.OrgId, []sqlc.PolicyRule{r})
	if err != nil {
		return nil, err
	}
	van, err := s.k8sVanishedMap(ctx, req.OrgId, []sqlc.PolicyRule{r})
	if err != nil {
		return nil, err
	}
	fqdnStatus := s.fqdnDestinationStatusMap(ctx, req.OrgId, []sqlc.PolicyRule{r})
	return api.ExtendGrant200JSONResponse{Body: toAPIRuleWithFQDNStatus(r, warn[r.ID], van[r.ID], fqdnStatus[r.ID]), Headers: api.ExtendGrant200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// SetPolicyRuleEnabled (F3) — enable/disable a rule without deleting it. policy:manage;
// disabling is an in-hash policy change (recompile + push). The response echoes the new enabled state.
func (s apiServer) SetPolicyRuleEnabled(ctx context.Context, req api.SetPolicyRuleEnabledRequestObject) (api.SetPolicyRuleEnabledResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if err := s.requireSpecialPermissionsForExistingRule(ctx, req.OrgId, req.RuleId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	r, err := s.policy.SetPolicyRuleEnabled(ctx, req.OrgId, req.RuleId, req.Body.Enabled)
	if err != nil {
		return nil, err
	}
	warn, err := s.policy.PolicyRuleCidrWarnings(ctx, req.OrgId, []sqlc.PolicyRule{r})
	if err != nil {
		return nil, err
	}
	van, err := s.k8sVanishedMap(ctx, req.OrgId, []sqlc.PolicyRule{r})
	if err != nil {
		return nil, err
	}
	fqdnStatus := s.fqdnDestinationStatusMap(ctx, req.OrgId, []sqlc.PolicyRule{r})
	return api.SetPolicyRuleEnabled200JSONResponse{Body: toAPIRuleWithFQDNStatus(r, warn[r.ID], van[r.ID], fqdnStatus[r.ID]), Headers: api.SetPolicyRuleEnabled200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// ── enforcement mode ──────────────────────────────────────────────────────────

func (s apiServer) GetZeroTrustMode(ctx context.Context, req api.GetZeroTrustModeRequestObject) (api.GetZeroTrustModeResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	mode, err := s.policy.GetMode(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetZeroTrustMode200JSONResponse{
		Body:    api.ZeroTrustMode{Mode: api.ZeroTrustModeMode(mode)},
		Headers: api.GetZeroTrustMode200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

// SetZeroTrustMode gates on PermPolicyManage — DISABLING re-opens the mesh, so it
// is the same (owner/admin) capability, deliberately not a members-level read.
func (s apiServer) SetZeroTrustMode(ctx context.Context, req api.SetZeroTrustModeRequestObject) (api.SetZeroTrustModeResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	mode, affected, err := s.policy.SetMode(ctx, req.OrgId, string(req.Body.Mode))
	if err != nil {
		return nil, err
	}
	body := api.ZeroTrustMode{Mode: api.ZeroTrustModeMode(mode)}
	if len(affected) > 0 {
		out := make([]api.AffectedDevice, 0, len(affected))
		for _, d := range affected {
			out = append(out, api.AffectedDevice{Id: d.ID, Name: d.Name})
		}
		body.AffectedFullTunnelDevices = &out
	}
	return api.SetZeroTrustMode200JSONResponse{
		Body:    body,
		Headers: api.SetZeroTrustMode200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

// ── mappers ─────────────────────────────────────────────────────────────────────

func toAPIGroupList(g sqlc.ListUserGroupsByOrgRow) api.UserGroup {
	out := api.UserGroup{Id: g.ID, OrgId: g.OrgID, Name: g.Name, Description: g.Description, MemberCount: int(g.MemberCount), CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt}
	if g.Origin != "" { // S7.5.2: distinguish a directory-synced group from a manual one
		o := api.UserGroupOrigin(g.Origin)
		out.Origin = &o
	}
	if g.IdpProvider != nil {
		p := api.UserGroupIdpProvider(*g.IdpProvider)
		out.IdpProvider = &p
	}
	out.IdpGroupId = g.IdpGroupID
	return out
}

// groupListResponse reuses the bounded list projection after a mutation, so an
// update cannot manufacture member_count: 0 for a group that already has
// members. The list is organization-scoped and is the canonical count source.
func (s apiServer) groupListResponse(ctx context.Context, orgID, groupID uuid.UUID) (api.UserGroup, error) {
	if s.system == nil {
		return api.UserGroup{}, apierr.Internal()
	}
	groups, err := s.system.ListUserGroupsByOrg(ctx, orgID)
	if err != nil {
		return api.UserGroup{}, err
	}
	for _, group := range groups {
		if group.ID == groupID {
			return toAPIGroupList(group), nil
		}
	}
	return api.UserGroup{}, apierr.NotFound("group_not_found", "group not found")
}

func toAPIResource(r sqlc.Resource) api.Resource {
	out := api.Resource{
		Id: r.ID, OrgId: r.OrgID, Name: r.Name, Cidr: r.Cidr,
		Protocol: api.ResourceProtocol(r.Protocol), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		PortLow: i32toIntPtr(r.PortLow), PortHigh: i32toIntPtr(r.PortHigh),
		// ⚠ Operator free text (S15.3). Rendered as written; never derived, never validated against
		// anything the product claims to detect.
		Label: r.Label,
	}
	return out
}

// k8sVanishedMap returns which of the given rules point at a now-absent (unexposed / cluster-deregistered)
// K8s Service — the read-time vanished-Service warn (S10.3 warn-not-refuse). A rule with a live dst, or a
// non-k8s_service dst, is absent from the map (false). Skips the DB read entirely when no rule is k8s-dst.
func (s apiServer) k8sVanishedMap(ctx context.Context, orgID uuid.UUID, rules []sqlc.PolicyRule) (map[uuid.UUID]bool, error) {
	out := map[uuid.UUID]bool{}
	any := false
	for _, r := range rules {
		if r.DstKind == "k8s_service" {
			any = true
			break
		}
	}
	if !any || s.k8s == nil {
		return out, nil
	}
	live, err := s.k8s.LiveServiceIDs(ctx, orgID)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if r.DstKind == "k8s_service" && r.DstK8sServiceID.Valid && !live[uuid.UUID(r.DstK8sServiceID.Bytes)] {
			out[r.ID] = true
		}
	}
	return out, nil
}

// fqdnDestinationStatusMap is a server-owned read projection for the FQDN
// destination identity already present on a policy rule. It is deliberately
// best-effort: an unavailable FQDN projection must not make the authoritative
// policy inventory disappear or turn an unknown state into a permissive one.
func (s apiServer) fqdnDestinationStatusMap(ctx context.Context, orgID uuid.UUID, rules []sqlc.PolicyRule) map[uuid.UUID]api.PolicyRuleFqdnDestinationStatus {
	out := map[uuid.UUID]api.PolicyRuleFqdnDestinationStatus{}
	var fqdnRules []sqlc.PolicyRule
	for _, rule := range rules {
		if rule.DstKind == "fqdn_resource" {
			fqdnRules = append(fqdnRules, rule)
		}
	}
	if len(fqdnRules) == 0 {
		return out
	}
	setAll := func(status api.PolicyRuleFqdnDestinationStatus) {
		for _, rule := range fqdnRules {
			out[rule.ID] = status
		}
	}
	if s.licence == nil || !licence.Has(s.licence.Evaluate(time.Now()).Tier, licence.FeatFQDNResources) {
		setAll(fqdnDestinationStatusFor(false, false, true, true, ""))
		return out
	}
	svc, err := s.fqdnService()
	if err != nil {
		setAll(fqdnDestinationStatusFor(true, false, false, true, ""))
		return out
	}
	enabled, err := svc.Setting(ctx, orgID)
	if err != nil {
		setAll(fqdnDestinationStatusFor(true, false, false, true, ""))
		return out
	}
	if !enabled {
		setAll(fqdnDestinationStatusFor(true, false, true, true, ""))
		return out
	}
	resources, err := svc.List(ctx, orgID)
	if err != nil {
		setAll(fqdnDestinationStatusFor(true, true, false, true, ""))
		return out
	}
	stateByID := make(map[uuid.UUID]string, len(resources))
	for _, resource := range resources {
		stateByID[resource.ID] = resource.State
	}
	for _, rule := range fqdnRules {
		if !rule.DstFqdnResourceID.Valid {
			out[rule.ID] = fqdnDestinationStatusFor(true, true, true, false, "")
			continue
		}
		state, exists := stateByID[uuid.UUID(rule.DstFqdnResourceID.Bytes)]
		out[rule.ID] = fqdnDestinationStatusFor(true, true, true, exists, state)
	}
	return out
}

func fqdnDestinationStatusFor(entitled, optedIn, projectionReadable, resourceExists bool, state string) api.PolicyRuleFqdnDestinationStatus {
	if !entitled {
		return api.FeatureUnavailable
	}
	if !projectionReadable {
		return api.ProjectionUnavailable
	}
	if !optedIn {
		return api.OptInDisabled
	}
	if !resourceExists {
		return api.GenerationUnavailable
	}
	return fqdnDestinationStatus(state)
}

func fqdnDestinationStatus(state string) api.PolicyRuleFqdnDestinationStatus {
	switch state {
	case "healthy":
		return api.ActiveGeneration
	case "draft", "resolving":
		return api.GenerationPending
	case "stale", "nxdomain", "failed":
		return api.GenerationWithdrawn
	default:
		return api.GenerationUnavailable
	}
}

type policyRuleOwnership struct {
	agentTemplate        bool
	agentAccessRequestID uuid.UUID
}

func toAPIRule(r sqlc.PolicyRule, cidrOutside, k8sVanished bool, ownership ...policyRuleOwnership) api.PolicyRule {
	status := api.NotApplicable
	if r.DstKind == "fqdn_resource" {
		status = api.GenerationUnavailable
	}
	return toAPIRuleWithFQDNStatus(r, cidrOutside, k8sVanished, status, ownership...)
}

func toAPIRuleWithFQDNStatus(r sqlc.PolicyRule, cidrOutside, k8sVanished bool, fqdnStatus api.PolicyRuleFqdnDestinationStatus, ownership ...policyRuleOwnership) api.PolicyRule {
	var owner policyRuleOwnership
	if len(ownership) != 0 {
		owner = ownership[0]
	}
	out := api.PolicyRule{
		Id: r.ID, OrgId: r.OrgID, SrcKind: api.PolicyRuleSrcKind(r.SrcKind),
		DstKind: api.PolicyRuleDstKind(r.DstKind), CreatedAt: r.CreatedAt,
		CidrOutsideOrgRanges:   cidrOutside, // S8.7 warn-not-refuse (D1); always false for non-cidr sources
		DstK8sServiceVanished:  k8sVanished, // S10.3 warn-not-refuse; the dst Service is gone (grant compiles to nothing)
		FqdnDestinationStatus:  fqdnStatus,
		Enabled:                !r.Disabled,              // F3: positive framing — a rule is enabled unless disabled
		ManagedByOperator:      r.ManagedByMachine.Valid, // S10.2 D2 cond 1: GitOps-managed → badge + warn-on-edit
		ManagedByAgentTemplate: owner.agentTemplate,
		ManagedByAgentAccess:   owner.agentAccessRequestID != uuid.Nil,
	}
	if owner.agentAccessRequestID != uuid.Nil {
		out.AgentAccessRequestId = &owner.agentAccessRequestID
	}
	if r.SrcGroupID.Valid {
		u := uuid.UUID(r.SrcGroupID.Bytes)
		out.SrcGroupId = &u
	}
	if r.SrcUserID.Valid {
		u := uuid.UUID(r.SrcUserID.Bytes)
		out.SrcUserId = &u
	}
	if r.SrcSiteID.Valid { // S8.2: src_kind=site
		u := uuid.UUID(r.SrcSiteID.Bytes)
		out.SrcSiteId = &u
	}
	if r.SrcDeviceID.Valid { // S15.3: src_kind=agent
		n := uuid.UUID(r.SrcDeviceID.Bytes)
		out.SrcDeviceId = &n
	}
	if r.SrcAgentGroupID.Valid {
		u := uuid.UUID(r.SrcAgentGroupID.Bytes)
		out.SrcAgentGroupId = &u
	}
	if r.SrcCidr != nil { // S8.7: src_kind=cidr
		out.SrcCidr = r.SrcCidr
	}
	if r.DstResourceID.Valid {
		u := uuid.UUID(r.DstResourceID.Bytes)
		out.DstResourceId = &u
	}
	if r.DstGroupID.Valid {
		u := uuid.UUID(r.DstGroupID.Bytes)
		out.DstGroupId = &u
	}
	if r.DstSiteID.Valid { // S8.1 (response mapping completed in S8.2): dst_kind=site
		u := uuid.UUID(r.DstSiteID.Bytes)
		out.DstSiteId = &u
	}
	if r.DstK8sServiceID.Valid { // S10.3: dst_kind=k8s_service
		u := uuid.UUID(r.DstK8sServiceID.Bytes)
		out.DstK8sServiceId = &u
	}
	if r.DstK8sClusterID.Valid {
		u := uuid.UUID(r.DstK8sClusterID.Bytes)
		out.DstK8sClusterId = &u
	}
	if r.DstFqdnResourceID.Valid {
		u := uuid.UUID(r.DstFqdnResourceID.Bytes)
		out.DstFqdnResourceId = &u
	}
	if r.ExpiresAt.Valid {
		t := r.ExpiresAt.Time
		out.ExpiresAt = &t
	}
	return out
}

func resourceInput(b api.ResourceRequest) policyspec.ResourceInput {
	return policyspec.ResourceInput{Name: b.Name, CIDR: b.Cidr, Protocol: string(b.Protocol), PortLow: b.PortLow, PortHigh: b.PortHigh}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func i32toIntPtr(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}
