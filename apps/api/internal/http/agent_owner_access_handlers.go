package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AI-UX-1, Access: what an agent can reach now, what it was refused recently, and rules made from its
// owner's access. The reads use the two queries in db/queries/agent_owner_access.sql; every rule is
// created through the policy service's rule insert (the one the "Add rule" dialog uses for an agent), so
// validation, the organization lock, the per-rule audit entry and the gateway push are the existing ones.

const (
	// agentAccessRefusalWindow and agentAccessRefusalScan bound "recently": the newest refused connections
	// of the last week, read from the newest 500 refusal rows of this agent.
	agentAccessRefusalWindow = 7 * 24 * time.Hour
	agentAccessRefusalScan   = 500
	agentAccessRefusalMax    = 100
	agentAccessRuleMax       = 1000

	auditAgentRulesFromOwner = "agent.access_rules_created_from_owner"
)

// ownerAccessCopyableKinds are the destination kinds the agent rule insert takes.
var ownerAccessCopyableKinds = map[string]bool{"resource": true, "group": true, "site": true, "k8s_service": true}

func agentAccessUnavailable() error {
	return apierr.New(http.StatusServiceUnavailable, "agent_access_unavailable", "Agent access is temporarily unavailable.")
}

func agentOwnerUnattributable() error {
	return apierr.Conflict("agent_owner_unattributable", "This agent has no owner in this organization, so there is no access to copy.")
}

func ownerAccessPreviewStale() error {
	return apierr.Conflict("owner_access_preview_stale", "The owner's access changed since this list was shown. Review the list again.")
}

func intPtr32(v *int32) *int {
	if v == nil {
		return nil
	}
	out := int(*v)
	return &out
}

func pgUUIDPtr(v pgtype.UUID) *uuid.UUID {
	if !v.Valid {
		return nil
	}
	id := uuid.UUID(v.Bytes)
	return &id
}

// accessRuleDestination names a rule's destination. present is false when the destination row is gone
// (for example a Kubernetes Service that is no longer exposed): the rule then reaches nothing.
func accessRuleDestination(row sqlc.ListAccessRulesForSubjectsRow) (out api.AgentAccessDestinationSummary, id uuid.UUID, present bool) {
	out.Kind = row.DstKind
	set := func(ref pgtype.UUID, name *string) {
		if ref.Valid {
			id = uuid.UUID(ref.Bytes)
			v := id
			out.Id = &v
		}
		if name != nil {
			out.Name = *name
			present = true
		}
	}
	switch row.DstKind {
	case "resource":
		set(row.DstResourceID, row.ResourceName)
		out.Address, out.Protocol = row.ResourceCidr, row.ResourceProtocol
		out.PortLow, out.PortHigh = intPtr32(row.ResourcePortLow), intPtr32(row.ResourcePortHigh)
	case "group":
		set(row.DstGroupID, row.DstGroupName)
	case "site":
		set(row.DstSiteID, row.SiteName)
	case "k8s_service":
		set(row.DstK8sServiceID, row.K8sServiceName)
		if present && row.K8sServiceNamespace != nil {
			out.Name = *row.K8sServiceNamespace + "/" + out.Name
		}
		out.Protocol = row.K8sServiceProtocol
		out.PortLow, out.PortHigh = intPtr32(row.K8sServicePortLow), intPtr32(row.K8sServicePortHigh)
	case "k8s_cluster_scope":
		set(row.DstK8sClusterID, row.K8sClusterName)
	case "fqdn_resource":
		set(row.DstFqdnResourceID, row.FqdnName)
		out.Address, out.Protocol = row.FqdnHost, row.FqdnProtocol
		out.PortLow, out.PortHigh = intPtr32(row.FqdnPortLow), intPtr32(row.FqdnPortHigh)
	case "k8s_api":
		set(row.K8sApiClusterID, row.K8sApiClusterName)
		tcp, port := "tcp", 443
		out.Protocol, out.PortLow, out.PortHigh = &tcp, &port, &port
	}
	if !present {
		out.Name = "No longer available"
	}
	return out, id, present
}

func agentAccessRules(rows []sqlc.ListAccessRulesForSubjectsRow) []api.AgentAccessRule {
	out := []api.AgentAccessRule{}
	for _, row := range rows {
		if len(out) == agentAccessRuleMax {
			break
		}
		var via api.AgentAccessRuleVia
		switch row.SrcKind {
		case "agent":
			via = api.AgentAccessRuleViaAgent
		case "agent_group":
			via = api.AgentAccessRuleViaAgentGroup
		default:
			continue
		}
		destination, _, _ := accessRuleDestination(row)
		rule := api.AgentAccessRule{RuleId: row.RuleID, Via: via, Destination: destination, Enabled: !row.Disabled}
		if via == api.AgentAccessRuleViaAgentGroup {
			rule.GroupId, rule.GroupName = pgUUIDPtr(row.SrcAgentGroupID), row.SrcAgentGroupName
		}
		if row.ExpiresAt.Valid {
			t := row.ExpiresAt.Time
			rule.ExpiresAt = &t
		}
		out = append(out, rule)
	}
	return out
}

// agentAccessRefusals groups an agent's recent refused connections by destination, newest first.
func agentAccessRefusals(events []accesslog.Event, now time.Time) []api.AgentAccessRefusal {
	type key struct {
		dst, protocol string
		port          int
	}
	index := map[key]int{}
	out := []api.AgentAccessRefusal{}
	for _, e := range events {
		if e.Decision != accesslog.DecisionDeny && e.Decision != accesslog.DecisionDenyAggregate {
			continue
		}
		if e.DstIP == "" || now.Sub(e.OccurredAt) > agentAccessRefusalWindow {
			continue
		}
		count := int64(e.DenyCount)
		if count < 1 {
			count = 1
		}
		k := key{e.DstIP, e.Protocol, e.DstPort}
		i, seen := index[k]
		if !seen {
			item := api.AgentAccessRefusal{Dst: e.DstIP, Protocol: e.Protocol, LastSeen: e.OccurredAt}
			if e.DstPort != 0 {
				port := e.DstPort
				item.Port = &port
			}
			index[k] = len(out)
			out = append(out, item)
			i = len(out) - 1
		}
		out[i].Count += count
		if e.OccurredAt.After(out[i].LastSeen) {
			out[i].LastSeen = e.OccurredAt
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if !out[a].LastSeen.Equal(out[b].LastSeen) {
			return out[a].LastSeen.After(out[b].LastSeen)
		}
		if out[a].Dst != out[b].Dst {
			return out[a].Dst < out[b].Dst
		}
		return derefInt(out[a].Port) < derefInt(out[b].Port)
	})
	if len(out) > agentAccessRefusalMax {
		out = out[:agentAccessRefusalMax]
	}
	return out
}

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

// GetAgentAccessSummary is authorized like the access diagnostic beside it. It reads; it changes nothing.
func (s apiServer) GetAgentAccessSummary(ctx context.Context, req api.GetAgentAccessSummaryRequestObject) (api.GetAgentAccessSummaryResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	if s.system == nil {
		return nil, agentAccessUnavailable()
	}
	if _, err := s.agentAccessOwner(ctx, req.OrgId, req.DeviceId); err != nil {
		return nil, err
	}
	rows, err := s.system.ListAccessRulesForSubjects(ctx, sqlc.ListAccessRulesForSubjectsParams{
		OrgID: req.OrgId, DeviceID: pgtype.UUID{Bytes: req.DeviceId, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	body := api.AgentAccessSummary{Rules: agentAccessRules(rows), Refusals: api.AgentAccessRefusals{Items: []api.AgentAccessRefusal{}}}
	if s.accessLog == nil {
		// The access log is not part of this edition: say so and name the plan, instead of failing the
		// whole tab with the 403 the access-events endpoint answers.
		plan := string(licence.TierStarter)
		body.Refusals.RequiredPlan = &plan
	} else {
		events, err := s.accessLog.List(ctx, req.OrgId, &accessEventIdentityFilter{Kind: accessEventIdentityAgent, ID: req.DeviceId},
			true, time.Now().Add(24*time.Hour), maxUUID, agentAccessRefusalScan)
		if err != nil {
			return nil, err
		}
		body.Refusals.Available = true
		body.Refusals.Items = agentAccessRefusals(events, time.Now())
	}
	return api.GetAgentAccessSummary200JSONResponse{Body: body, Headers: api.GetAgentAccessSummary200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) agentAccessOwner(ctx context.Context, orgID, deviceID uuid.UUID) (sqlc.GetAgentAccessOwnerRow, error) {
	row, err := s.system.GetAgentAccessOwner(ctx, sqlc.GetAgentAccessOwnerParams{OrgID: orgID, DeviceID: deviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return row, apierr.NotFound("agent_not_found", "agent not found")
	}
	return row, err
}

// ownerAccessCandidate is one destination of the owner's access, as a rule the agent could be given.
type ownerAccessCandidate struct {
	api   api.AgentOwnerAccessCandidate
	input policyspec.RuleInput
}

// ownerAccessKey ties a candidate to this agent, the owner's rule it came from, the destination and the
// expiry it would carry. It holds no state: a key is accepted only while a fresh preview still lists it.
func ownerAccessKey(orgID, deviceID, sourceRuleID uuid.UUID, kind string, destinationID uuid.UUID, expiresAt *time.Time) string {
	expiry := ""
	if expiresAt != nil {
		expiry = strconv.FormatInt(expiresAt.UTC().UnixMicro(), 10)
	}
	sum := sha256.Sum256([]byte("owner-access-v1\x00" + orgID.String() + "\x00" + deviceID.String() + "\x00" + sourceRuleID.String() + "\x00" + kind + "\x00" + destinationID.String() + "\x00" + expiry))
	return hex.EncodeToString(sum[:])
}

// ownerAccessCandidates turns the owner's rules into candidates for the agent: one per destination, with
// whether an agent rule can name it and whether the agent already reaches it. Where the owner reaches a
// destination by several rules, the rule naming the owner wins over a group rule and a permanent rule over
// a temporary one. A temporary rule is copied with its expiry, never as a permanent one.
func ownerAccessCandidates(orgID, deviceID uuid.UUID, ownerRows, agentRows []sqlc.ListAccessRulesForSubjectsRow) []ownerAccessCandidate {
	type destination struct {
		kind string
		id   uuid.UUID
	}
	covered := map[destination]bool{}
	for _, row := range agentRows {
		if row.Disabled || (row.SrcKind != "agent" && row.SrcKind != "agent_group") {
			continue
		}
		if _, id, present := accessRuleDestination(row); present {
			covered[destination{row.DstKind, id}] = true
		}
	}
	rank := func(row sqlc.ListAccessRulesForSubjectsRow) int {
		score := 0
		if row.SrcKind != "user" {
			score += 2
		}
		if row.ExpiresAt.Valid {
			score++
		}
		return score
	}
	chosen := map[destination]int{}
	out := []ownerAccessCandidate{}
	best := []int{}
	for _, row := range ownerRows {
		if row.Disabled || (row.SrcKind != "user" && row.SrcKind != "group") {
			continue
		}
		summary, id, present := accessRuleDestination(row)
		if !present || id == uuid.Nil {
			continue
		}
		var expires *time.Time
		if row.ExpiresAt.Valid {
			t := row.ExpiresAt.Time
			expires = &t
		}
		d := destination{row.DstKind, id}
		candidate := ownerAccessCandidate{api: api.AgentOwnerAccessCandidate{
			Key: ownerAccessKey(orgID, deviceID, row.RuleID, row.DstKind, id, expires), Destination: summary,
			Via: api.AgentOwnerAccessViaUser, SourceRuleId: row.RuleID,
			Copyable: ownerAccessCopyableKinds[row.DstKind], AlreadyCovered: covered[d],
		}}
		if row.SrcKind == "group" {
			candidate.api.Via, candidate.api.ViaGroupName = api.AgentOwnerAccessViaGroup, row.SrcGroupName
		}
		agent, target := deviceID, id
		candidate.input = policyspec.RuleInput{SrcKind: "agent", SrcAgentDeviceID: &agent, DstKind: row.DstKind, ExpiresAt: expires}
		switch row.DstKind {
		case "resource":
			candidate.input.DstResourceID = &target
		case "group":
			candidate.input.DstGroupID = &target
		case "site":
			candidate.input.DstSiteID = &target
		case "k8s_service":
			candidate.input.DstK8sServiceID = &target
		}
		if i, seen := chosen[d]; seen {
			if rank(row) < best[i] {
				out[i], best[i] = candidate, rank(row)
			}
			continue
		}
		chosen[d] = len(out)
		out = append(out, candidate)
		best = append(best, rank(row))
	}
	if len(out) > agentAccessRuleMax {
		out = out[:agentAccessRuleMax]
	}
	return out
}

// ownerAccessPreview reads the owner's current access and the agent's own rules. It creates nothing.
func (s apiServer) ownerAccessPreview(ctx context.Context, orgID, deviceID uuid.UUID) (sqlc.GetAgentAccessOwnerRow, []ownerAccessCandidate, error) {
	if s.system == nil {
		return sqlc.GetAgentAccessOwnerRow{}, nil, agentAccessUnavailable()
	}
	owner, err := s.agentAccessOwner(ctx, orgID, deviceID)
	if err != nil {
		return owner, nil, err
	}
	if !owner.OwnerUserID.Valid {
		return owner, nil, agentOwnerUnattributable()
	}
	ownerRows, err := s.system.ListAccessRulesForSubjects(ctx, sqlc.ListAccessRulesForSubjectsParams{OrgID: orgID, UserID: owner.OwnerUserID})
	if err != nil {
		return owner, nil, err
	}
	agentRows, err := s.system.ListAccessRulesForSubjects(ctx, sqlc.ListAccessRulesForSubjectsParams{OrgID: orgID, DeviceID: pgtype.UUID{Bytes: deviceID, Valid: true}})
	if err != nil {
		return owner, nil, err
	}
	return owner, ownerAccessCandidates(orgID, deviceID, ownerRows, agentRows), nil
}

func (s apiServer) PreviewAgentOwnerAccess(ctx context.Context, req api.PreviewAgentOwnerAccessRequestObject) (api.PreviewAgentOwnerAccessResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentGrantAccess); err != nil {
		return nil, err
	}
	owner, candidates, err := s.ownerAccessPreview(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	body := api.AgentOwnerAccessPreview{OwnerEmail: owner.OwnerEmail, Candidates: make([]api.AgentOwnerAccessCandidate, 0, len(candidates))}
	for _, candidate := range candidates {
		body.Candidates = append(body.Candidates, candidate.api)
	}
	return api.PreviewAgentOwnerAccess200JSONResponse{Body: body, Headers: api.PreviewAgentOwnerAccess200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// CreateAgentRulesFromOwnerAccess creates one agent rule for each chosen key and nothing else. Every key
// must be in a preview computed now for this agent, copyable and not already covered; otherwise the whole
// request is refused before anything is created.
func (s apiServer) CreateAgentRulesFromOwnerAccess(ctx context.Context, req api.CreateAgentRulesFromOwnerAccessRequestObject) (api.CreateAgentRulesFromOwnerAccessResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentGrantAccess); err != nil {
		return nil, err
	}
	if req.Body == nil || len(req.Body.Keys) == 0 || len(req.Body.Keys) > 200 {
		return nil, apierr.BadRequest("invalid_request", "Choose between 1 and 200 destinations.")
	}
	wanted := map[string]bool{}
	for _, key := range req.Body.Keys {
		if key == "" || len(key) > 128 || wanted[key] {
			return nil, apierr.BadRequest("invalid_request", "Each chosen destination must be listed once.")
		}
		wanted[key] = true
	}
	if s.policy == nil {
		return nil, policyServiceUnavailable()
	}
	owner, candidates, err := s.ownerAccessPreview(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	chosen := make([]ownerAccessCandidate, 0, len(wanted))
	for _, candidate := range candidates {
		if !wanted[candidate.api.Key] {
			continue
		}
		if !candidate.api.Copyable || candidate.api.AlreadyCovered {
			return nil, ownerAccessPreviewStale()
		}
		chosen = append(chosen, candidate)
	}
	if len(chosen) != len(wanted) {
		return nil, ownerAccessPreviewStale()
	}
	uid, sys, cause := auditActor(ctx)
	ruleIDs := make([]uuid.UUID, 0, len(chosen))
	sourceRuleIDs := make([]string, 0, len(chosen))
	var createErr error
	for _, candidate := range chosen {
		rule, err := s.policy.CreatePolicyRule(ctx, req.OrgId, candidate.input, machineID(ctx), uid, sys, cause)
		if err != nil {
			createErr = err
			break
		}
		ruleIDs = append(ruleIDs, rule.ID)
		sourceRuleIDs = append(sourceRuleIDs, candidate.api.SourceRuleId.String())
	}
	// The audit entry names exactly the rules that exist, also when a later one failed.
	if len(ruleIDs) > 0 {
		if err := s.auditAgentRulesFromOwner(ctx, req.OrgId, req.DeviceId, uuid.UUID(owner.OwnerUserID.Bytes), ruleIDs, sourceRuleIDs, uid, sys, cause); err != nil && createErr == nil {
			createErr = err
		}
	}
	if createErr != nil {
		return nil, createErr
	}
	return api.CreateAgentRulesFromOwnerAccess201JSONResponse{Body: api.AgentOwnerAccessRulesResult{RuleIds: ruleIDs},
		Headers: api.CreateAgentRulesFromOwnerAccess201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) auditAgentRulesFromOwner(ctx context.Context, orgID, deviceID, ownerID uuid.UUID, ruleIDs []uuid.UUID, sourceRuleIDs []string, actor uuid.UUID, actorSystem, cause string) error {
	ids := make([]string, len(ruleIDs))
	for i, id := range ruleIDs {
		ids[i] = id.String()
	}
	meta := map[string]any{"rule_ids": ids, "source_rule_ids": sourceRuleIDs, "owner_user_id": ownerID.String()}
	if actorSystem != "" && cause != "" {
		meta["cause"] = cause
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	targetType, targetID := "device", deviceID.String()
	org := pgtype.UUID{Bytes: orgID, Valid: true}
	if actorSystem != "" {
		_, err = s.system.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{OrgID: org, ActorSystem: &actorSystem, Action: auditAgentRulesFromOwner, TargetType: &targetType, TargetID: &targetID, Metadata: raw})
		return err
	}
	_, err = s.system.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{OrgID: org, ActorUserID: pgtype.UUID{Bytes: actor, Valid: actor != uuid.Nil}, Action: auditAgentRulesFromOwner, TargetType: &targetType, TargetID: &targetID, Metadata: raw})
	return err
}
