package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentaccessguard"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// Service is the enterprise Zero Trust policy CRUD + snapshot service. Every
// mutation writes an actor-attributed audit row in the same transaction, and
// validates inputs before touching the DB. It is only constructed in the
// enterprise build (policy_wire_enterprise.go); the open build's port is nil.
type Service struct {
	pool   *pgxpool.Pool
	q      *sqlc.Queries
	notify Notifier // nil => no push (provider-only service / tests)
	// fqdnGenerations is deliberately a read-only Lane 2 seam. It returns
	// immutable active snapshots from the server-selected resolver context; this
	// service remains responsible for deciding whether the named entitlement and
	// organization opt-in make those snapshots enforceable.
	fqdnGenerations fqdnresolver.ActiveGenerationReader
	fqdnEntitled    func() bool
}

// SetNotifier wires the push hub (S7.2). Call on the CRUD service; the desired-
// state provider service does not mutate and needs none.
func (s *Service) SetNotifier(n Notifier) { s.notify = n }

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: sqlc.New(pool)}
}

// WithFQDNGenerations wires the persisted Lane 2 snapshot reader into this
// policy provider. A nil reader or entitlement function is fail closed: FQDN
// rules remain stored but compile to no authorization.
func (s *Service) WithFQDNGenerations(reader fqdnresolver.ActiveGenerationReader, entitled func() bool) *Service {
	s.fqdnGenerations = reader
	s.fqdnEntitled = entitled
	return s
}

// ── groups ──────────────────────────────────────────────────────────────────────

func (s *Service) ListGroups(ctx context.Context, orgID uuid.UUID) ([]sqlc.ListUserGroupsByOrgRow, error) {
	return s.q.ListUserGroupsByOrg(ctx, orgID)
}

func (s *Service) CreateGroup(ctx context.Context, orgID uuid.UUID, name, description string) (sqlc.UserGroup, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return sqlc.UserGroup{}, apierr.BadRequest("invalid_request", "group name is required")
	}
	var g sqlc.UserGroup
	err := s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		var e error
		g, e = q.CreateUserGroup(ctx, sqlc.CreateUserGroupParams{OrgID: orgID, Name: name, Description: description})
		if e != nil {
			return conflictIfDup(e, "a group with that name already exists")
		}
		return writeAudit(ctx, q, orgID, "group.created", "group", g.ID.String(), map[string]any{"name": name})
	})
	return g, err
}

func (s *Service) UpdateGroup(ctx context.Context, orgID, groupID uuid.UUID, name, description string) (sqlc.UserGroup, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return sqlc.UserGroup{}, apierr.BadRequest("invalid_request", "group name is required")
	}
	var g sqlc.UserGroup
	err := s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		var e error
		g, e = q.UpdateUserGroup(ctx, sqlc.UpdateUserGroupParams{ID: groupID, OrgID: orgID, Name: name, Description: description})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("group_not_found", "group not found")
		}
		if e != nil {
			return conflictIfDup(e, "a group with that name already exists")
		}
		return writeAudit(ctx, q, orgID, "group.updated", "group", groupID.String(), map[string]any{"name": name})
	})
	return g, err
}

func (s *Service) DeleteGroup(ctx context.Context, orgID, groupID uuid.UUID) error {
	return s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		if _, e := agentaccessguard.LockDestination(ctx, q, orgID, "group", groupID); e != nil {
			return e
		}
		live, e := agentaccessguard.LiveDestinationRequests(ctx, q, orgID, "group", groupID)
		if e != nil {
			return e
		}
		if live != 0 {
			return apierr.Conflict("agent_access_destination_in_use", fmt.Sprintf("%d pending or approved agent access requests reference this group", live))
		}
		versions, e := q.CountAgentPolicyTemplateGroupReferences(ctx, sqlc.CountAgentPolicyTemplateGroupReferencesParams{OrgID: orgID, DstGroupID: pgtype.UUID{Bytes: groupID, Valid: true}})
		if e != nil {
			return e
		}
		if versions != 0 {
			return apierr.Conflict("agent_policy_template_destination", fmt.Sprintf("%d immutable agent policy template versions reference this group", versions))
		}
		n, e := q.DeleteUserGroup(ctx, sqlc.DeleteUserGroupParams{ID: groupID, OrgID: orgID})
		if e != nil {
			return e
		}
		if n == 0 {
			return apierr.NotFound("group_not_found", "group not found")
		}
		return writeAudit(ctx, q, orgID, "group.deleted", "group", groupID.String(), nil)
	})
}

// ── group members ───────────────────────────────────────────────────────────────

func (s *Service) ListGroupMembers(ctx context.Context, orgID, groupID uuid.UUID) ([]sqlc.ListGroupMembersRow, error) {
	if _, err := s.q.GetUserGroup(ctx, sqlc.GetUserGroupParams{ID: groupID, OrgID: orgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apierr.NotFound("group_not_found", "group not found")
		}
		return nil, err
	}
	return s.q.ListGroupMembers(ctx, sqlc.ListGroupMembersParams{OrgID: orgID, GroupID: groupID})
}

func (s *Service) AddGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID) error {
	return s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		g, e := q.GetUserGroup(ctx, sqlc.GetUserGroupParams{ID: groupID, OrgID: orgID})
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.NotFound("group_not_found", "group not found")
			}
			return e
		}
		// D1 (S7.5.2): an idp_sync group's membership is owned by the reconciler — hand-editing
		// it would be silently overwritten on the next poll, and worse, would blur the disjoint
		// manual/idp origins the schema guards. Refuse loudly instead.
		if g.Origin == "idp_sync" {
			return apierr.Conflict("idp_managed_group", "this group is managed by directory sync; members cannot be edited manually")
		}
		// The user must be a member of THIS org — no adding a foreign/unknown user
		// to a group (which would then inherit grants). GetMembership is org-scoped.
		if _, e := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: userID}); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.BadRequest("not_a_member", "user is not a member of this organization")
			}
			return e
		}
		n, e := q.AddGroupMember(ctx, sqlc.AddGroupMemberParams{OrgID: orgID, GroupID: groupID, UserID: userID})
		if e != nil {
			return e
		}
		if n == 0 {
			return nil // already a member — no state change, so no audit event (idempotent)
		}
		return writeAudit(ctx, q, orgID, "group.member_added", "group", groupID.String(), map[string]any{"user_id": userID.String()})
	})
}

func (s *Service) RemoveGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID) error {
	return s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		g, e := q.GetUserGroup(ctx, sqlc.GetUserGroupParams{ID: groupID, OrgID: orgID})
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.NotFound("group_not_found", "group not found")
			}
			return e
		}
		if g.Origin == "idp_sync" { // D1: reconciler-owned; see AddGroupMember
			return apierr.Conflict("idp_managed_group", "this group is managed by directory sync; members cannot be edited manually")
		}
		n, e := q.RemoveGroupMember(ctx, sqlc.RemoveGroupMemberParams{OrgID: orgID, GroupID: groupID, UserID: userID})
		if e != nil {
			return e
		}
		if n == 0 {
			return apierr.NotFound("member_not_found", "user is not a member of this group")
		}
		return writeAudit(ctx, q, orgID, "group.member_removed", "group", groupID.String(), map[string]any{"user_id": userID.String()})
	})
}

// ── resources ───────────────────────────────────────────────────────────────────

// validateResource validates a resource payload (the DTO lives in policyspec so
// the open build's http port can reference it without importing this package).
func validateResource(in policyspec.ResourceInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return apierr.BadRequest("invalid_request", "resource name is required")
	}
	if _, err := netip.ParsePrefix(in.CIDR); err != nil {
		return apierr.BadRequest("invalid_cidr", "cidr must be a valid IP prefix (e.g. 10.0.5.0/24)")
	}
	switch in.Protocol {
	case "any":
		if in.PortLow != nil || in.PortHigh != nil {
			return apierr.BadRequest("invalid_request", "protocol 'any' cannot carry ports")
		}
	case "tcp", "udp":
		// Ports are both-or-neither (finding #3). A half-set range (only low OR only
		// high) is rejected here so it can never reach the gateway, where renderAllow
		// fails it closed (skips the rule) — which would SILENTLY break a grant the API
		// reported as created. The renderer's fail-closed and this validation are the
		// two halves of the same invariant; neither alone is sufficient.
		if (in.PortLow == nil) != (in.PortHigh == nil) {
			return apierr.BadRequest("invalid_request", "port_low and port_high must be set together (both or neither)")
		}
	default:
		return apierr.BadRequest("invalid_request", "protocol must be any, tcp, or udp")
	}
	for _, p := range []*int{in.PortLow, in.PortHigh} {
		if p != nil && (*p < 1 || *p > 65535) {
			return apierr.BadRequest("invalid_request", "ports must be in 1..65535")
		}
	}
	if in.PortLow != nil && in.PortHigh != nil && *in.PortLow > *in.PortHigh {
		return apierr.BadRequest("invalid_request", "port_low must be <= port_high")
	}
	return nil
}

func (s *Service) ListResources(ctx context.Context, orgID uuid.UUID) ([]sqlc.Resource, error) {
	return s.q.ListResourcesByOrg(ctx, orgID)
}

// ⛔ `label` IS A SEPARATE PARAMETER, NOT A FIELD ON policyspec.ResourceInput — AND THAT IS DELIBERATE.
//
// S15.3's binding constraint is that nothing it adds may reach the compiled artifact. `ResourceInput` lives
// in `policyspec`, the compiler's own package; adding a descriptive field there would touch the compiler's
// input type to carry something the compiler must never read.
//
// > **THE COMPILER'S INPUT TYPE STAYS PURE.** A trailing parameter looks less tidy and says something true:
// > this value is not policy input. A field on ResourceInput would say the opposite, and the next person
// > would have to check the compiler to find out which.
//
// ⚠ The mechanical test still holds either way — `CanonicalHash` reads cidr, protocol and the port bounds —
// but the type is where a reader looks first, and it should not need the test.
func (s *Service) CreateResource(ctx context.Context, orgID uuid.UUID, in policyspec.ResourceInput, label *string) (sqlc.Resource, error) {
	if err := validateResource(in); err != nil {
		return sqlc.Resource{}, err
	}
	in.CIDR = canonicalCIDR(in.CIDR) // store the masked prefix, never host-bits-set
	var r sqlc.Resource
	err := s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		var e error
		r, e = q.CreateResource(ctx, sqlc.CreateResourceParams{
			OrgID: orgID, Name: strings.TrimSpace(in.Name), Cidr: in.CIDR,
			Protocol: in.Protocol, PortLow: i32ptr(in.PortLow), PortHigh: i32ptr(in.PortHigh),
			Label: label,
		})
		if e != nil {
			return conflictIfDup(e, "a resource with that name already exists")
		}
		return writeAudit(ctx, q, orgID, "resource.created", "resource", r.ID.String(),
			map[string]any{"name": r.Name, "cidr": r.Cidr, "protocol": r.Protocol})
	})
	return r, err
}

func (s *Service) UpdateResource(ctx context.Context, orgID, resourceID uuid.UUID, in policyspec.ResourceInput, label *string) (sqlc.Resource, error) {
	if err := validateResource(in); err != nil {
		return sqlc.Resource{}, err
	}
	in.CIDR = canonicalCIDR(in.CIDR)
	var r sqlc.Resource
	err := s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		var e error
		r, e = q.UpdateResource(ctx, sqlc.UpdateResourceParams{
			ID: resourceID, OrgID: orgID, Name: strings.TrimSpace(in.Name), Cidr: in.CIDR,
			Protocol: in.Protocol, PortLow: i32ptr(in.PortLow), PortHigh: i32ptr(in.PortHigh),
			Label: label,
		})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("resource_not_found", "resource not found")
		}
		if e != nil {
			return conflictIfDup(e, "a resource with that name already exists")
		}
		return writeAudit(ctx, q, orgID, "resource.updated", "resource", resourceID.String(),
			map[string]any{"name": r.Name, "cidr": r.Cidr, "protocol": r.Protocol})
	})
	return r, err
}

func (s *Service) DeleteResource(ctx context.Context, orgID, resourceID uuid.UUID) error {
	return s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		if _, e := agentaccessguard.LockDestination(ctx, q, orgID, "resource", resourceID); e != nil {
			return e
		}
		live, e := agentaccessguard.LiveDestinationRequests(ctx, q, orgID, "resource", resourceID)
		if e != nil {
			return e
		}
		if live != 0 {
			return apierr.Conflict("agent_access_destination_in_use", fmt.Sprintf("%d pending or approved agent access requests reference this resource", live))
		}
		versions, e := q.CountAgentPolicyTemplateResourceReferences(ctx, sqlc.CountAgentPolicyTemplateResourceReferencesParams{OrgID: orgID, DstResourceID: pgtype.UUID{Bytes: resourceID, Valid: true}})
		if e != nil {
			return e
		}
		if versions != 0 {
			return apierr.Conflict("agent_policy_template_destination", fmt.Sprintf("%d immutable agent policy template versions reference this resource", versions))
		}
		n, e := q.DeleteResource(ctx, sqlc.DeleteResourceParams{ID: resourceID, OrgID: orgID})
		if e != nil {
			return e
		}
		if n == 0 {
			return apierr.NotFound("resource_not_found", "resource not found")
		}
		return writeAudit(ctx, q, orgID, "resource.deleted", "resource", resourceID.String(), nil)
	})
}

// ── rules ───────────────────────────────────────────────────────────────────────

func (s *Service) ListPolicyRules(ctx context.Context, orgID uuid.UUID) ([]sqlc.PolicyRule, error) {
	rows, err := s.q.ListPolicyRulesByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]sqlc.PolicyRule, 0, len(rows))
	for _, row := range rows {
		// ListPolicyRulesByOrg deliberately projects the post-0109 FQDN
		// destination through JSONB so it can read an old policy_rules table
		// where the additive column does not exist. sqlc represents that
		// nullable derived UUID as uuid.UUID; uuid.Nil is therefore the
		// historical no-FQDN value rather than a valid destination.
		fqdn := pgtype.UUID{}
		if row.DstFqdnResourceID != uuid.Nil {
			fqdn = pgtype.UUID{Bytes: row.DstFqdnResourceID, Valid: true}
		}
		out = append(out, sqlc.PolicyRule{
			ID: row.ID, OrgID: row.OrgID,
			SrcGroupID: row.SrcGroupID, DstKind: row.DstKind,
			DstResourceID: row.DstResourceID, DstGroupID: row.DstGroupID,
			CreatedAt: row.CreatedAt, SrcKind: row.SrcKind,
			SrcUserID: row.SrcUserID, ExpiresAt: row.ExpiresAt,
			DstSiteID: row.DstSiteID, SrcSiteID: row.SrcSiteID,
			SrcCidr: row.SrcCidr, Disabled: row.Disabled,
			DstK8sServiceID:   row.DstK8sServiceID,
			ManagedByMachine:  row.ManagedByMachine,
			SrcDeviceID:       row.SrcDeviceID,
			DstK8sClusterID:   row.DstK8sClusterID,
			SrcAgentGroupID:   row.SrcAgentGroupID,
			DstFqdnResourceID: fqdn,
		})
	}
	return out, nil
}

func (s *Service) AgentTemplateManagedRuleIDs(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]bool, error) {
	ids, err := s.q.ListAgentTemplateManagedRuleIDs(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

func (s *Service) AgentAccessManagedRules(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	rows, err := s.q.ListAgentAccessManagedRules(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]uuid.UUID, len(rows))
	for _, row := range rows {
		out[row.PolicyRuleID.Bytes] = row.RequestID
	}
	return out, nil
}

func refuseAgentTemplateManagedRule(ctx context.Context, q *sqlc.Queries, orgID, ruleID uuid.UUID) error {
	managed, err := q.IsAgentTemplateManagedRule(ctx, sqlc.IsAgentTemplateManagedRuleParams{
		OrgID: orgID, PolicyRuleID: ruleID,
	})
	if err != nil {
		return err
	}
	if managed {
		return apierr.Conflict("agent_template_managed_rule", "this rule is managed by an agent policy template assignment; change or remove the assignment instead")
	}
	return nil
}

func refuseWorkflowManagedRule(ctx context.Context, q *sqlc.Queries, orgID, ruleID uuid.UUID) error {
	if err := refuseAgentTemplateManagedRule(ctx, q, orgID, ruleID); err != nil {
		return err
	}
	_, err := q.GetAgentAccessRequestByPolicyRule(ctx, sqlc.GetAgentAccessRequestByPolicyRuleParams{
		OrgID: orgID, PolicyRuleID: pgtype.UUID{Bytes: ruleID, Valid: true},
	})
	if err == nil {
		return apierr.Conflict("agent_access_managed_rule", "this rule is managed by a JIT agent-access request; revoke the request instead")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

// PolicyRuleCidrWarnings computes, per rule id, the S8.7 read-time warning cidr_outside_org_ranges: true for
// a src_kind='cidr' rule whose CIDR is inside NO current site subnet — a rule that compiles to nothing (the
// reassuring-rule guard, D1 warn-not-refuse). ONE-TRUTH with the compiler placement: it reuses containingSite
// over the SAME site subnets, so the warning fires EXACTLY when the placement finds no site (warn ⟺
// won't-enforce). DERIVED at READ time from CURRENT ranges — a rule out-of-world at creation and in-world
// after the range lands SHEDS its warning with no edit. (Routed-range/device-pool ranges are a noted S8.7
// boundary: they neither place the grant nor clear the warning in this slice — a CIDR in only those ranges
// still won't enforce, so warning it is honest.)
func (s *Service) PolicyRuleCidrWarnings(ctx context.Context, orgID uuid.UUID, rules []sqlc.PolicyRule) (map[uuid.UUID]bool, error) {
	siteSubnets, err := s.q.ListSiteSubnetsForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	siteCIDRs := map[uuid.UUID][]string{}
	for _, ss := range siteSubnets {
		siteCIDRs[ss.SiteID] = append(siteCIDRs[ss.SiteID], ss.Cidr.String())
	}
	// The SAME site→gateway map the compiler builds (ListSiteNodesForOrg), so the warning and the placement
	// share ONE "has a bound gateway" truth — the [9] fix + the [0]+[9] biconditional (warn ⟺ won't-place).
	siteNodes, err := s.q.ListSiteNodesForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	siteNode := map[uuid.UUID]uuid.UUID{}
	for _, sn := range siteNodes {
		if id := fromPgUUID(sn.SiteID); id != uuid.Nil && sn.ID != uuid.Nil {
			siteNode[id] = sn.ID
		}
	}
	out := map[uuid.UUID]bool{}
	for _, r := range rules {
		if r.SrcKind == "cidr" && r.SrcCidr != nil {
			_, places := cidrPlacementSite(*r.SrcCidr, siteCIDRs, siteNode)
			out[r.ID] = !places // warn IFF the rule places nowhere — one truth with the compiler
		}
	}
	return out, nil
}

// managedByMachine (S10.2 Slice 3a): the operator's machine credential when a MACHINE principal creates the
// grant (uuid.Nil for a human → NULL, inert) — the ownership marker the dashboard surfaces in Slice 4.
func (s *Service) CreatePolicyRule(ctx context.Context, orgID uuid.UUID, in policyspec.RuleInput, managedByMachine, actorUserID uuid.UUID, actorSystem, cause string) (sqlc.PolicyRule, error) {
	// SOURCE-subject shape (S7.5.4): "" defaults to "group" (back-compat). Exactly one
	// of src_group_id / src_user_id, matching src_kind (the DB CHECK backstops it).
	srcKind := in.SrcKind
	if srcKind == "" {
		srcKind = "group"
	}
	switch srcKind {
	case "group":
		if in.SrcGroupID == uuid.Nil || in.SrcUserID != nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "src_kind=group requires src_group_id (and no src_user_id)")
		}
	case "user":
		if in.SrcUserID == nil || in.SrcGroupID != uuid.Nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "src_kind=user requires src_user_id (and no src_group_id)")
		}
	case "site": // S8.2: a site's LAN as the SOURCE subject
		if in.SrcSiteID == nil || in.SrcGroupID != uuid.Nil || in.SrcUserID != nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "src_kind=site requires src_site_id (and no src_group_id/src_user_id)")
		}
	case "cidr": // S8.7: a literal source CIDR (/32-precise). Well-formed here; ORG-RANGE meaningfulness is a
		// READ-TIME WARNING (warn-not-refuse, D1), NOT a creation refusal — an admin may pre-stage a rule for
		// a range about to be declared.
		if in.SrcCIDR == nil || in.SrcGroupID != uuid.Nil || in.SrcUserID != nil || in.SrcSiteID != nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "src_kind=cidr requires src_cidr (and no src_group_id/src_user_id/src_site_id)")
		}
		if _, err := netip.ParsePrefix(*in.SrcCIDR); err != nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "src_cidr must be a valid CIDR (e.g. 172.31.17.64/32)")
		}
	case "agent": // S15.3: the source is ONE agent's own /32.
		// ⛔ THE NODE MUST BE AN AGENT, AND THE CHECK IS HERE RATHER THAN AT THE COMPILER. A rule naming a
		// plain gateway would compile to nothing and look like a working grant — the reassuring-empty class
		// applied to a policy rule, where the operator believes access was granted and it never was.
		if in.SrcAgentDeviceID == nil || in.SrcGroupID != uuid.Nil || in.SrcUserID != nil || in.SrcSiteID != nil || in.SrcCIDR != nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "src_kind=agent requires src_device_id (and no other src_*)")
		}
	default:
		return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "src_kind must be group, user, site, cidr, or agent")
	}
	// Destination shape: exactly one dst_* set, matching dst_kind.
	switch in.DstKind {
	case "resource":
		if in.DstResourceID == nil || in.DstGroupID != nil || in.DstSiteID != nil || in.DstK8sServiceID != nil || in.DstFQDNResourceID != nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "dst_kind=resource requires dst_resource_id (and no dst_group_id/dst_site_id)")
		}
	case "group":
		if in.DstGroupID == nil || in.DstResourceID != nil || in.DstSiteID != nil || in.DstK8sServiceID != nil || in.DstFQDNResourceID != nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "dst_kind=group requires dst_group_id (and no dst_resource_id/dst_site_id)")
		}
	case "site":
		if in.DstSiteID == nil || in.DstResourceID != nil || in.DstGroupID != nil || in.DstK8sServiceID != nil || in.DstFQDNResourceID != nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "dst_kind=site requires dst_site_id (and no dst_resource_id/dst_group_id/dst_k8s_service_id)")
		}
	case "k8s_service": // S10.3: a grant reaching an exposed K8s Service (governance is enterprise)
		if in.DstK8sServiceID == nil || in.DstResourceID != nil || in.DstGroupID != nil || in.DstSiteID != nil || in.DstFQDNResourceID != nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "dst_kind=k8s_service requires dst_k8s_service_id (and no dst_resource_id/dst_group_id/dst_site_id)")
		}
	case "fqdn_resource":
		if in.DstFQDNResourceID == nil || in.DstResourceID != nil || in.DstGroupID != nil || in.DstSiteID != nil || in.DstK8sServiceID != nil {
			return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "dst_kind=fqdn_resource requires dst_fqdn_resource_id (and no other dst_ id)")
		}
	default:
		return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "dst_kind must be resource, group, site, k8s_service, or fqdn_resource")
	}
	// ⛔ THE FIRST CROSS-FIELD CHECK THIS FUNCTION HAS EVER HAD, AND ITS ABSENCE WAS THE DEFECT.
	//
	// Every check above validates ONE side: that src_kind=group carries a src_group_id, that dst_kind=site
	// carries a dst_site_id. Twenty checks, all of the shape "does this side have its own id", and not one
	// of them reads the two kinds TOGETHER or asks whether they name the same thing.
	//
	// > **A SITE CANNOT REACH ITSELF THROUGH ITS OWN GATEWAY.** Two hosts on one LAN are switched locally;
	// > their traffic never enters that gateway's forward chain, so the compiler emits an allow that CANNOT
	// > MATCH — a rule rendering `active` while enforcing nothing.
	//
	// ⚠ REFUSED RATHER THAN WARNED, and the distinction is the one the warn-not-refuse convention turns on.
	// OUTSIDE RANGES and VANISHED describe things that are true today and may become false — a CIDR comes
	// in-world when a range is declared, a Service returns when it is re-exposed. This is false BY
	// CONSTRUCTION: there is no future state of the world in which a LAN reaching itself starts working, so
	// a warning here would never clear and would only teach the operator to ignore warnings.
	//
	// ⛔ AND IT LIVES HERE, NOT IN THE FORM. The web UI, the tunnex CLI and the GitOps CR path all reach this
	// function; a dropdown that omits the option guards one caller of three.
	if srcKind == "site" && in.DstKind == "site" && in.SrcSiteID != nil && in.DstSiteID != nil &&
		*in.SrcSiteID == *in.DstSiteID {
		return sqlc.PolicyRule{}, apierr.BadRequest("invalid_rule_self_site",
			"a site cannot be both the source and the destination: hosts on one LAN reach each other "+
				"directly, so this rule would enforce nothing")
	}

	// A temporary grant must expire in the FUTURE (a past expiry is a no-op grant —
	// reject it rather than silently create a rule that never compiles).
	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()) {
		return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "expires_at must be in the future")
	}
	var r sqlc.PolicyRule
	err := s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		// Referenced src subject + dst must belong to THIS org (no cross-tenant refs).
		if srcKind == "group" {
			if _, e := q.GetUserGroup(ctx, sqlc.GetUserGroupParams{ID: in.SrcGroupID, OrgID: orgID}); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return apierr.BadRequest("group_not_found", "src group not found")
				}
				return e
			}
		} else if srcKind == "user" { // must be a CURRENT org member (the FK enforces it too; clean 400 here)
			if _, e := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: *in.SrcUserID}); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return apierr.BadRequest("user_not_member", "src user is not a member of this org")
				}
				return e
			}
		} else if srcKind == "site" { // S8.2 — the source site must exist in THIS org. A SUBNETLESS source
			// site is ALLOWED (symmetric to the dst ruling): it compiles to nothing until subnets are added,
			// so refusing would impose an ordering dependency.
			if _, e := q.GetSite(ctx, sqlc.GetSiteParams{ID: *in.SrcSiteID, OrgID: orgID}); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return apierr.BadRequest("site_not_found", "src site not found")
				}
				return e
			}
			// srcKind == "cidr" (S8.7): a LITERAL CIDR has no DB entity — no cross-org ref check. Its
			// org-range meaningfulness is a READ-TIME warning (D1 warn-not-refuse), not a creation gate.
		}
		if in.DstResourceID != nil {
			if _, e := q.GetResource(ctx, sqlc.GetResourceParams{ID: *in.DstResourceID, OrgID: orgID}); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return apierr.BadRequest("resource_not_found", "dst resource not found")
				}
				return e
			}
		}
		if in.DstGroupID != nil {
			if _, e := q.GetUserGroup(ctx, sqlc.GetUserGroupParams{ID: *in.DstGroupID, OrgID: orgID}); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return apierr.BadRequest("group_not_found", "dst group not found")
				}
				return e
			}
		}
		if in.DstSiteID != nil { // S8.1: the dst site must exist in THIS org. A SUBNETLESS site is
			// ALLOWED (ruled) — it is a valid target that compiles to nothing until subnets are added;
			// refusing would impose an ordering dependency.
			if _, e := q.GetSite(ctx, sqlc.GetSiteParams{ID: *in.DstSiteID, OrgID: orgID}); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return apierr.BadRequest("site_not_found", "dst site not found")
				}
				return e
			}
		}
		// ⛔ THE NARROWED TWIN OF THE SELF-SITE REFUSAL. `src_kind=cidr` is a site source narrowed to a
		// literal prefix, so a CIDR that lies INSIDE the destination site's own subnet is the same
		// impossible rule wearing a different kind: a LAN address reaching its own LAN, through the gateway
		// that never sees that traffic.
		//
		// ⚠ NEEDS THE SUBNETS, so it lives in the transaction rather than beside its twin — and the
		// asymmetry is worth the correctness. A CIDR in ANY OTHER site, or in no site at all, is untouched:
		// the second is the OUTSIDE RANGES warn case, which self-clears and must not become a refusal.
		if srcKind == "cidr" && in.DstKind == "site" && in.SrcCIDR != nil && in.DstSiteID != nil {
			src, e := netip.ParsePrefix(*in.SrcCIDR)
			if e != nil {
				return apierr.BadRequest("invalid_request", "src_cidr must be a valid CIDR")
			}
			subs, e := q.ListSiteSubnets(ctx, *in.DstSiteID)
			if e != nil {
				return e
			}
			for _, sub := range subs {
				if sub.Cidr.Contains(src.Addr()) {
					return apierr.BadRequest("invalid_rule_self_site",
						"this source CIDR is inside the destination site's own subnet ("+sub.Cidr.String()+"): "+
							"hosts on one LAN reach each other directly, so this rule would enforce nothing")
				}
			}
		}
		if in.DstK8sServiceID != nil { // S10.3: the dst Service must exist in THIS org and be LIVE (not
			// unexposed). A vanished Service is a creation-time refusal here; an EXISTING rule whose Service
			// later vanishes is the read-time warn surface (warn-not-refuse), not this gate.
			if _, e := q.GetK8sService(ctx, sqlc.GetK8sServiceParams{ID: *in.DstK8sServiceID, OrgID: orgID}); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return apierr.BadRequest("k8s_service_not_found", "dst Kubernetes Service not found or no longer exposed")
				}
				return e
			}
		}
		if in.DstFQDNResourceID != nil {
			if _, e := q.GetFQDNResourceForPolicy(ctx, sqlc.GetFQDNResourceForPolicyParams{ID: *in.DstFQDNResourceID, OrgID: orgID}); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return apierr.BadRequest("fqdn_resource_not_found", "dst FQDN resource not found")
				}
				return e
			}
		}
		var e error
		r, e = q.CreatePolicyRule(ctx, sqlc.CreatePolicyRuleParams{
			OrgID: orgID, SrcKind: srcKind, SrcGroupID: toPgUUIDVal(in.SrcGroupID), SrcUserID: toPgUUID(in.SrcUserID),
			SrcSiteID: toPgUUID(in.SrcSiteID), SrcCidr: in.SrcCIDR,
			SrcDeviceID: toPgUUID(in.SrcAgentDeviceID),
			DstKind:     in.DstKind, DstResourceID: toPgUUID(in.DstResourceID), DstGroupID: toPgUUID(in.DstGroupID),
			DstSiteID: toPgUUID(in.DstSiteID), DstK8sServiceID: toPgUUID(in.DstK8sServiceID), DstFqdnResourceID: toPgUUID(in.DstFQDNResourceID), ExpiresAt: toPgTimestamptz(in.ExpiresAt),
			ManagedByMachine: pgtype.UUID{Bytes: managedByMachine, Valid: managedByMachine != uuid.Nil},
		})
		if e != nil {
			return conflictIfDup(e, "an identical rule already exists")
		}
		meta := map[string]any{"src_kind": srcKind, "dst_kind": in.DstKind}
		switch srcKind { // M6: a site source must audit its src_site_id, never a nil-UUID group (misattribution)
		case "user":
			meta["src_user_id"] = in.SrcUserID.String()
		case "site":
			meta["src_site_id"] = in.SrcSiteID.String()
		default:
			meta["src_group_id"] = in.SrcGroupID.String()
		}
		if in.ExpiresAt != nil {
			meta["expires_at"] = in.ExpiresAt.UTC().Format(time.RFC3339)
		}
		return writeAuditAs(ctx, q, orgID, actorUserID, actorSystem, cause, "policy.rule_created", "policy_rule", r.ID.String(), meta)
	})
	return r, err
}

func (s *Service) DeletePolicyRule(ctx context.Context, orgID, ruleID, actorUserID uuid.UUID, actorSystem, cause string) error {
	return s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		if err := refuseWorkflowManagedRule(ctx, q, orgID, ruleID); err != nil {
			return err
		}
		n, e := q.DeletePolicyRule(ctx, sqlc.DeletePolicyRuleParams{ID: ruleID, OrgID: orgID})
		if e != nil {
			return e
		}
		if n == 0 {
			return apierr.NotFound("rule_not_found", "rule not found")
		}
		// M1b (S10.2): honor the caller's attribution — a machine (the operator revoking a grant) records
		// actor_system=operator:<name> + the CR as cause, NOT a zero user-id. This is the walk's Leg 6 audit.
		return writeAuditAs(ctx, q, orgID, actorUserID, actorSystem, cause, "policy.rule_deleted", "policy_rule", ruleID.String(), nil)
	})
}

// SetPolicyRuleEnabled toggles a rule's disabled flag (F3). Enabling/disabling ACCESS is policy-
// consequential (same class as create/delete): it uses s.mutate (recompile + push — disabling changes the
// compiled artifact's CONTENT, in-hash, an ordinary desync-free push; NO version bump — only which entries
// exist changes) and audits with TWO DISTINCT actions (policy.rule_enabled / policy.rule_disabled), so
// "who cut access at 3am" is a one-read action filter, not a metadata query.
func (s *Service) SetPolicyRuleEnabled(ctx context.Context, orgID, ruleID uuid.UUID, enabled bool) (sqlc.PolicyRule, error) {
	if err := refuseWorkflowManagedRule(ctx, s.q, orgID, ruleID); err != nil {
		return sqlc.PolicyRule{}, err
	}
	// F-A1: read current state FIRST and NO-OP if already in the desired state — no push, no audit. The
	// wasted push is the smaller half; the real defect a naive toggle would introduce is an AUDIT LIE — a
	// policy.rule_disabled row that corresponds to no change in access corrupts exactly the one-read
	// "who cut access at 3am" answer the two-action design exists for. It is the swallowed-audit law's
	// MIRROR: that law says a real change must always leave a row; this says a row must always correspond
	// to a real change. API-only reachability doesn't lower it (scripts re-assert desired state routinely).
	// The ExtendGrant lapse-guard is the precedent: a no-op returns the entity unchanged.
	cur, err := s.q.GetPolicyRuleForOrg(ctx, sqlc.GetPolicyRuleForOrgParams{ID: ruleID, OrgID: orgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.PolicyRule{}, apierr.NotFound("rule_not_found", "rule not found")
		}
		return sqlc.PolicyRule{}, err
	}
	if cur.Disabled == !enabled {
		return cur, nil // already in the desired state → no-op (no push, no audit)
	}
	var r sqlc.PolicyRule
	err = s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		if e := refuseWorkflowManagedRule(ctx, q, orgID, ruleID); e != nil {
			return e
		}
		var e error
		r, e = q.SetPolicyRuleEnabled(ctx, sqlc.SetPolicyRuleEnabledParams{ID: ruleID, OrgID: orgID, Disabled: !enabled})
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) { // deleted between the read and the write
				return apierr.NotFound("rule_not_found", "rule not found")
			}
			return e
		}
		action := "policy.rule_disabled"
		if enabled {
			action = "policy.rule_enabled"
		}
		return writeAudit(ctx, q, orgID, action, "policy_rule", ruleID.String(), nil)
	})
	return r, err
}

// ── temporary-grant lifecycle (S7.5.4 slice 2) ──────────────────────────────────

// grantSweepInterval paces the expiry sweeper. Expiry is a PROMISE (a grant that
// says "expires 5:00" leaving at 5:04 is a poor look), so it is tighter than the
// health staleness cadence (5 min).
const grantSweepInterval = time.Minute

// ExtendGrant moves a temporary grant's window IN PLACE (window-extensible, never
// delete+recreate — the recreate would churn the /32 and cause a spurious push).
// The DB lapse-guard (expires_at > now()) makes extend and the sweeper compose on
// the row lock: a lapsed grant is terminal (409 grant_lapsed), only a live one moves.
func (s *Service) ExtendGrant(ctx context.Context, orgID, ruleID uuid.UUID, newExpiresAt time.Time) (sqlc.PolicyRule, error) {
	if !newExpiresAt.After(time.Now()) {
		return sqlc.PolicyRule{}, apierr.BadRequest("invalid_request", "expires_at must be in the future")
	}
	var r sqlc.PolicyRule
	// withTx, NOT mutate: extend moves only expires_at, which is NOT in the compiled
	// enforcement artifact (the CanonicalHash projection excludes it — a grant's window
	// never changes its src/dst allow tuple). A push here would recompile the whole org
	// and re-apply a BYTE-IDENTICAL ruleset on every gateway — the "spurious push" the
	// ExtendPolicyRule comment says the in-place update avoids. It's safe to skip because
	// nothing on the data plane consumes expires_at: lapse is enforced by the compiler's
	// active-rules filter on the next real recompile + the expiry sweeper's delete-push.
	// This endpoint is extend-ONLY (ExtendGrantRequest is expires_at-only, additionalProperties
	// false; ExtendPolicyRule SETs only expires_at) — no artifact-affecting field can flow
	// through it, so dropping the push can never hide an edit that SHOULD push. (S7.5.4 box-walk)
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		if e := refuseWorkflowManagedRule(ctx, q, orgID, ruleID); e != nil {
			return e
		}
		// Read the CURRENT window FIRST, under a row lock, so (a) old_expires_at is the true
		// PRE-update value for the D7 old->new audit, and (b) the sweeper's DELETE can't
		// interleave between this read and the UPDATE (extend and sweep serialize on this lock).
		existing, ge := q.GetPolicyRuleForUpdate(ctx, sqlc.GetPolicyRuleForUpdateParams{ID: ruleID, OrgID: orgID})
		if errors.Is(ge, pgx.ErrNoRows) {
			return apierr.NotFound("rule_not_found", "rule not found")
		}
		if ge != nil {
			return ge
		}
		if !existing.ExpiresAt.Valid {
			return apierr.Conflict("not_temporary", "this is a permanent grant — it has no expiry to extend")
		}
		if !existing.ExpiresAt.Time.After(time.Now()) {
			return apierr.Conflict("grant_lapsed", "this grant already expired — create a new one")
		}
		oldExpiry := existing.ExpiresAt.Time.UTC().Format(time.RFC3339) // captured BEFORE the update
		var e error
		r, e = q.ExtendPolicyRule(ctx, sqlc.ExtendPolicyRuleParams{
			ID: ruleID, OrgID: orgID, NewExpiresAt: pgtype.Timestamptz{Time: newExpiresAt, Valid: true},
		})
		if e != nil {
			return e // the row is locked + verified-live above, so 0-rows can't happen here
		}
		// D7: the audit shows the old->new window (who moved a grant's window, from when).
		return writeAudit(ctx, q, orgID, "policy.grant_extended", "policy_rule", ruleID.String(),
			map[string]any{"old_expires_at": oldExpiry, "new_expires_at": newExpiresAt.UTC().Format(time.RFC3339)})
	})
	return r, err
}

// SweepExpiredGrants DELETEs the currently-expired temporary grants (the story-end
// AMENDMENT — delete-on-sweep replaced linger; see docs/S7.5.4-decisions.md). Each lapse
// is audited grant_expired (SYSTEM actor grant-expiry, cause, SAME-TX with the delete),
// then each affected org is pushed org-wide (F1: a lapsed grant's /32 must leave EVERY
// gateway, not just the subject's node — incl. a non-hosting gateway that had the /32 as a
// group destination). STATELESS: every expired grant is deleted each call, so a failed or
// interrupted (downtime) tick leaves rows for the next tick — no window to skip, no lapse
// unaudited. Composes with ExtendGrant on the row lock (an extend that moved expires_at to
// the future is no longer <= now(), so it is neither deleted nor falsely audited expired).
func (s *Service) SweepExpiredGrants(ctx context.Context) (int, error) {
	var expired []sqlc.DeleteExpiredGrantsRow
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		rows, e := q.DeleteExpiredGrants(ctx)
		if e != nil {
			return e
		}
		expired = rows
		for _, r := range rows {
			if e := writeSystemAudit(ctx, q, r.OrgID, "policy.grant_expired", "policy_rule", r.ID.String(),
				map[string]any{"cause": "grant_expired"}); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range expired {
		if !seen[r.OrgID] {
			seen[r.OrgID] = true
			s.pushOrg(ctx, r.OrgID)
		}
	}
	return len(expired), nil
}

// StartGrantExpirySweeper runs the stateless expiry sweep on an interval until ctx ends.
// No in-memory window: a sweep error just retries next tick (the rows are still expired),
// and a grant that lapses during downtime is deleted+audited on the next tick after
// restart — the audit trail has no hole. Enterprise-only (started in main).
// mayTick gates each sweep on scheduler leadership (S13.1 review #10). nil = ungated (tests).
func (s *Service) StartGrantExpirySweeper(ctx context.Context, mayTick func() bool) {
	t := time.NewTicker(grantSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if mayTick != nil && !mayTick() {
				continue // followers serve requests but never tick
			}
			if n, err := s.SweepExpiredGrants(ctx); err != nil {
				slog.Warn("grant_expiry_sweep_failed", slog.String("error", err.Error()))
			} else if n > 0 {
				slog.Info("grant_expiry_swept", slog.Int("count", n))
			}
		}
	}
}

// writeSystemAudit records a SYSTEM-actor audit row (0027) in the caller's tx — the
// sweeper's grant_expired lapses have no human initiator.
func writeSystemAudit(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, action, targetType, targetID string, meta map[string]any) error {
	raw := []byte("{}")
	if meta != nil {
		b, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		raw = b
	}
	as := "policy-grants"
	tt, tid := targetType, targetID
	_, err := q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{
		OrgID: pgtype.UUID{Bytes: orgID, Valid: true}, ActorSystem: &as,
		Action: action, TargetType: &tt, TargetID: &tid, Metadata: raw,
	})
	return err
}

// ── enforcement mode ──────────────────────────────────────────────────────────

func (s *Service) GetMode(ctx context.Context, orgID uuid.UUID) (string, error) {
	org, err := s.q.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return "", err
	}
	return org.ZeroTrustMode, nil
}

// SetMode flips the org enforcement mode. Both directions are audited; disabling
// (enforcing -> off) re-opens the mesh and is the security-sensitive direction.
// Enabling with zero grants is ALLOWED (a locked-down posture is legitimate; the
// UI warns — the server obeys, per the S4.7 server-is-truth precedent).
// SetMode flips the org enforcement mode. Enabling (off->enforcing) returns the
// AFFECTED full-tunnel devices (S7.2 decision 2a): the server OBEYS regardless (S4.7
// server-is-truth), but the response tells the caller / the S7.4 warn-and-confirm
// exactly whose internet egress the flip governs (blast radius). Disabling returns no
// list (re-opening the mesh restores egress). Both directions are audited + push the
// gateways (via mutate).
func (s *Service) SetMode(ctx context.Context, orgID uuid.UUID, mode string) (string, []policyspec.AffectedDevice, error) {
	if mode != ModeOff && mode != ModeEnforcing {
		return "", nil, apierr.BadRequest("invalid_request", "mode must be off or enforcing")
	}
	err := s.mutate(ctx, orgID, func(q *sqlc.Queries) error {
		org, e := q.SetOrgZeroTrustMode(ctx, sqlc.SetOrgZeroTrustModeParams{ID: orgID, ZeroTrustMode: mode})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("org_not_found", "organization not found")
		}
		if e != nil {
			return e
		}
		action := "org.zero_trust_disabled"
		if org.ZeroTrustMode == ModeEnforcing {
			action = "org.zero_trust_enabled"
		}
		return writeAudit(ctx, q, orgID, action, "organization", orgID.String(), map[string]any{"mode": mode})
	})
	if err != nil {
		return "", nil, err
	}
	// The mode is committed + the gateways pushed the instant mutate() returned nil —
	// the enforcement change is ALREADY live. The affected-device list is advisory
	// blast-radius info for the caller / S7.4 warn-and-confirm; it is BEST-EFFORT and
	// must NEVER fail the call (finding #A). A failure here returning 500 would tell the
	// admin "failed to enable" while the org is in fact live-enforcing and blocking — a
	// UX-to-breach path. On its error we log and return success with no list (S4.7
	// server-is-truth: the mutation is truth; everything after is advisory).
	var affected []policyspec.AffectedDevice
	if mode == ModeEnforcing {
		if rows, e := s.q.ListActiveFullTunnelDevices(ctx, orgID); e != nil {
			slog.Warn("affected_full_tunnel_enumeration_failed_after_mode_commit",
				slog.String("org_id", orgID.String()), slog.String("error", e.Error()))
		} else {
			for _, r := range rows {
				affected = append(affected, policyspec.AffectedDevice{ID: r.ID, Name: r.Name})
			}
		}
	}
	return mode, affected, nil
}

// ── snapshot + invalidation (consumed by S7.2) ──────────────────────────────────

// BuildSnapshot loads the org's full policy state into the pure-compiler input.
// S7.2 calls Compile(BuildSnapshot(...)) when serving a node's desired state.
func (s *Service) BuildSnapshot(ctx context.Context, orgID uuid.UUID) (Snapshot, error) {
	snap, err := BuildSnapshotWithQueries(ctx, s.q, orgID)
	if err != nil {
		return Snapshot{}, err
	}
	if s.fqdnEntitled != nil {
		snap.FQDNResourcesLicensed = s.fqdnEntitled()
	}
	// A missing dependency, disabled opt-in, or absent entitlement is not an
	// error and must not revive a stored FQDN rule. The compiler sees an empty
	// FQDN input and default-denies that destination.
	if err := appendActiveFQDNGenerations(ctx, &snap, s.fqdnGenerations, orgID); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

func appendActiveFQDNGenerations(ctx context.Context, snap *Snapshot, reader fqdnresolver.ActiveGenerationReader, orgID uuid.UUID) error {
	if snap == nil || !snap.FQDNResourcesLicensed || !snap.FQDNResourcesEnabled || reader == nil {
		return nil
	}
	generations, err := reader.ActiveGenerations(ctx, orgID)
	if err != nil {
		// Do not compile against stale in-memory DNS state if the authoritative
		// persisted snapshot cannot be read.
		return err
	}
	for _, generation := range generations {
		resource, err := fqdnResourceFromActiveGeneration(generation)
		if err != nil {
			return err
		}
		snap.FQDNResources = append(snap.FQDNResources, resource)
	}
	return nil
}

// BuildSnapshotWithQueries exposes the canonical snapshot loader to an
// enclosing transaction. F09 preview/apply uses this rather than duplicating
// destination or membership resolution, so its digest and mutation are based
// on the exact same rows as the compiler.
func BuildSnapshotWithQueries(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID) (Snapshot, error) {
	settings, err := q.GetOrganizationPolicySnapshotSettings(ctx, orgID)
	if err != nil {
		return Snapshot{}, err
	}
	// COMPILER INPUT: active rules only — expired temporary grants are excluded here
	// (the clockless pure compiler can't filter by now(); the snapshot build applies
	// it). The admin LIST uses ListPolicyRulesByOrg (shows expired rules distinctly).
	rules, err := q.ListActivePolicyRulesForOrg(ctx, orgID)
	if err != nil {
		return Snapshot{}, err
	}
	resources, err := q.ListResourcesByOrg(ctx, orgID)
	if err != nil {
		return Snapshot{}, err
	}
	members, err := q.ListGroupMembershipsByOrg(ctx, orgID)
	if err != nil {
		return Snapshot{}, err
	}
	devices, err := q.ListActiveDevicesForOrg(ctx, orgID)
	if err != nil {
		return Snapshot{}, err
	}
	agentGroupMembers, err := q.ListActiveAgentGroupMembersForOrg(ctx, orgID)
	if err != nil {
		return Snapshot{}, err
	}
	siteSubnets, err := q.ListSiteSubnetsForOrg(ctx, orgID) // S8.1: dst_kind='site' resolution input
	if err != nil {
		return Snapshot{}, err
	}
	snap := Snapshot{Mode: settings.ZeroTrustMode, FQDNResourcesEnabled: settings.FqdnResourcesEnabled}
	for _, r := range rules {
		rule := Rule{
			ID:      r.ID,
			SrcKind: r.SrcKind, SrcGroupID: fromPgUUID(r.SrcGroupID), SrcUserID: fromPgUUID(r.SrcUserID),
			SrcSiteID:       fromPgUUID(r.SrcSiteID),       // S8.2: src_kind='site' resolution
			SrcCIDR:         derefString(r.SrcCidr),        // S8.7: src_kind='cidr' resolution
			SrcDeviceID:     fromPgUUID(r.SrcDeviceID),     // S15.3: src_kind='agent' resolution
			SrcAgentGroupID: fromPgUUID(r.SrcAgentGroupID), // F09: active agent-group resolution
			DstKind:         r.DstKind,
			DstResourceID:   fromPgUUID(r.DstResourceID), DstGroupID: fromPgUUID(r.DstGroupID),
			DstSiteID:       fromPgUUID(r.DstSiteID),
			DstK8sServiceID: fromPgUUID(r.DstK8sServiceID), // S10.3: dst_kind='k8s_service' resolution
			Disabled:        r.Disabled,                    // F3: carried to the compiler, which OWNS the skip
		}
		snap.Rules = append(snap.Rules, rule)
		if r.DstKind == "fqdn_resource" && r.DstFqdnResourceID != uuid.Nil {
			snap.FQDNRuleReferences = append(snap.FQDNRuleReferences, FQDNRuleReference{PolicyRuleID: r.ID, FQDNResourceID: r.DstFqdnResourceID})
		}
	}
	for _, ss := range siteSubnets {
		snap.SiteSubnets = append(snap.SiteSubnets, SiteSubnet{SiteID: ss.SiteID, CIDR: ss.Cidr.String()})
	}
	siteNodes, err := q.ListSiteNodesForOrg(ctx, orgID) // S8.2: (site_id, node_id) for src placement
	if err != nil {
		return Snapshot{}, err
	}
	for _, sn := range siteNodes {
		snap.SiteNodes = append(snap.SiteNodes, SiteNode{SiteID: fromPgUUID(sn.SiteID), NodeID: sn.ID, Endpoint: sn.Endpoint})
	}
	for _, r := range resources {
		snap.Resources = append(snap.Resources, Resource{
			ID: r.ID, CIDR: r.Cidr, Protocol: r.Protocol,
			PortLow: derefI32(r.PortLow), PortHigh: derefI32(r.PortHigh),
		})
	}
	// S10.3: exposed K8s Services (id -> current VIP) for dst_kind='k8s_service' resolution. LIVE only, so a
	// soft-deleted Service is absent -> its grant compiles to nothing.
	exposed, err := q.ListActiveK8sServicesForOrg(ctx, orgID)
	if err != nil {
		return Snapshot{}, err
	}
	for _, e := range exposed {
		snap.ExposedServices = append(snap.ExposedServices, ExposedService{
			ID: e.ID, VIP: e.Vip, DNSVIP: e.DnsVip, Protocol: e.Protocol,
			PortLow: derefI32(e.PortLow), PortHigh: derefI32(e.PortHigh), SiteID: e.SiteID,
			ConnectorNodeID: fromPgUUID(e.ConnectorNodeID),
		})
	}
	for _, m := range members {
		snap.Memberships = append(snap.Memberships, Membership{GroupID: m.GroupID, UserID: m.UserID})
	}
	for _, m := range agentGroupMembers {
		snap.AgentGroupMemberships = append(snap.AgentGroupMemberships, AgentGroupMembership{
			GroupID: m.AgentGroupID, DeviceID: m.DeviceID,
		})
	}
	for _, d := range devices {
		ip := ""
		if d.AssignedIp != nil {
			ip = *d.AssignedIp
		}
		snap.Devices = append(snap.Devices, Device{
			ID: d.ID, UserID: d.UserID, NodeID: d.NodeID, AssignedIP: ip,
			Kind: d.Kind, ConfigRevision: d.AgentConfigRevision,
		})
	}
	return snap, nil
}

// CompiledForNode builds the per-node compiled artifact the control plane pushes in
// the desired state (S7.2). A node with active devices gets its compiled entry; a
// device-LESS node gets an explicit deny-all under enforcing (so the blanket mesh is
// removed proactively, not left until the first device) or nil under off (legacy
// mesh). This is the nodes.PolicyProvider the desired-state path calls.
func (s *Service) CompiledForNode(ctx context.Context, orgID, nodeID, activeHub uuid.UUID) (*policyspec.Compiled, error) {
	snap, err := s.BuildSnapshot(ctx, orgID)
	if err != nil {
		return nil, err
	}
	snap.ActiveHub = activeHub // S8.6 REDUCE #1: the derived active hub, threaded — the compiler never elects
	compiled := Compile(snap)
	if c, ok := compiled[nodeID]; ok {
		return &c, nil
	}
	if snap.Mode == ModeEnforcing {
		// Content-derived version (#6, per the Slice-1 RequiredVersion law): an empty deny-all needs no
		// v5 feature. The CORE finalizeArtifact/pushedHash attach routes + re-derive the version, so a
		// device-less SITE gateway still lands at v5 consistently across the served + pushed paths.
		return &policyspec.Compiled{
			Version: policyspec.RequiredVersion(policyspec.Compiled{Mode: ModeEnforcing}), NodeID: nodeID.String(),
			Mode: ModeEnforcing, Mesh: false, Subjects: subjectAttribution(snap.Devices), // deny-all: no blanket even with no devices
		}, nil
	}
	return nil, nil // off / no policy -> agent keeps the legacy mesh
}

// CompiledArtifactsForNodes returns each requested node's ROUTE-LESS compiled artifact, building the org
// snapshot ONCE (finding #5). Route-less BY DESIGN: the CORE finalizeArtifact/pushedHash attach the site
// routes + derive the version, so the pushed-hash baseline is computed the SAME way the served artifact
// is — the #1 single-source fix (two compile paths can no longer disagree). Per node it reproduces
// CompiledForNode's pick-or-fallback: the compiled entry, else the enforcing deny-all (content-derived
// version), else nil for off / no-policy (the core pushedHash renders nil + non-enforcing as "").
func (s *Service) CompiledArtifactsForNodes(ctx context.Context, orgID uuid.UUID, nodeIDs []uuid.UUID, activeHub uuid.UUID) (map[uuid.UUID]*policyspec.Compiled, error) {
	snap, err := s.BuildSnapshot(ctx, orgID)
	if err != nil {
		return nil, err
	}
	snap.ActiveHub = activeHub // S8.6 REDUCE #1: the derived active hub, threaded — the compiler never elects
	out := make(map[uuid.UUID]*policyspec.Compiled, len(nodeIDs))
	compiled := Compile(snap)
	enforcing := snap.Mode == ModeEnforcing
	for _, id := range nodeIDs {
		if c, ok := compiled[id]; ok {
			cc := c
			out[id] = &cc
			continue
		}
		if enforcing {
			// Enforcing node with no active devices → the deny-all fallback (content-derived version,
			// #6), IDENTICAL to what CompiledForNode serves; the core finalize re-derives v5 for a
			// device-less SITE gateway consistently on both paths.
			out[id] = &policyspec.Compiled{
				Version: policyspec.RequiredVersion(policyspec.Compiled{Mode: ModeEnforcing}), NodeID: id.String(),
				Mode: ModeEnforcing, Mesh: false, Subjects: subjectAttribution(snap.Devices),
			}
			continue
		}
		out[id] = nil // off / no policy — pushedHash renders "" (no enforcement boundary, finding #C)
	}
	return out, nil
}

// AffectedNodeIDs returns the nodes whose compiled policy could change for this
// org — the nodes that currently host active devices. A policy mutation is
// org-wide, so S7.2 recompiles + pushes to exactly these nodes (the invalidation
// target). Model-layer logic, tested here; the push itself is S7.2.
func (s *Service) AffectedNodeIDs(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	return s.q.ListActiveNodeIDsForOrg(ctx, orgID)
}

// ── helpers ─────────────────────────────────────────────────────────────────────

// Notifier signals gateways to re-fetch desired state (the <5s push path). The
// nodepush hub satisfies it; nil = no push (tests / provider-only service).
type Notifier interface{ NotifyMany(nodeIDs []uuid.UUID) }

// mutate runs a mutation in a transaction and, on success, PUSHES the org's
// device-hosting gateways so they re-fetch + recompile within the <5s spec. Every
// compiler input changes through one of these (group/resource/rule CRUD, membership
// add/remove, mode) -- so wrapping them here is the single choke point for the
// recompile+push triggers. The push is best-effort (a missed signal is caught by the
// agent's reconcile-interval safety net); it never fails the mutation.
func (s *Service) mutate(ctx context.Context, orgID uuid.UUID, fn func(*sqlc.Queries) error) error {
	if err := s.withTx(ctx, fn); err != nil {
		return err
	}
	s.pushOrg(ctx, orgID)
	return nil
}

// pushOrg notifies every gateway that currently hosts an active device in the org
// (the nodes whose compiled policy could change). Best-effort.
func (s *Service) pushOrg(ctx context.Context, orgID uuid.UUID) {
	if s.notify == nil {
		return
	}
	ids, err := s.AffectedNodeIDs(ctx, orgID)
	if err != nil || len(ids) == 0 {
		return
	}
	s.notify.NotifyMany(ids)
}

func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if err := fn(sqlc.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// writeAudit records an actor-attributed, secret-free audit row in the same tx.
// writeAuditAs (S10.2 M1b) audits a policy mutation with the CALLER'S attribution: a MACHINE → actor_system
// (operator:<name>) with the cause (the CR) in metadata; a HUMAN → actor_user_id. It mirrors the k8s
// service.audit() helper EXACTLY. Before this, the policy path had only writeAudit (actorPg → a machine's
// UserID is uuid.Nil, stamped as a VALID ZERO user-id: the confidently-wrong attribution D3 exists to
// prevent) and writeSystemAudit (hardcoded "policy-grants", no cause). M1b root = two audit helpers, one
// taught the machine branch in Slice 1 and one not (guard-not-mirrored); the durable fix (one helper) is
// registered in docs/S10.2-decisions.md.
func writeAuditAs(ctx context.Context, q *sqlc.Queries, orgID, actorUserID uuid.UUID, actorSystem, cause, action, targetType, targetID string, meta map[string]any) error {
	if meta == nil {
		meta = map[string]any{}
	}
	tt, tid := targetType, targetID
	if actorSystem != "" {
		if cause != "" {
			meta["cause"] = cause
		}
		b, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		as := actorSystem
		_, err = q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{
			OrgID: pgtype.UUID{Bytes: orgID, Valid: true}, ActorSystem: &as,
			Action: action, TargetType: &tt, TargetID: &tid, Metadata: b,
		})
		return err
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID: pgtype.UUID{Bytes: orgID, Valid: true},
		// NULL (not a fake zero) when there is no human actor — see k8s service.audit(): the 0027 CHECK
		// permits a neither-actor row, and a zero uuid would violate the actor_user_id FK.
		ActorUserID: pgtype.UUID{Bytes: actorUserID, Valid: actorUserID != uuid.Nil},
		Action:      action, TargetType: &tt, TargetID: &tid, Metadata: b,
	})
	return err
}

func writeAudit(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, action, targetType, targetID string, meta map[string]any) error {
	// metadata is NOT NULL — default a nil meta to an empty JSON object, never a nil
	// []byte (which pgx sends as SQL NULL → 23502, silently 500ing every audited DELETE
	// that passes nil: group.deleted / resource.deleted / policy.rule_deleted). The other
	// audit helpers (invites, sso, devices, nodes) already default to "{}"; this one didn't.
	raw := []byte("{}")
	if meta != nil {
		b, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		raw = b
	}
	tt := targetType
	tid := targetID
	_, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: orgID, Valid: true},
		ActorUserID: actorPg(ctx),
		Action:      action,
		TargetType:  &tt,
		TargetID:    &tid,
		Metadata:    raw,
	})
	return err
}

func actorPg(ctx context.Context) pgtype.UUID {
	if p, ok := authctx.PrincipalFrom(ctx); ok {
		return pgtype.UUID{Bytes: p.UserID, Valid: true}
	}
	return pgtype.UUID{Valid: false}
}

// conflictIfDup maps a unique-violation (23505) to a clean 409; other errors pass through.
func conflictIfDup(err error, msg string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return apierr.New(http.StatusConflict, "conflict", msg)
	}
	return err
}

// canonicalCIDR returns the masked (host-bits-zeroed) form of a prefix already
// validated by validateResource, so the stored + compiled DstCIDR is canonical
// (e.g. 10.0.5.5/24 -> 10.0.5.0/24) and never rejected/mis-read by the S7.2
// nftables/ipset apply.
func canonicalCIDR(s string) string {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return s // unreachable after validateResource; keep input rather than panic
	}
	return p.Masked().String()
}

func toPgUUID(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

// derefString maps a nullable text pointer (sqlc emits *string for a nullable column) to its value, "" when
// NULL — the src_cidr (S8.7) read path.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// toPgUUIDVal maps a value UUID to nullable pg: uuid.Nil => SQL NULL (a per-user
// rule has src_group_id NULL, and vice versa).
func toPgUUIDVal(id uuid.UUID) pgtype.UUID {
	if id == uuid.Nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: id, Valid: true}
}

func toPgTimestamptz(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func fromPgUUID(v pgtype.UUID) uuid.UUID {
	if !v.Valid {
		return uuid.Nil
	}
	return uuid.UUID(v.Bytes)
}

func i32ptr(p *int) *int32 {
	if p == nil {
		return nil
	}
	v := int32(*p)
	return &v
}

func derefI32(p *int32) int {
	if p == nil {
		return 0
	}
	return int(*p)
}

// fqdnResourceFromActiveGeneration is the only adapter from Lane 2's durable
// resolver snapshot to compiler input. It rejects malformed context rather
// than treating an answer set as portable across Sites or gateways.
func fqdnResourceFromActiveGeneration(g fqdnresolver.ActiveGeneration) (FQDNResource, error) {
	site, err := uuid.Parse(g.Context.ResolverID)
	if err != nil || site == uuid.Nil {
		return FQDNResource{}, fmt.Errorf("invalid selected Site in active FQDN generation %s", g.ResourceID)
	}
	gateway, err := uuid.Parse(g.Context.GatewayID)
	if err != nil || gateway == uuid.Nil {
		return FQDNResource{}, fmt.Errorf("invalid selected gateway in active FQDN generation %s", g.ResourceID)
	}
	if g.ResourceID == uuid.Nil || g.Hostname == "" || len(g.Addresses) == 0 || len(g.Addresses) > fqdnresolver.MaxAnswers {
		return FQDNResource{}, fmt.Errorf("invalid active FQDN generation %s", g.ResourceID)
	}
	configID, err := uuid.Parse(g.ResolverConfig.ID)
	if err != nil || configID == uuid.Nil || g.ResolverConfig.Version < 1 || len(g.ResolverConfig.Endpoints) == 0 || len(g.ResolverConfig.Endpoints) > 8 {
		return FQDNResource{}, fmt.Errorf("invalid resolver configuration snapshot for active FQDN generation %s", g.ResourceID)
	}
	for _, endpoint := range g.ResolverConfig.Endpoints {
		if !endpoint.Address.IsValid() || endpoint.Address.IsUnspecified() || endpoint.Address.IsLoopback() || endpoint.Address.IsMulticast() || endpoint.Address.IsLinkLocalUnicast() || endpoint.Port == 0 || (endpoint.Transport != "udp" && endpoint.Transport != "tcp") {
			return FQDNResource{}, fmt.Errorf("invalid resolver endpoint snapshot for active FQDN generation %s", g.ResourceID)
		}
	}
	answers := make([]string, 0, len(g.Addresses))
	for _, address := range g.Addresses {
		if !address.IsValid() {
			return FQDNResource{}, fmt.Errorf("invalid active FQDN answer for %s", g.ResourceID)
		}
		answers = append(answers, address.String())
	}
	return FQDNResource{
		ID:       g.ResourceID,
		FQDN:     g.Hostname,
		Protocol: g.Protocol,
		PortLow:  derefI32(g.PortLow),
		PortHigh: derefI32(g.PortHigh),
		Active: &FQDNGeneration{
			ResourceID:            g.ResourceID,
			SelectedSiteID:        site,
			SelectedGatewayID:     gateway,
			ResolverConfigID:      configID,
			ResolverConfigVersion: g.ResolverConfig.Version,
			Answers:               answers,
		},
	}, nil
}
