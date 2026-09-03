// Package rbac is the single source of the authorization model: what each role
// may do. Call sites ask Can(role, permission) — never `role == "admin"` — so
// when a role is added or a permission moves, only this file changes.
package rbac

import "sort"

// Permission is a capability a role may hold.
type Permission string

const (
	PermOrgView      Permission = "org:view"
	PermOrgUpdate    Permission = "org:update"
	PermOrgDelete    Permission = "org:delete"
	PermMemberList   Permission = "member:list"
	PermMemberInvite Permission = "member:invite"
	// PermMemberManage is the base capability to change roles / remove members.
	// Relational limits (who may touch whom) are applied by CanManageMembership.
	PermMemberManage Permission = "member:manage"
	// Zero Trust policy (S7.1, enterprise). PermPolicyView reads the model
	// (groups/resources/rules/mode); PermPolicyManage mutates it AND flips the
	// enforcement mode — disabling re-opens the mesh, so it is the same
	// (owner/admin) capability, deliberately not a members-level read.
	PermPolicyView   Permission = "policy:view"
	PermPolicyManage Permission = "policy:manage"
	// PermAccessEventRetentionManage governs the organization-wide lifecycle of
	// access-event records. It is deliberately separate from policy:manage: an
	// automated policy operator may author grants, but may not shorten audit-data
	// retention or trigger maintenance that deletes expired records.
	PermAccessEventRetentionManage Permission = "access_event_retention:manage"
	// Audit-log retention has a dedicated read permission as well as management:
	// its latest deletion counts and failure state are control-plane evidence,
	// not organization-wide member metadata. Both are owner/admin-grained, while
	// only management requires a verified mutating principal.
	PermAuditLogRetentionView   Permission = "audit_log_retention:view"
	PermAuditLogRetentionManage Permission = "audit_log_retention:manage"
	// FQDN resources are a separate, resolver-backed destination capability. They
	// must never inherit policy permissions implicitly: callers need an explicit
	// FQDN read or manage grant before the later entitlement and organization
	// opt-in gates can disclose or mutate resolver-backed state (S21 D7).
	PermFQDNResourceView   Permission = "fqdn_resource:view"
	PermFQDNResourceManage Permission = "fqdn_resource:manage"
	// PermDeviceApprove governs device posture (S7.3, enterprise): approving/rejecting a
	// pending device AND flipping the org device-approval gate. A distinct capability from
	// policy:manage because device-trust is its own governance domain (an org may require
	// device approval without Zero Trust policy, or vice versa) — but at the SAME
	// owner/admin grain, since approving a device GRANTS network access (security-sensitive,
	// above org:update).
	PermDeviceApprove Permission = "device:approve"
	// PermDeviceHealthManage governs device HEALTH posture (S7.5.3, enterprise):
	// configuring the org's per-check posture requirements (warn/require). Named per
	// feature — deliberately NOT a reuse of PermDeviceApprove: approval (known-device)
	// and health (healthy-device) are orthogonal governance axes, and reusing the
	// approve perm would silently grant posture control to every existing approver.
	// Same owner/admin grain (a require-mode check can disconnect devices). The
	// self-REPORT endpoint carries no perm: it is device-owner-authed in the service.
	PermDeviceHealthManage Permission = "device_health:manage"
	// PermDeviceRestore governs restoring the devices a gateway revoke cascaded (S13.1 Slice 7). Named per
	// feature, and deliberately NOT a reuse of org:update (which revokes a node) or device:approve: this is the
	// capability to UNDO a revoke's blast radius, and reusing the revoke permission would mean everyone who can
	// take access away silently gained the power to hand it back — the two halves of a security decision, granted
	// by one checkbox. Owner/admin grain: restoring a device returns network access to a user.
	//
	// It is the AUTHORIZATION HALF of D3. A proof of possession may never overturn a human decision, so the only
	// thing that can is another human, holding a permission that says so.
	PermDeviceRestore Permission = "device:restore"

	// PermDeviceTransfer governs MOVING a gateway's live devices onto another gateway (S12.12 D1). Named per
	// feature, and deliberately NOT a reuse of device:restore or org:update — the invariant is that a new
	// capability never rides in on an existing permission, and this one has a distinct blast radius from
	// both. Restore hands access BACK to devices a revoke took it from; transfer moves LIVE users between
	// gateways, which changes which gateway serves them and, when the destination sits in a different site,
	// WHICH POLICY RULES APPLY TO THEM (D5). Reusing the revoke permission would mean everyone who can retire
	// a gateway silently gained the power to re-scope a fleet's access. Owner/admin grain.
	PermDeviceTransfer Permission = "device:transfer"

	// PermLicenseManage governs installing a licence key (S12.1).
	//
	// ⛔ OWNER-ONLY, AND DELIBERATELY NOT A REUSE OF org:update. Installing a licence changes what the
	// WHOLE DEPLOYMENT may do — how many gateways, how many organizations, whether SSO exists — and an
	// admin who can rename an org must not thereby be able to change the commercial entitlement of every
	// org on the box. Named per capability, like every other permission here.
	//
	// ⚠ Reading the entitlement is NOT gated by this: any member may see which tier they are on, because a
	// user hitting a ceiling needs to understand why without asking an owner.
	PermLicenseManage Permission = "license:manage"
	// PermMfaManage governs ORG-LEVEL MFA (S7.5.5, enterprise): the enforce toggle + admin-reset
	// of a member's MFA. Named per feature (NOT a policy/member reuse) — MFA governance is its own
	// axis, and admin-reset is an account-takeover-adjacent power (disenroll-only, audited,
	// target-notified). Owner/admin grain (mandating MFA / resetting a factor is security-sensitive).
	// Self-service enrollment carries NO perm — it is user-owned (any authenticated user).
	PermMfaManage Permission = "mfa:manage"
	// PermSiteManage governs SITE-TO-SITE (S8.1, EPIC 8): registering site gateways, binding a node,
	// adding subnets, and APPROVING advertised subnets (a compromised gateway must not hijack routes —
	// approval is an admin checkpoint). Named per feature (site governance is its own axis).
	// Owner/admin grain (site routing + advertisement approval are network-shaping powers).
	PermSiteManage Permission = "site:manage"
	// PermK8sManage governs KUBERNETES cluster registration + Service exposure (S10.3, EPIC 10): the
	// CONNECTIVITY layer — registering a cluster's synthetic VIP range and exposing an in-cluster Service
	// to the fabric. Named per feature (K8s connectivity is its own axis; NOT a site/policy reuse).
	// CORE (all editions, like site:manage) — GOVERNANCE of a grant reaching a Service is the separate
	// enterprise gate. Owner/admin grain (VIP-range + exposure are network-shaping powers).
	PermK8sManage Permission = "k8s:manage"
	// Connector HA and cluster-scope governance are distinct capabilities. HA
	// observation is safe for the fixed machine operator, but activation is a
	// human owner/admin decision. Cluster-scope data is enterprise governance;
	// machines receive none of its view, lifecycle, or approval authorities.
	PermK8sHAView       Permission = "k8s_ha:view"
	PermK8sHAManage     Permission = "k8s_ha:manage"
	PermK8sScopeView    Permission = "k8s_scope:view"
	PermK8sScopeManage  Permission = "k8s_scope:manage"
	PermK8sScopeApprove Permission = "k8s_scope:approve"
	// PermMachineManage governs MACHINE CREDENTIALS (S10.2, EPIC 10): minting/revoking a first-class
	// NON-USER org principal (the GitOps operator's identity). OWNER-ONLY grain — a machine credential is
	// a non-human caller that can register clusters, expose Services, and (enterprise) create grants, so
	// creating one is org-delete-grade privilege. Named per feature; never a member/policy reuse.
	PermMachineManage Permission = "machine:manage"
	// PermAgentRuntimeManage governs the F04 organization opt-in. This is a
	// separate security decision from enrolling an agent or editing ordinary
	// organization metadata: enabling it opens an unattended configuration
	// channel to every eligible managed agent in the organization.
	PermAgentRuntimeManage Permission = "agent_runtime:manage"
	// PermAgentCredentialRotate authorizes the one human checkpoint that asks
	// an active managed agent to replace its machine bearer. It is deliberately
	// narrower than runtime opt-in, device lifecycle, and future F06 delegation.
	PermAgentCredentialRotate Permission = "agent_credential:rotate"
	// F06 agent-governance permissions are deliberately separate: enrolling,
	// reading privileged facts, managing lifecycle/metadata, authoring access,
	// and revoking have different blast radii and must not ride on org/member
	// administration permissions.
	PermAgentEnroll         Permission = "agent:enroll"
	PermAgentViewPrivileged Permission = "agent:view_privileged"
	PermAgentManage         Permission = "agent:manage"
	PermAgentGrantAccess    Permission = "agent:grant_access"
	PermAgentRevoke         Permission = "agent:revoke"
	// PermAgentTemplateManage governs the F09 organization opt-in plus agent
	// group/template administration. Applying a template still separately
	// requires policy:manage and agent:grant_access.
	PermAgentTemplateManage Permission = "agent_template:manage"
	// F10 separates asking for temporary access from approving it. Scoped agent
	// owners/managers receive request authority relationally; only owner/admin
	// roles hold organization-wide approval authority.
	PermAgentAccessRequest Permission = "agent_access:request"
	PermAgentAccessApprove Permission = "agent_access:approve"
	// PermAlertingManage governs F11 alert destinations, subscriptions, test
	// sends, and delivery history. It is intentionally not a reuse of runtime,
	// policy, or agent lifecycle authority: configuring a webhook authorizes the
	// control plane to make outbound requests on behalf of the organization.
	PermAlertingManage Permission = "alerting:manage"
	// PermAgentMCPToolPolicyManage governs the exact allow-list used by F14's
	// explicit local MCP proxy. It is separate from network-policy, OAuth
	// consent, and lifecycle permissions because it authorizes tool invocation.
	PermAgentMCPToolPolicyManage Permission = "agent_mcp_tool_policy:manage"
	// Separate human approval authority: policy authors cannot implicitly
	// approve their own tool invocations.
	PermAgentMCPToolApprovalApprove Permission = "agent_mcp_tool_approval:approve"
)

// Roles.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
	// RoleOperator (S10.2) is the fixed role a MACHINE credential holds — NOT user-assignable (the member
	// role picker offers owner/admin/member only). Scoped to EXACTLY what the GitOps operator needs (D3):
	// register a cluster, expose a Service, create a grant, and read the org — nothing else (no member
	// management, no org delete, no MFA/site/machine administration). A machine principal's Roles map is
	// {orgID: "operator"}.
	RoleOperator = "operator"
	// RoleAgent (S15.2, D4) — the fixed role a DATA-PLANE AGENT holds. NOT user-assignable, and NOT the
	// same principal kind as RoleOperator.
	//
	// ⛔ THE SPLIT IS THE POINT, AND IT IS WHY THIS COULD NOT SHIP BEFORE THE AGENT PRINCIPAL EXISTED.
	// `RoleOperator` holds PermPolicyManage — correct for a GitOps operator, whose entire job is reconciling
	// TunnexGrant CRs into policy rules, and INVERTED for an agent. An agent is a principal that can be
	// talked into a request; one that could then WRITE THE RULE PERMITTING IT is a compromised principal
	// granting itself what it was denied.
	//
	// ⚠ The fix was never "remove PermPolicyManage" — that breaks the operator. It was "stop having one role
	// for two principal kinds", and that requires the second kind. This is it.
	RoleAgent = "agent"
)

// rolePermissions is the role -> permission grant table. This map IS the policy.
//
// MIRRORED CLIENT-SIDE in apps/web/src/lib/rbac.ts (to gate which controls
// render). The server is authoritative; the client copy is UX only. This GRANT
// TABLE is now machine-synced: `make generate-rbac` serializes Policy() to
// apps/web/src/lib/rbac-policy.json (which rbac.ts consumes) and generate-check
// fails the build if they drift — so editing this table can't silently desync
// the client. NOTE: CanManageMembership's relational rules are logic, not data,
// so they are NOT covered by the guard and are still hand-mirrored in rbac.ts.
var rolePermissions = map[string]map[Permission]bool{
	RoleMember: {
		PermOrgView:    true,
		PermMemberList: true,
	},
	RoleAdmin: {
		PermOrgView:                     true,
		PermMemberList:                  true,
		PermOrgUpdate:                   true,
		PermMemberInvite:                true,
		PermMemberManage:                true,
		PermPolicyView:                  true,
		PermPolicyManage:                true,
		PermAccessEventRetentionManage:  true,
		PermAuditLogRetentionView:       true,
		PermAuditLogRetentionManage:     true,
		PermFQDNResourceView:            true,
		PermFQDNResourceManage:          true,
		PermDeviceApprove:               true,
		PermDeviceRestore:               true,
		PermDeviceTransfer:              true,
		PermDeviceHealthManage:          true,
		PermMfaManage:                   true,
		PermSiteManage:                  true,
		PermK8sManage:                   true,
		PermK8sHAView:                   true,
		PermK8sHAManage:                 true,
		PermK8sScopeView:                true,
		PermK8sScopeManage:              true,
		PermK8sScopeApprove:             true,
		PermAgentRuntimeManage:          true,
		PermAgentCredentialRotate:       true,
		PermAgentEnroll:                 true,
		PermAgentViewPrivileged:         true,
		PermAgentManage:                 true,
		PermAgentGrantAccess:            true,
		PermAgentRevoke:                 true,
		PermAgentTemplateManage:         true,
		PermAgentAccessRequest:          true,
		PermAgentAccessApprove:          true,
		PermAlertingManage:              true,
		PermAgentMCPToolPolicyManage:    true,
		PermAgentMCPToolApprovalApprove: true,
	},
	RoleOwner: {
		PermOrgView:                     true,
		PermMemberList:                  true,
		PermOrgUpdate:                   true,
		PermOrgDelete:                   true,
		PermMemberInvite:                true,
		PermMemberManage:                true,
		PermPolicyView:                  true,
		PermPolicyManage:                true,
		PermAccessEventRetentionManage:  true,
		PermAuditLogRetentionView:       true,
		PermAuditLogRetentionManage:     true,
		PermFQDNResourceView:            true,
		PermFQDNResourceManage:          true,
		PermDeviceApprove:               true,
		PermDeviceRestore:               true,
		PermDeviceTransfer:              true,
		PermDeviceHealthManage:          true,
		PermMfaManage:                   true,
		PermSiteManage:                  true,
		PermK8sManage:                   true,
		PermK8sHAView:                   true,
		PermK8sHAManage:                 true,
		PermK8sScopeView:                true,
		PermK8sScopeManage:              true,
		PermK8sScopeApprove:             true,
		PermLicenseManage:               true,
		PermMachineManage:               true, // owner-only: minting a non-human org principal is org-delete-grade
		PermAgentRuntimeManage:          true,
		PermAgentCredentialRotate:       true,
		PermAgentEnroll:                 true,
		PermAgentViewPrivileged:         true,
		PermAgentManage:                 true,
		PermAgentGrantAccess:            true,
		PermAgentRevoke:                 true,
		PermAgentTemplateManage:         true,
		PermAgentAccessRequest:          true,
		PermAgentAccessApprove:          true,
		PermAlertingManage:              true,
		PermAgentMCPToolPolicyManage:    true,
		PermAgentMCPToolApprovalApprove: true,
	},
	// RoleOperator (S10.2) — the machine credential's fixed role, scoped to exactly the operator's verbs
	// (D3). NOT user-assignable. NO machine:manage (a machine can't mint more machines), NO member/org
	// administration. PermPolicyManage is still enterprise-gated at the handler (a TunnexGrant → 403
	// edition_required in the open build), so holding the perm here does not widen the edition surface.
	RoleOperator: {
		PermOrgView:          true,
		PermK8sManage:        true,
		PermK8sHAView:        true,
		PermPolicyView:       true,
		PermPolicyManage:     true,
		PermAgentGrantAccess: true,
		// member:list is READ-ONLY (WF-OP-1) — the operator resolves a TunnexGrant's user subject
		// (email -> id) via GET /members; it NEVER mutates membership (no member:invite / member:manage).
		// The role was first scoped from the intended verbs, before the subject-resolution path existed;
		// enumerate a principal's role from the CALL GRAPH it traverses, not the feature description.
		PermMemberList: true,
	},
	// RoleAgent (S15.2, D4) — a data-plane agent. ⛔ NO PermPolicyManage: an agent READS the policy it is
	// told to enforce and never authors it. NO machine:manage, no member/org administration, no device
	// verbs. It is the narrowest non-human role in the table, and deliberately so.
	//
	// ⚠ PermOrgView ONLY, and even that is under review by whoever next needs an agent to read something:
	// the honest default for a principal that acts unattended is that every permission is argued for
	// individually, not inherited from a sibling role that happened to exist first.
	RoleAgent: {
		PermOrgView: true,
	},
}

// Can reports whether a role holds a permission.
func Can(role string, p Permission) bool {
	return rolePermissions[role][p]
}

// Policy returns the role→permissions grant table as sorted string slices — the
// serializable, authoritative form. `make generate-rbac` marshals this to
// apps/web/src/lib/rbac-policy.json, which the client RBAC mirror (lib/rbac.ts)
// consumes; `make generate-check` then fails the build if the committed JSON has
// drifted from this table. So this map is the ONE source of truth for grants and
// the client can no longer silently diverge. (canManageMembership's relational
// rules are logic, not data, and remain mirrored by hand.)
func Policy() map[string][]string {
	out := make(map[string][]string, len(rolePermissions))
	for role, perms := range rolePermissions {
		list := make([]string, 0, len(perms))
		for p := range perms {
			list = append(list, string(p))
		}
		sort.Strings(list)
		out[role] = list
	}
	return out
}

// IsMutating reports whether a permission changes state. Mutating actions are
// gated on a verified email (S2.2); read permissions are not.
func IsMutating(p Permission) bool {
	// Deliberately an ALLOWLIST OF READS: only the read permissions are
	// non-mutating; everything else (including any future permission) is treated
	// as mutating and therefore gated on a verified email. This is the
	// fail-closed polarity — an unclassified new permission gets the gate by
	// default, so the worst case is an unverified user 403ing on a read, never an
	// unverified user slipping through a mutation. Do NOT invert this into a
	// mutating-allowlist.
	switch p {
	case PermOrgView, PermMemberList, PermPolicyView, PermAuditLogRetentionView, PermFQDNResourceView, PermAgentViewPrivileged, PermK8sHAView, PermK8sScopeView:
		return false
	default:
		return true
	}
}

// ValidRole reports whether role is a known role.
func ValidRole(role string) bool {
	_, ok := rolePermissions[role]
	return ok
}

// CanManageMembership reports whether an actor may set target's role to newRole
// (newRole == "" means removal). It layers relational rules on PermMemberManage:
//   - only an owner may manage an existing owner;
//   - only an owner may grant the owner role (no privilege escalation by admins).
//
// The last-owner invariant (an org must keep >= 1 owner) is enforced separately
// at the service layer, since it requires counting current owners.
func CanManageMembership(actorRole, targetRole, newRole string) bool {
	if !Can(actorRole, PermMemberManage) {
		return false
	}
	if targetRole == RoleOwner && actorRole != RoleOwner {
		return false
	}
	if newRole == RoleOwner && actorRole != RoleOwner {
		return false
	}
	return true
}
