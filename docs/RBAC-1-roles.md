# RBAC-1: roles that fit how teams split the work

Status: decisions locked by the founder on 2026-11-27 ("approver choad ke sab kr
do", plus "readonly admin require ho to wo bhi bna do"). Story branch
`story/rbac-1`, stacked on `story/ai-ux-1`.

## Problem

People get one of five roles: Owner, Admin, Member, AI admin, AI viewer. A
person can hold several. Owner and Admin differ only in deleting the
organization, the licence and machine credentials. Anything between Member and
Admin is impossible:

1. A security or compliance reviewer must be made Admin to read policies,
   access events, agent activity or the organization audit log, which also lets
   them turn Zero Trust off.
2. The team that runs AI agents must be Admin to add agents, connect MCP
   servers and set tool choices, which also gives them users, MFA and network
   setup.
3. The IT or network team must be Admin to run gateways, sites, IPsec,
   Kubernetes and rules, which also gives them users, MFA and AI.
4. Helpdesk must be Admin to approve a device or reset someone's MFA.
5. "AI admin" and "AI viewer" cover only AI Gateway, not AI agents or MCP. The
   names suggest otherwise.

## Decisions

### New roles

- Locked: **Auditor** (`auditor`). Sees what an admin sees and changes nothing.
  The founder chose the name on 2026-11-27, replacing "Read-only admin",
  because it is the term buyers and other access products use.
  - Grants every view permission an admin has, plus a new `audit:view_all` for
    the organization-wide audit log.
  - Does not see: Vault secret values, Server Access session recordings, AI
    provider key material, MCP approval arguments (approvals need
    `agent_mcp_tool_approval:approve`), install tokens beyond their metadata.
- Locked: **AI Agents admin** (`agents-admin`). Runs AI agents and MCP.
  - Agent enrol, manage, revoke, credential rotation, privileged agent view;
    runtime synchronization; agent groups and policy templates; MCP switch,
    servers and tool policy; MCP approvals; agent access requests and
    approvals; access rules whose source is an agent or an agent group.
  - Not: rules for people or devices, user groups, Zero Trust mode, AI Gateway
    model access (combine with AI Gateway admin when needed), users, MFA.
- Locked: **Network admin** (`network-admin`). Runs the network.
  - Gateways and connectivity, sites, IPsec, Kubernetes (all scopes), FQDN
    resources, resources, access rules, devices (approve, restore, transfer,
    device health), access events.
  - Not: Zero Trust on or off, user groups and directory sync (these stay under
    `policy:manage`, which only Owner and Admin hold), users, MFA, AI, agents.
- Locked: **Helpdesk** (`helpdesk`). Helps people get connected.
  - Member list, device approve and restore, MFA reset, devices view.
  - MFA reset and device actions only for a person who holds no admin-grade
    role (Owner, Admin, Network admin, AI Agents admin, Auditor, AI Gateway
    admin). Enforced on the server.
  - Not: policies, rules, users' roles, anything else.
- Not built: **Approver**. Dropped by the founder.
- Not built: custom roles and SCIM role mapping; only if a customer asks.

### Renamed

- Locked: "AI admin" is shown as **AI Gateway admin** and "AI viewer" as **AI
  Gateway viewer**. The stored values `ai-admin` and `ai-view` do not change, so
  there is no migration and no API change for them.

### Rules for every new role

- Locked: no new role holds `member:invite`, `member:manage`, `org:update`,
  `org:delete`, `license:manage` or `machine:manage`. Only Owner and Admin
  assign roles, and the existing rule that only an Owner can grant or remove
  Owner is unchanged.
- Locked: role checks by name become permission checks. Every place that
  compares a role to "owner" or "admin" to decide access is converted to a
  permission, so a new role is neither locked out by accident nor let in by
  accident. Comparisons that protect the Owner role itself stay by name.
- Locked: agent-only rules no longer need the generic rule permission.
  Creating or deleting a rule whose source is an agent or an agent group needs
  `agent:grant_access`; any other rule still needs `policy_rule:manage`.
- Locked: the console never shows a control the person cannot use. Every page
  a new role can open hides or disables each mutation it cannot perform, with
  one sentence on who can.

### Storage

- Locked: one migration widens the role CHECK constraints on memberships and
  invitations to the four new values. Its down migration refuses while any row
  uses one of them.

## Validation

- Tests first.
- The route walk is extended so that, for each new role, every state-changing
  route outside that role's grants answers 403, in both editions.
- Separate tests: Helpdesk cannot reset MFA for, or act on devices of, a person
  with an admin-grade role; AI Agents admin can create agent rules and cannot
  create a rule for a person, a user group or a device; Auditor reads the
  organization audit log and cannot change anything; renamed labels appear
  everywhere a role is shown.
- `make generate-check`, both editions, web unit suite, typecheck, build.
- Live walk on the test deployment with one person per new role.

## As built

Implemented on `story/rbac-1`. Deviations from the decisions above, and choices
the paper did not make, are listed here for the founder's disposition.

### Grants

- **Auditor** (`auditor`): `org:view`, `member:list`, `audit:view_all`,
  `audit_log_retention:view`, `policy:view`, `fqdn_resource:view`,
  `k8s_ha:view`, `k8s_scope:view`, `device:view`, `app_access:view`,
  `app_access:event_view`, `beam:audit_view`, `ai_workload:view`,
  `ai_model_access:view`, `ai_gateway:view`, `ai_provider:view`,
  `agent:view_privileged`, `sandbox:view`. Derived mechanically from every
  admin read (a test re-derives it). Left out: `server_access:replay`
  (session recordings), Vault (no read permission exists), MCP approvals
  (`agent_mcp_tool_approval:approve`), install tokens (`agent:enroll`), and
  `server_access:view`, which gates no server route and would only offer a
  terminal page the auditor cannot use. Checked against the handlers:
  `ai_provider:view` returns a key id, never key material; MCP tool activity
  carries an argument digest, never arguments. Admin reads that are gated by
  a manage permission (pending devices, device-approval mode, MFA enforcement
  state, SSO connections, agent groups and templates, site DNS forwards,
  Kubernetes inventory, install tokens) are not visible to the auditor; no
  per-read permission was invented for them.
- **AI Agents admin** (`agents-admin`): the agent and MCP permissions in the
  paper, plus `org:view`, `member:list` and **`policy:view`** (not in the
  paper). The policy template and agent access screens pick destinations from
  `/resources` and `/groups`, which are `policy:view`; without it those
  screens cannot load. Read only.
- **Network admin** (`network-admin`): as the paper, plus `policy:view` and
  `policy_rule:manage` for access rules. It does not hold `connectivity:use`
  (a member's "use" permission).
- **Helpdesk** (`helpdesk`): `org:view`, `member:list`, `device:view`,
  `device:approve`, `device:restore`, `mfa:reset`.

### New permissions (split, never widened)

The paper's roles could not be expressed with the existing permissions,
because several bundled a capability a role needs with one it must not have.
Owner and admin hold every new permission, so nothing changes for them.

- `audit:view_all` (paper): the organization audit log.
- `gateway:manage`: gateway routes (join token, rename, revoke, delete,
  address pool, cross-gateway clients, OpenVPN, the lifecycle claim remint),
  moved off `org:update`, which no new role may hold. Organization settings,
  SSO, the agent quota and the deployment-wide gateway endpoint stay
  `org:update`.
- `mfa:reset`: admin MFA reset, split from `mfa:manage`, which keeps the
  enforcement toggle (Helpdesk must not switch enforcement off).
- `device_approval:manage`: the organization's device-approval toggle, split
  from `device:approve` (Helpdesk approves devices and must not switch the
  requirement off).
- `device:view`: the organization-wide device list, previously decided by
  `member:manage`.
- `resource:manage`: resource create, edit and delete, split from
  `policy:manage` (network admin manages resources and must not switch Zero
  Trust off).
- `alerting:private_destination`: owner only; replaces the owner-name check on
  private alert destinations.

### Rules

- A rule, a cluster scope or a template assignment whose source is an agent or
  an agent group needs `agent:grant_access`; any other source needs
  `policy_rule:manage`. Template apply and remove no longer need
  `policy:manage` (their rules are always agent-group rules). Creating a
  Kubernetes cluster scope needs the rule permission for its source instead of
  `policy:manage`.
- Founder decision (2026-11-28): enabling, disabling and extending a rule
  need the same source-based permission as creating it (`policy_rule:manage`,
  or `agent:grant_access` for an agent or agent-group source), so a network
  admin and an AI Agents admin manage the whole life of the rules they may
  create. Machine and agent principals still need `policy:manage` for these
  verbs, which they never hold, so the GitOps operator stays as RBAC-0 D4 left
  it. Zero Trust mode, user groups and directory sync stay `policy:manage`.

### Helpdesk ceiling

- Enforced in the MFA reset transaction and before device approve, reject,
  restore and transfer, from the target's full role set. Restore and transfer
  act on a whole gateway, so they are refused outright when any device on that
  gateway belongs to an admin-grade person, rather than skipping those
  devices. The device checks run just before the action, not inside its
  transaction.
- Helpdesk's restore is reachable through the API only: the gateway pages are
  `gateway:manage`/`site:manage` and are not offered to Helpdesk.

### Role checks converted

Server: org-wide audit log (`audit:view_all`); private alert destinations;
agent access requester authority (read from the role set, schema-agnostic);
SSO connection test; every `RoleIn` + `rbac.Can` on the primary role (device
list, device for another person, device mode, device lifecycle target, OpenVPN
for another person, agent owners, agent profile permissions, agent access
request authority) now reads the whole role set. Kept by name: last-owner
guard, owner-grants-owner, owner MFA reset, and the SQL "member, admin or
owner" standing checks for Beam and sandboxes (no new role holds a Beam or
sandbox create permission). No new view-gated mutation was found: the auditor
route walk reaches only the RBAC-0 D5 self-service set.

Console: labels and one-sentence descriptions for every role; "AI Gateway
admin" and "AI Gateway viewer" for `ai-admin` and `ai-view`. Role-name gating
replaced with `can()` in the IPsec workspace, licence card, device approvals
and posture, alerts, resources, people and agent groups, the audit log and the
organization-deletion copy. `useOrgAdmins` still lists owners and admins by
name: it is the "who to ask" contact list, not an access decision.

### Founder decisions (2026-11-28)

- Kept as built: AI Agents admin holds `policy:view`; network admin holds
  `k8s_api:manage`; Helpdesk restore is reachable through the API only; the
  gateway-level Helpdesk ceiling refuses the whole operation, and the device
  ceiling checks run before the action rather than inside its transaction.
- Rule lifecycle: see Rules above.
- The Auditor reads the admin lists. Each read gets the read half of its
  manage permission, held by owner, admin, auditor and the role that manages
  the area; none returns a secret:
  - `device:view`: pending devices, device-approval mode.
  - `agent_template:view` (also AI Agents admin): agent groups and members,
    MCP profiles and assignments, an agent group's MCP tool policy, policy
    templates, versions and assignments.
  - `alerting:view`: alert delivery setting, destinations (host and keyed
    fingerprint only), subscriptions, deliveries (stable error codes only),
    occurrences.
  - `mfa:view`: organization MFA enforcement.
  - `device_health:view` (also network admin): posture checks.
  - `site:view` (also network admin): pending site ranges, site DNS forwards,
    site deletion references.
  - `k8s:view` (also network admin and the GitOps operator, which held the
    read through `k8s:manage`): Kubernetes cluster inventory.
  - `invitation:view`: invitations (no tokens are listed).
  - `app_access:view` (existing): App Access grants and application sessions.
  - Already readable before: SSO connections and SSO config (`org:view`, no
    client secret is served).
  - Still closed, by design: install tokens and their status (`agent:enroll`),
    MCP approval requests (arguments; `agent_mcp_tool_approval:approve`),
    Server Access recordings and storage settings, Vault, the agent JIT
    setting toggle state, MCP connection previews and the write-flow impact
    previews (template destination impact, App Access revoke and publication
    impact, FQDN setting impact), the Kubernetes lifecycle claim and install
    reads, and the agent runtime release.
  - Console: device approvals, posture, alerts, MCP, agent groups, policy
    templates, invitations, gateways, sites, App Access grants and sessions,
    and the sign-in and MFA settings open read-only for the Auditor, each
    with one sentence on who can change it. The pending-range queue on Sites
    and the Kubernetes inventory picker stay in their editing flows; pending
    ranges are listed in the ranges table.

### Not done

- The live walk with one person per role on the test deployment.

## Live walk (test deployment, 2026-11-28)

One user per new role was invited, accepted the invitation and signed in on the
test deployment running this branch (schema 256). Checked through the API as
each user:

- Auditor: read the organization audit log (entries from six people), rules,
  agent groups, alert destinations, invitations and MCP servers; was refused
  creating a rule or a resource, turning Zero Trust off, inviting, and turning
  MCP off.
- AI Agents admin: created, disabled and deleted a rule for an agent, created
  and archived an agent group; was refused a rule with a CIDR source, a
  resource, Zero Trust and invitations.
- Network admin: created a resource and a rule with a CIDR source, disabled and
  deleted the rule, deleted the resource; was refused an agent rule, Zero
  Trust, user groups and invitations.
- Helpdesk: listed members and reset a plain member's two-factor
  authentication after entering its own password; was refused resetting the
  owner's and the auditor's, creating a rule, inviting and Zero Trust. A plain
  member was refused the same reset.

Not walked: the console pages as each role (covered by unit tests).
