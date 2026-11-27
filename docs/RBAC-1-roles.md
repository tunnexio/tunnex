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

- Locked: **Read-only admin** (`read-only-admin`). Sees what an admin sees and
  changes nothing.
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
    role (Owner, Admin, Network admin, AI Agents admin, Read-only admin, AI
    Gateway admin). Enforced on the server.
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
  create a rule for a person, a user group or a device; Read-only admin reads
  the organization audit log and cannot change anything; renamed labels appear
  everywhere a role is shown.
- `make generate-check`, both editions, web unit suite, typecheck, build.
- Live walk on the test deployment with one person per new role.
