# S18 — AI Agents console workspace decisions

**Status:** founder-approved implementation paper. No commit or push is authorized
without a further explicit approval.

**Proposed branch:** `story/S18-ai-agents-console-workspace`  
**Base at proposal:** `main` / `fe7ccf5`  
**Companion discovery:** `docs/ux-console/10-ai-agents-api-contract.md`

## 1. Purpose and boundary

S18 is the first console-UX reference vertical slice. It turns the existing
AI Agents route into an operational index and a route-owned detail workspace.
It proves the shared console grammar on one real domain; it does not redesign
the whole console in parallel.

The visual direction is Tunnex's existing dark/crimson security identity.
LiteLLM is a reference only for operational hierarchy, compact information
density, clear detail workspaces, contextual guidance, and staged setup.

## 2. Locked slice decisions

### D1 — AI Agents is a first-class owner

AI Agents owns agent lifecycle, runtime, MCP profiles and assignment, JIT
access context, groups/templates, and agent activity. Access Policies retains
policy provenance and links to the owning agent workspace; it must not retain a
second editor for the same agent capability.

### D1a — one binary, licence-tier entitlement

Tunnex ships one binary. Community is the absence of a licence key; valid keys
report Trial, Starter, Growth, or Scale. Product entitlement decisions read
`GET /api/v1/license` (`state`, `tier`, named `features`, and API-provided
ceilings), never a build tag or `meta.edition`. Base AI Agents—inventory,
detail, bootstrap, enrolment, profile/runtime and credential management—are
available on Community and every higher tier when RBAC permits. `agent_jit_access`
is the distinct named capability currently granted only by Scale; a capability
grant never enables its organization opt-in automatically. Permission is always
resolved before entitlement so a caller cannot learn a plan through a refusal.

Product-facing copy uses plan/capability language, not Open/Enterprise wording.
The Community live baseline must be proven before the founder installs the
Scale key through Settings → Licence & Plan. Plaintext keys are never printed,
logged, committed, seeded, screenshotted, or handled outside that intended
product store.

Gateway enrollment ceilings are deployment-wide and API-owned: Community `1`,
Trial `2`, Starter `5`, Growth `20`, and Scale unlimited. `GET /api/v1/license`
returns `gateway_ceiling` and `gateways_in_use`; `null` ceiling means unlimited.
The ceiling applies only when enrolling a new gateway—expiry, lapse, downgrade,
or a reached ceiling never stops or deletes a running gateway. React reads these
returned values and never hardcodes the tier matrix. At a refusal, the product
states the current plan, in-use count, effective ceiling, and the recovery path
through Settings → Licence & Plan.

### D2 — the index is an operator index, not a card feed

`/agents` has a breadcrumb, title/count only when the server supplies one,
short explainer, one primary **Add agent** action, URL-backed toolbar, compact
table, and explicit state blocks. It answers: which agents exist; whether they
are usable now; who/what owns them; what needs operator attention; and where to
act next.

The list URL uses D-UX-01's keyset contract: `q`, allowlisted domain filters,
`sort`, `dir`, bounded `limit`, and opaque `cursor`. Back/Forward restores the
whole URL state. It never synthesizes numbered pages or an exact total from a
loaded batch.

### D3 — each agent has a stable detail workspace

The canonical detail route is
`/agents/:agentId?tab=overview|runtime|mcp|access|activity`. The list is for
scanning; configuration and evidence are in the detail workspace. Returning to
the index preserves its current query URL.

| Tab | Current read(s) | Scope in S18 |
| --- | --- | --- |
| Overview | `getAgentProfile` | Profile metadata, lifecycle, ownership/managing-group assignment, connection facts, and revoke-then-remove recovery. |
| Runtime | `getAgentRuntimeStatus`, `getAgentCredentialRotation` | Runtime state and the authoritative credential-rotation action/status subject to existing permissions. |
| MCP | `getAgentMCPInventory`, `getAgentMCPToolPolicy`, `listAgentMCPToolApprovalRequests`, `listAgentMCPOAuthConnections`, `listAgentMCPProfiles` | Inventory, OAuth creation, tool policy, step-up approval actions, and group-derived profile provenance. |
| Access | Existing agent JIT settings, destinations, request list/detail reads | Agent-specific JIT posture and links/actions; no duplicated Access Policy editor. |
| Activity | `listAgentWorkflowProvenance` | Workflow provenance; link out to cross-domain access/audit evidence rather than copying it. |

### D4 — Add Agent is staged token issuance, not claimed enrolment

The browser may call authenticated `issueAgentBootstrapToken` (`POST
/organizations/{orgId}/agents/bootstrap-token`) to issue an operator-visible
one-time bootstrap token. The current `201` response returns the shown-once
token and release metadata, **not an expiry**; the UI must not invent one. The
flow is identity/gateway → review → shown-once command. It validates identity
and gateway only when the operator continues, never calls the token endpoint
before the review step, and clears its in-memory command on close. It may say
**waiting for enrollment**, but never claims enrolled, connected, or ready.
The browser never calls `POST /api/v1/agent/bootstrap`: that is an
unauthenticated machine protocol redemption route, not an operator UI action.
The flow must not infer enrollment from a gateway name or token issuance.

Gateway-enrolment correlation remains outside S18 under D-UX-03.

#### Agent mutation reachability census

This is the S18 browser evidence, matched by operation rather than path text.
It deliberately distinguishes the one supported operator action from machine
protocol and legacy/unmounted callers; it does not make an API capability look
reachable merely because a retired component still imports a generated client.

| Operation | Current disposition | Rendered caller / safety |
| --- | --- | --- |
| `issueAgentBootstrapToken` | Browser reachable | `AgentsIndex.tsx` → `AddAgentFlow.tsx`; `agent:enroll` is resolved before `?add=1` opens. POST occurs only after identity/gateway review; the `201` token is shown once as a command and is cleared on dismiss. |
| `bootstrapAgent`, `pollAgentRuntime`, `reportAgentRuntime`, `reportAgentWorkflowProvenance` | Intentionally machine protocol-only | No browser caller. Runtime credentials and bootstrap redemption must never be rendered in the operator console. |
| `updateAgentProfile`, `requestAgentCredentialRotation`, MCP tool-policy/OAuth/approval mutations | Browser reachable | The active Agent detail Overview, Runtime, and MCP tabs own these operations under their exact existing permissions. The legacy `pages/Agents.tsx` is removed after its callers migrate; an unmounted source is never reachability evidence. |
| JIT request/approval/reject/cancel/revoke | Access-domain caller only | Deliberately outside Add Agent. Feature and organization opt-in checks stay server-authoritative and precede no browser mutation without the normal Access surface. |

**Absence answer.** Active detail tabs expose every browser-authorized Agent
management mutation, while Add Agent owns only issuance. Bootstrap redemption,
runtime reporting, and enrollment polling remain machine/protocol-only or
explicitly deferred; none is simulated in the browser.

### D5 — MCP profile lifecycle is not silently left unreachable

D-UX-02 assigns reusable MCP profiles to AI Agents. The existing
`createAgentMCPProfile` and `assignAgentMCPProfile` operations require an
explicit S18 implementation disposition before code begins:

1. include profile inventory plus group-targeted creation/assignment in an
   Agents-owned Profiles/Groups workspace, with the individual MCP tab showing
   group-derived provenance and a contextual link; or
2. defer all three together to a named immediate follow-up story, leaving an
honest unavailable state and no false management claim.

**Founder disposition: option 1 is selected.** S18 owns an Agents MCP
management workspace. Profiles are attached to agent groups—not individual
agents—and the agent detail tab shows the inherited effective profile and its
source group. Profile-management links point to `/agents/mcp`; Agent Group
lifecycle links point to `/access/groups?type=agents`.

The group-owned lifecycle contract supplies assignment inventory, preview,
atomic replace, idempotent unassign, and soft archive. Profiles stay immutable:
an endpoint change creates a new profile and atomically replaces a group
assignment rather than performing an in-place update.

#### S18 MCP mutation and effect evidence

| UI operation | OpenAPI / handler | RBAC and opt-in | Database effect / response / audit | Operator warning and recovery |
| --- | --- | --- | --- | --- |
| Enable MCP management | `setOrganizationAgentPolicyTemplatesEnabled` / `SetOrganizationAgentPolicyTemplatesEnabled` | `agent_template:manage`, then service availability; no plan gate | Updates `organizations.agent_policy_templates_enabled`; `200` setting; audit `org.agent_policy_templates_enabled`. | Explains that it enables management, not a profile assignment. Disable is the normal recovery when no blocking policy-template state exists. |
| Create / archive profile | `createAgentMCPProfile`, `archiveAgentMCPProfile` | `agent_template:manage`, then organization opt-in | Inserts or soft-archives `agent_mcp_profiles`; transactional lifecycle audit. Archive refuses active references with exact group/agent impact. | Creation affects no agent until group assignment; recovery after archive is creating a replacement profile. |
| Agent Group lifecycle | Typed Group operations | Group permission, then organization opt-in | Canonical Access Groups workspace owns group/member rows and audit. | `/agents/mcp` is read-only for group lifecycle and deep-links to `/access/groups?type=agents`. |
| Preview / assign / replace / unassign profile | Group-owned MCP lifecycle operations; deprecated profile-scoped POST delegates to the same service | `agent_template:manage`, then organization opt-in | Atomic active/history change, same-transaction audit, and post-commit desired-runtime queue only when effective configuration changes. | Server preview supplies exact affected agents; replacement/unassign confirmation gives recovery and never claims runtime applied. |

The management workspace reads profiles, assignment history, and Agent Groups;
it supports profile lifecycle and group-owned assignment through the
server-owned impact contract while leaving Group lifecycle canonical in Access.

**Capability absence answer.** Profile assignment is group-owned and active in
the Agents MCP workspace. Agent Group create/rename/archive/member lifecycle is
active only in canonical Access Groups. Direct per-agent profile assignment and
mutable profile updates remain prohibited product models, not missing UI.

**Destructive-effect answer.** Archive, member removal, replacement, and
unassignment are server-impact-driven. The active UI shows the group/agent
impact and recovery before mutation, then refetches the authoritative lifecycle
and audit result; no browser-side count or runtime-applied claim is invented.

### D6 — use existing primitives, prove reuse before extracting

Extend `AppShell`, `PageHeader`, `DataTable`, `SettingsRail`, and Visual Gallery
where the real Agent screens require it. Do not introduce an
`EntityIndex`/`EntityDetail` mega-component. A new abstraction requires two
implemented screens with the same proven shape.

## 3. Required API and product changes

| Change | Why it is needed | S18 disposition |
| --- | --- | --- |
| Keyset Agents index API | Current `listAgents` is a bare array and has no query/page envelope. | Required API/OpenAPI change before an honest URL-backed index can ship. Preserve the path only with a compatible migration plan, or add a versioned/list-specific operation. |
| Index response freshness and field support | Status needs source/freshness; requested sorts need server facts. | Return source timestamps needed for rendered status. Offer only server-supported allowlisted sorts. `total` is optional and absent unless server-calculated. |
| Detail routing and tab state | Current view is one large `Agents.tsx` surface. | Browser routing/state work; existing detail reads remain the source of truth. |
| Add Agent token issuance | Existing `issueAgentBootstrapToken` browser caller exists at `Agents.tsx:821`; it must be reshaped into the staged flow. | Expose only issuance; redemption remains protocol-only; refetch index only after protocol enrolment is observable. |
| MCP profile lifecycle | Existing profile create/assignment operations have no browser caller; assignment targets an agent group, not an individual agent. | Founder chooses include/defer per D5; direct per-agent assignment needs a new API/product contract. |

No S18 change may weaken existing RBAC, licence-feature enforcement, audit
writes, or server-side refusal semantics. UI hidden/disabled/restricted states
distinguish missing permission from a plan/capability restriction.

## 4. Explicit non-goals

- Gateway enrolment record/token correlation, retention, cancellation, or
  polling protocol (D-UX-03).
- Device mode control (D-UX-04).
- Control-plane administrator governance (D-UX-05).
- A Devices, Gateways, Access, Settings, or Observability redesign.
- A second JIT/access or MCP profile editor under Access Policies.
- Numbered pagination, inferred totals, fabricated impact counts, or browser
  emulation of server-side safety decisions.
- A generic entity framework, light/blue LiteLLM styling, or claims that an
  agent boundary detects prompt injection or controls individual MCP tools when
  the enforcement plane cannot make that claim.

## 5. Security, permissions, and destructive behaviour

The screen renders only actions authorized by the API and makes refusal causes
visible. Existing handler permissions and named feature gates remain authoritative;
the UI must preserve an actionable distinction among loading, no data, stale or
partial data, pending, permission denied, and plan/capability restriction.

Any lifecycle/revoke/disable action included in S18 must state before execution:
the exact target, access/runtime consequence, server-provided affected-resource
facts only, recovery route (or no recovery), and audit evidence. It refetches
the authoritative profile/index/activity evidence after success; it does not
invent a client-side cascade preview.

## 6. Required rapid visual-review states

Before story completion, review in the browser with fixture owner/admin and a
restricted persona:

- populated, fresh, empty, loading, failure, partial/stale, and
  permission-denied index states;
- query/filter/sort/cursor navigation and Back/Forward restoration;
- healthy, degraded, offline, pending, revoked/suspended agent rows with source
  and freshness facts;
- every Overview, Runtime, MCP, Access, and Activity tab, including no-data and
  denied states where meaningful;
- Add Agent issuance, copy/expiry guidance, pending enrolment, server refusal,
  and safe post-close return;
- MCP-profile decision outcome, JIT contextual links, mutation confirmation,
  post-action refresh, and audit evidence;
- narrow-screen, keyboard, focus, hover, disabled, and notification behaviour.

During rapid visual iteration, continuously inspect browser console, network
requests/responses, API failures, permissions, and rendered state truth. Unit
tests and CI may be deferred only during that iteration; typecheck, build,
required local gates, and exact-head CI remain mandatory before completion or
merge.

## 7. Approval gates and remaining decisions

S18 may start only after the founder approves the proposed identifier/branch
and this paper, selects the D5 MCP-profile scope, and approves the required
Agents index API migration shape. The runtime/MCP read gates must remain
operation-specific (not a blanket plan label), and activity remains an
unpaged array until a later API contract changes it. Those are implementation
decisions, not missing investigation.

The isolated non-production fixture procedure in
`docs/ux-console/07-azure-fixture-and-live-review-plan.md` must be followed;
production credentials and production data are forbidden.

## 8. Founder dispositions recorded during implementation

- Community is the canonical no-key product plan. The product has one binary;
  `meta.edition`, build tags, and Open/Enterprise labels are not entitlement
  inputs for S18.
- Agent MCP profiles are assigned to Agent Groups, never directly to an
  individual agent. The agent MCP tab shows effective profile and source group.
  MCP profiles and profile-assignment context remain Agents-owned, while the
  single canonical typed Group lifecycle workspace is Access-owned.
- JIT is available only when `GET /api/v1/license` includes
  `agent_jit_access`, then remains unavailable until the organization opt-in is
  explicitly enabled. Service wiring failure is `503 agent_access_unavailable`,
  distinct from `403 feature_required`.
- Core Zero Trust Access Rules, Groups, Resources, Test Access, and the
  existing default-deny/enforcement controls are Community capabilities when
  normal RBAC permits. The policy port is wired in the single binary; a missing
  policy service is `503 policy_service_unavailable`, never `edition_required`.
  The retained `meta.edition` compatibility field is not consumed by Access or
  any new entitlement decision; no concrete published external caller has been
  identified in this S18 audit, so its removal remains owned by S18.1 rather
  than silently changing a public response in this feature slice.
- Repository-wide migration of remaining non-Agent `meta.edition`,
  `isEnterprise`, old error codes, build-target names, and historical/legal
  terminology is a feature-sized follow-up: **One-Binary Licence-Tier
  Entitlement Migration**. It is not silently absorbed into S18.

### D7 — approved follow-ups and terminology boundary

- **S18.1 — One-Binary Licence-Tier Migration** is a prerequisite to S19
  product implementation. It migrates remaining product/build terminology and
  `meta.edition`/`isEnterprise` seams; Community remains the canonical no-key
  plan.
- **S18.2 — Agent Query Scalability** owns database keyset execution, dynamic
  filter batching, and effective-MCP lookup batching. It is deliberately not
  folded into this UX slice.
- Enrollment-status polling is deferred to S19 as the shared opaque
  Agent/Gateway enrollment-status contract. Until then S18 may say **bootstrap
  token issued** or **waiting for enrollment** only; it must not claim an agent
  is enrolled, connected, or ready from issuance alone.
- Preserve legally accurate uses of “open source”, Apache-2.0, and proprietary
  boundary language. Remove only obsolete product-plan/build-edition wording.

### D8 — MCP assignment lifecycle (founder-approved)

An agent group has at most one **active** MCP profile assignment; one immutable
profile may be active for many groups. Agents inherit only their managing
group's active profile and must fail closed if legacy history would otherwise
yield more than one effective profile. Runtime configuration derives only from
active assignments.

Profiles are immutable: endpoint changes require a new profile and an atomic
group-owned replacement. Assignment history is retained with `active`,
`replaced`, `unassigned`, and `quarantined` lifecycle states. Existing multiple
legacy assignments are all quarantined—never arbitrarily selected—and their
group remains visibly unresolved until an operator selects one profile.

The migration adds profile archival and a partial one-active-assignment-per-
group invariant. Archived profiles remain historical evidence but cannot be
selected. Its down migration refuses if post-migration lifecycle/history data
would be lost. A system-actor audit is written for every quarantined legacy
group with cause `legacy_mcp_assignment_ambiguity`.

The public API is group-owned and OpenAPI-first:

- assignment inventory returns active and historical profile/group provenance,
  lifecycle, timestamps, and quarantine reason;
- server-owned preview returns current/proposed state, bounded affected agents,
  desired-runtime updates, conflicts, and ambiguity;
- atomic set/replace ends the old active row, creates the new active row,
  audits in the same transaction, and queues normal runtime reconciliation only
  after commit;
- unassign preserves history, audits, queues reconciliation, and returns impact;
- archive-profile is soft, refuses active references with exact group/agent
  counts, and retains historical references;
- membership add/remove and group archive include MCP inheritance/assignment
  impact and trigger the same desired-runtime path when effective configuration
  changes.

Required audit actions are `agent_mcp_profile.created`, `.assigned`,
`.replaced`, `.unassigned`, `.archived`, and
`.ambiguity_quarantined`. Group membership audit metadata names MCP inheritance
gained/lost; group archive refusal/success exposes MCP impact. An audit write
failure rolls back its mutation.

The old profile-scoped assignment POST has no concrete published caller in the
repository census. It remains a deprecated compatibility wrapper over the
group-owned atomic operation and must not remain capable of producing multiple
active assignments. No
`meta.edition`/`isEnterprise` decision is permitted; handler authorization is
permission first, then organization opt-in, with Community base Agent reads and
Scale JIT unchanged. MCP endpoints remain credential-free absolute URLs.

Rejected alternatives: direct agent assignment; mutable profile endpoints;
selecting a legacy winner; browser-calculated assignment safety; and applying a
runtime change merely because a mutation was accepted.

### D9 — superseded Agents management route ownership

This earlier visual-review fold put Agent Groups in the Agents rail. It is
superseded by D10: Groups have one canonical Access-owned workspace. The
permanent AI Agents rail is `Agents`, `Policy templates`, and `MCP profiles`.

| Mutation family | Active rendered caller | Impact/recovery surfaced |
| --- | --- | --- |
| create, rename, archive group | `/access/groups` | Archive states member/template blockers and does not promise a cascade. |
| add/remove group member | `/access/groups` | Typed member dialogs explain inherited configuration; removal reports withdrawal only for that member. |
| create, rename, archive template | `/agents/policies` | Archive explains that existing assignments remain until explicitly removed. |
| create immutable version, preview, apply/remove assignment | `/agents/policies` | Server preview precedes apply; confirmation names agent/rule/gateway impact and removal preserves shared rules. |
| create, archive MCP profile; preview, assign/replace, unassign group profile | `/agents/mcp` | Group lifecycle stays read-only and links to `/access/groups?type=agents`; server impact preview names affected agents and desired-runtime queueing, confirmations state recovery, and runtime application is never inferred from queueing. |

`Access.tsx` owns no Agent template authoring implementation. It retains only
generated rule evidence; a template-managed rule links to the owning Agents
policy workspace. The canonical Access Groups workspace owns group lifecycle
through type-specific adapters. The route tests cover permission denial,
organization reset, the separate rendered callers, and all pre-existing F09
mutation families.

### D10 — canonical Groups ownership (founder amendment)

Human/user groups and managed-agent groups remain distinct backend entity types.
Directory-synced groups also remain server-owned directory projections. Tunnex
has **one canonical Groups experience** at `/access/groups`, which aggregates
these types through adapters without merging tables or membership semantics.
People members can never be added to Agent Groups, and agents can never be
added to People Groups. A universal-principal-group schema migration is
explicitly deferred and is not part of S18.

`/agents/groups` is compatibility-only and redirects to
`/access/groups?type=agents`. The Agents rail is `Agents`, `Policy templates`,
and `MCP profiles`; policy-template and MCP pages select Agent Groups read-only
and deep-link to the canonical workspace. Rules, Groups, and Resources are the
Access rail. No route may render a second group-management implementation.

### D11 — bounded exact group member counts (founder-approved)

The existing People/Directory and Agent Group list contracts carry an exact,
non-negative `member_count`. A returned empty group is therefore `0`; an API or
count failure remains an error and is never rendered as either `0` or an
unknown-looking success state. The count follows the same active/current
membership semantics as each existing list-members operation, remains strictly
organization scoped, and excludes removed, archived, historical, and
quarantined membership rows.

Counts are computed in each existing typed list implementation with a bounded
grouped aggregate or CTE, not one member-list request/query per table row. This
does not create a universal Group entity or a combined endpoint. `/access/groups`
is the only management UI; it uses the two typed list responses and renders
their exact counts. Columns with no bounded, server-authoritative policy or MCP
fact are omitted rather than filled with repeated “Not available”.

### D12 — Community Access Rules reachability and no-oracle ordering

Access Rules are a core Community capability in the one-binary product. The
client must not read `meta.edition`, `isEnterprise`, or a build tag to decide
whether to render Rules. The normal order for every protected operation is
authentication, organization membership, RBAC permission, named feature (only
when that operation has one), organization opt-in, then handler/service work.
The Access JIT panel alone uses the named `agent_jit_access` capability; it is
shown only after its RBAC check and remains separately subject to the
organization opt-in. A missing policy service is an operational `503
policy_service_unavailable`, not a plan refusal.

| Mutation family | Active rendered caller | Destructive/operator consequence and recovery |
| --- | --- | --- |
| Create, edit, enable, disable, delete Rule | `/access` `RulesSection` and `RuleFormModal` | Disable stops enforcement without deleting the rule; delete confirmation describes removal and recovery is recreating the rule from its visible rule fields. |
| Change Zero Trust/default-deny mode | `/access` `ModeSection` | Confirmation communicates the enforcement-mode change; restore the previous mode through the same control. |
| Device approval setting; approve/reject device | `/devices/approvals` `DeviceApprovalSection` | Approval decisions use the existing device lifecycle controls and explain the immediate access consequence; recovery follows the existing approve/re-enrol workflow. |
| Create/remove posture check | `/devices/posture` `PostureChecksSection` | Removing a check withdraws that evaluation requirement; recovery is recreating the same check through the visible form. |
| Create, rename, archive typed group; add/remove member | `/access/groups` `AccessGroups` adapters | People uses `user_id`, Agent uses `device_id`, Directory is read-only. Archive/member removal dialogs identify the typed impact and offer the corresponding recreate/re-add path. |
| Create, edit, delete resource | `/access/resources` `AccessResources` | The delete confirmation identifies that dependent policy references may be refused by the server; recovery is recreating the resource and reviewing affected rules. |
| Request, approve, reject, cancel, revoke JIT | `/access` `AgentJITCapabilitySection` → `AgentJITAccessSection` | Only reached after RBAC, named feature, and opt-in checks. State changes identify grant/request impact and recovery is a new request when policy permits. |

`Test Access` is a read/evaluation surface, not a mutation. This census keeps
Rules, Groups, and Resources as separately reachable Access routes and prevents
the legacy embedded Groups/Resources implementation from becoming a second
caller.

### D13 — founder disposition: Resources and Device lifecycle ownership

Resources own destination CIDR, protocol, optional label, and port scope. Rules
select a Resource and therefore inherit its destination scope; ordinary Rule
authoring must not duplicate ports. The Resource request contract accepts `any`,
`tcp`, or `udp`; `any` has no bounds, while TCP/UDP can have all ports, a single
port, or an inclusive range validated from `1` through `65535`.

The Access Rules route owns Test Access, Zero Trust/default-deny mode, and the
authoritative scalable Rules table. Visualization is optional, must use the
operator's loaded scope, and must never draw an arbitrary partial subset.

Device lifecycle owns approval and posture: `/devices/approvals` owns approval
mode and the pending queue; `/devices/posture` owns disk-encryption and minimum
OS posture configuration. Both are Community core with normal RBAC and their
existing explicit organization default-off controls. JIT remains the separate
Scale named feature and opt-in. Device approval/posture service absence is an
operational unavailable response, never `edition_required`; active product UI
and handlers do not use Open/Enterprise build semantics for these controls.

### D14 — historical entitlement-gate reconciliation

The former 43-handler edition census is retained as a named ledger in
`edition_gate_order_test.go`; the test rejects duplicates, omissions, invalid
classifications, and a mismatch with the current scanned inventory. The
one-binary reconciliation is **14 legacy named-plan handlers + 11 named-feature
handlers + 18 Community-core handlers = 43**.

| Classification | Historical handlers |
| --- | --- |
| Retained named-plan | `PutIdpSyncConfig`, `GetIdpSyncHealth`, `TriggerIdpSync`, `MapIdpGroup`, `UnmapIdpGroup`, `GetMfaEnforce`, `SetMfaEnforce`, `AdminResetMfa`, `SetSsoConfig`, `GetSsoConfig`, `ListAccessEvents`, `GetAccessLogHealth` |
| Pre-session exception | `StartSsoLogin`, `SsoCallback` — no authenticated principal exists; both remain explicit exceptions in the ordering guard. |
| Reclassified named-feature | `ListAgents` (only its JIT filter), `ListAgentAccessDestinations`, `GetOrganizationAgentJITAccessSetting`, `SetOrganizationAgentJITAccessEnabled`, `CreateAgentAccessRequest`, `ListAgentAccessRequests`, `GetAgentAccessRequest`, `ApproveAgentAccessRequest`, `RejectAgentAccessRequest`, `CancelAgentAccessRequest`, `RevokeAgentAccessRequest` — all use `agent_jit_access`, never an edition/build gate. |
| Community-core | `ListPolicyRules`, `CreatePolicyRule`, `SetPolicyRuleEnabled`, `DeletePolicyRule`, `ExtendGrant`, `ListGroups`, `CreateGroup`, `UpdateGroup`, `DeleteGroup`, `ListGroupMembers`, `AddGroupMember`, `RemoveGroupMember`, `ListResources`, `CreateResource`, `UpdateResource`, `DeleteResource`, `GetZeroTrustMode`, `SetZeroTrustMode` |

There are no historical entries in this census classified as
`operational-unavailable`: that response is reserved for a real missing service
after authorization, never a substitute for a plan decision.

### D15 — founder amendment: one mutation home for access and security

This supersedes the Device Approval and JIT toggle placement in D12/D13 without
changing their API contracts. Org Settings gains **Access & security** as the
only organization-wide settings mutation home. `Require device approval` and
the licensed Agent JIT organization opt-in mutate only there. The Devices
Approvals workspace remains operational: it reads the current mode, links to
Settings for mode changes, and owns pending-device approve/reject actions.

`/access` owns only operational JIT request lifecycle actions. When
`agent_jit_access` is absent it renders no upsell ahead of core Rules; when the
feature is licensed but the organization opt-in is off it renders a compact
link to Settings. Ordering remains RBAC, named feature, then organization
opt-in. Zero Trust remains mutable only in Access because its confirmation is
derived from current rule/device impact; Settings is read-only with a management
link. Posture remains mutable only at `/devices/posture`, with an optional
read-only Settings status/link.

Resources hide all create/edit/delete affordances for a caller lacking resource
management permission while retaining an explicit permission-denied state.

Settings section selection is URL-backed (`/settings?section=<id>`): direct
links, browser Back/Forward, and rail selection resolve to the same permitted
section. The Access & security read-only Zero Trust row reads the authoritative
mode and distinguishes loading or read failure from `Off`; its mutation remains
solely in Access Policies.

### D16 — active Agent management and destructive-operation closure

S18 preserves every previously reachable browser Agent capability. The active
detail workspace is the sole owner: **Overview** owns profile metadata,
ownership/managing-group assignment, lifecycle, and revoke-then-remove;
**Runtime** owns authoritative credential rotation; and **MCP** owns observed
inventory, OAuth connections, tool policy, and step-up approvals. The active
index owns staged bootstrap-token issuance only. JIT request lifecycle remains
Access-owned.

Organization-wide Agent quota and runtime-synchronization opt-in belong only to
`/settings?section=ai-agents`. That section is URL-backed, restores with
Back/Forward, clears organization-scoped state on organization switch, and
distinguishes loading/failure from off/unlimited server values. Group lifecycle
remains canonical at `/access/groups?type=agents`; MCP profile management and
assignment remain at `/agents/mcp`.

The deprecated profile-scoped assignment POST is compatibility-only and must
delegate to the group-owned atomic lifecycle service; it may not write legacy
assignment SQL directly. Repeating unassign is a `200` no-op with no audit,
history, or runtime queue. Profile archive refusal returns server-authoritative
active-group and distinct affected-agent counts. Successful lifecycle changes
write audit in the mutation transaction and queue desired runtime only after
commit; queued means desired state, never runtime applied.

Both Device Approve and Reject require confirmation of the exact selected
device(s), served ownership facts, consequence, and recovery. Approval makes a
device active under the current policy and recovery is Device revoke. Rejection
refuses pending enrollment and recovery requires a fresh enrollment. Partial
bulk results are reported per target before authoritative reload.

The legacy unmounted Agents implementation is removed only after the
mutation-to-rendered-caller census proves each browser mutation has exactly one
active owner. Machine-only bootstrap redemption/runtime reporting and the S19
opaque enrollment-status contract remain non-browser/deferred by D7.

**Legacy Agent reconciliation.** The removed `/agents` implementation's
`PATCH /agents/{deviceId}` metadata, ownership/group, and lifecycle mutations
are covered by `agentsruntimewiring.test.tsx` on Agent Detail Overview. Its
credential-rotation POST and refetch are covered on the Runtime tab in the
same test. Its MCP OAuth creation, tool-policy PUT, and step-up approval POST
are covered by the active MCP tab and its protected-read/retry regressions.
Its organization quota and runtime-synchronization controls are covered by
`settingswiring.test.tsx` at `?section=ai-agents`. Its bootstrap issuance is
covered by `addagentflow.test.tsx`; revoke-then-remove is covered by the active
Overview test. The removed index-local row/profile state, per-row runtime/MCP
caches, and duplicated organization settings are **obsolete UI state**, not
API contracts: the index now owns scan/query state and the Detail/Settings
workspaces own their authoritative reads. No browser mutation was retired.
