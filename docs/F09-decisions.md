# F09 — Agent groups and reusable policy templates decisions

Status: **SATISFIES — implementation, focused gates and the combined AWS DEV
walk are complete at `4e09c9378e193cd6f8b2db901d012b5533396241`**. Owner/member API,
compiler, lifecycle, released owner authoring DOM and unrelated-member DOM
absence all ran live. Opt-in and all disposable live access state were restored.

## Customer outcome

An authorized operator can collect managed agents into a reusable group, define
an immutable version of an access template, preview the exact policy impact, and
apply that version to one or more groups. The resulting access is ordinary
Tunnex policy compiled and enforced by the existing policy pipeline.

## Reuse census

- Canonical agent identity, lifecycle, owner and tunnel remain `devices` plus
  `agent_profiles` (F01/F06). F09 adds no agent identity or lifecycle state.
- Existing `user_groups` and `group_members` contain human users and are already
  both Zero Trust policy subjects and F06 managing teams. They are not agent
  groups and cannot be overloaded without changing their meaning and FK effects.
- Existing resources, sites, Kubernetes services and policy-rule destination
  resolution remain authoritative. A template references those stable IDs with
  tenant-scoped restrictive FKs; it does not snapshot CIDRs, addresses or
  compiled entries.
- `policy_rules` remains the only enforcement grant model. F09 materializes an
  applied assignment as ordinary agent-group-source policy rules and the existing
  deterministic compiler produces the wire artifact. There is no template
  evaluator in the node or agent runtime.
- F06 `policy:manage` plus `agent:grant_access` remains the grant-authoring
  boundary. F09 adds a named permission only for template/group administration;
  applying access still requires both existing grant permissions.
- F07 audit actors and F08 read-only Test Access remain the attribution and
  diagnostic seams. F09 does not invent a second audit identity or reachability
  oracle.

## Locked decisions

### D1 — Agent groups are a separate, flat organization-scoped model

Add `agent_groups` and `agent_group_members`. Membership points to a live agent
device in the same organization. A group may contain zero or more agents; an
agent may belong to multiple groups. Suspension preserves membership but makes
the agent compile to no source; revoke/remove drops its memberships. Nested
groups, selectors and label-driven automatic membership are not part of F09.

The database enforces tenant equality. Revoking or soft-removing an agent makes
it ineligible for new membership and removes it from compiler expansion; its
historical assignment/audit records remain. Group membership changes are
audited and wake policy reconciliation only when the group has live assignments.

### D2 — Templates are immutable versions, not mutable rule bags

Add `agent_policy_templates` and immutable
`agent_policy_template_versions`. Editing a template creates the next monotonic
version in one transaction; an existing version is never rewritten. Each
version contains an ordered, bounded list of destination references. L4 scope
is owned by the canonical destination exactly as it is for ordinary policy
rules: resources and Kubernetes Services supply their protocol/ports, while
groups and sites retain their existing compiler semantics. Template items do
not add a second per-rule L4 override that `policy_rules` cannot represent.
Temporary/JIT expiry belongs to F10 and is not smuggled into reusable F09
templates.

Names and descriptions are mutable template metadata. Version content is
canonical JSON only at the API boundary; normalized relational item rows own
database validation, tenant FKs and deterministic ordering. Raw compiled policy,
CIDR, protocol/port snapshots and agent addresses are never stored in a
version. Preview digests include the current destination-owned L4 inputs, so a
destination edit between preview and apply is detected as stale.

### D3 — Assignments pin an exact version

`agent_policy_template_assignments` binds one agent group to one exact template
version. Reapplying the same version with the same idempotency key is a no-op.
Applying a newer version is an explicit replacement; it does not silently move
all assignments that happen to use the template.

One live assignment per `(agent_group_id, template_id)` is allowed. The record
stores actor, timestamps and state; it never stores a secret or compiled wire
artifact. Version history remains queryable after replacement.

### D4 — Apply materializes ordinary rules atomically

Each assignment owns a deterministic set of ordinary `policy_rules`, one per
template item. Generated rows use a new `src_kind=agent_group`, the agent-group
ID, and the existing destination columns. The existing compiler adds one source
resolution branch that expands the current active members to their canonical
device addresses; the compiled wire artifact remains ordinary IP tuples. A join
table binds each generated rule to its assignment and version item.

Two assignments that resolve to the same group/destination tuple share one
canonical generated rule through multiple binding rows; it is deleted only when
the last binding is removed. `agent_group` rules have no direct/manual create
surface, so hand-authored rules are never adopted into template ownership.

Apply/replacement runs in one transaction: lock assignment/group/version,
validate current agents and destination tenant ownership, create the new rule
set, remove the superseded generated set, write audit, then commit. Recompile
and gateway wake use the existing post-mutation policy path. Failure leaves the
old assignment and rules byte-for-byte intact.

Direct edits to assignment-owned rules are refused. Operators change the
template version, membership or assignment instead. Hand-authored rules remain
unrelated and are never adopted or deleted by F09.

### D5 — Membership is dynamic compiler input, not rule churn

Adding or removing a member changes no `policy_rules`. The membership mutation
and audit commit atomically, then use the existing policy reconciliation wake.
The next snapshot expands the unchanged `agent_group` rule over the new active
membership. This preserves rule IDs/history and avoids an O(members × items)
database write fan-out.

Preview and apply use the same membership snapshot and compiler branch. A stale
preview digest refuses before mutation. There is no background half-applied
group state in F09.

### D6 — Preview is pure and uses the exact expansion/compiler seams

Preview accepts a group, exact template version and optional replacement
assignment. It performs no insert, update, delete, audit, revision wake or
runtime action. It resolves the same current agents and template destinations
through the same expansion function used by apply, overlays the proposed
ordinary rules on a read-only policy snapshot, and invokes the existing policy
compiler.

The response reports bounded server-owned facts: affected agent count, created,
reused and removed ordinary-rule counts, changed gateway/artifact count, and
per-agent added/removed enforcement tuples. It includes exact agent/rule IDs
only when the caller is authorized to view them. It never claims network
reachability; F08 remains the diagnostic surface after apply.

### D7 — Separate administration permission; applying still needs grant authority

Add `agent_template:manage` for creating/updating/deleting agent groups,
membership, templates and immutable versions. Owner/admin receive it. Member,
operator and agent roles do not.

Preview requires `policy:view`, `agent_template:manage`, and privileged view of
every affected agent. Apply/replace/remove assignment additionally requires
`policy:manage` plus `agent:grant_access`. A data-plane agent can never manage a
group/template or apply the access it receives. Permission is checked before
edition and before loading object identity, preserving no-oracle behavior.

### D8 — Enterprise unlock then explicit opt-in

F09 is Enterprise and adds `organizations.agent_policy_templates_enabled`,
default `false`. Unlocking a license never activates group/template enforcement.
An owner/admin explicitly enables it through Org Settings using the named
`agent_template:manage` permission. Disable is refused while live assignments
exist; the operator must remove assignments first, so a toggle cannot silently
withdraw or retain access.

### D9 — Destructive verbs refuse instead of silently cascading access

- Deleting a non-empty agent group is refused until memberships are removed.
- Deleting a group with any live assignment is refused first and reports the
  assignment and generated-rule counts.
- Deleting a template is allowed only before it has a version. Once versioned,
  F09 provides archive for authoring cleanup; immutable versions and audit
  history remain, and live assignments continue unchanged.
- Removing an assignment atomically deletes only its generated rules, records
  the exact impact and triggers ordinary policy reconciliation.
- Removing a member names how many assignments and compiled enforcement tuples
  will stop applying to that agent before confirmation; shared group rules stay.

No F09 endpoint hard-deletes a device, human group, resource, site or Kubernetes
service. A destination referenced by an immutable template version is protected
by `ON DELETE RESTRICT`; the existing destination-delete confirmation must name
the blocking template/version count. The operator archives/replaces the
template rather than silently corrupting its immutable history.

### D10 — Migration and rollback preserve existing policy

Migration `0097` adds the F09 tables, assignment-owned rule linkage, the
`agent_group` policy source column/check/uniqueness rules, organization opt-in
and required indexes/triggers. Existing policy rows and compiled meaning are
untouched. New tables use explicit organization columns and same-org constraints
so every query can be tenant-scoped directly.

Down succeeds only when the opt-in is off and all F09 groups, memberships,
templates, versions, assignments and generated-rule links are empty. Otherwise
it refuses before dropping anything and preserves all rows and rule IDs. An
empty down/up-again preserves every pre-F09 policy rule and compiled hash.

## API and released UI contract

- OpenAPI owns CRUD for groups/memberships, templates/versions, preview and
  assignment apply/remove. Generated Go and TypeScript bindings are the only
  request/response types.
- Access Policies gains Agent groups and Templates sections; the existing rule
  list remains the enforcement record and labels assignment-owned rows as
  managed, read-only children.
- The apply dialog always shows a fresh server preview and requires explicit
  confirmation of agent/rule/gateway counts. Preview returns a deterministic
  digest over the group membership, exact version and referenced policy inputs;
  apply takes that digest, recomputes it while holding the mutation locks, and
  rejects stale input. No preview token or server-side preview state is stored.
- Mutation success is server-refetched. No optimistic group membership,
  assignment, rule count or version is rendered.
- Organization switches synchronously clear groups, templates, previews,
  assignments, selected agents and in-flight results before the target org is
  rendered. Unauthorized members receive no F09 API facts or DOM.

## Absence audit — every mutation has a caller and visible consequence

| Mutation | Released caller | Required consequence copy |
| --- | --- | --- |
| Enable/disable templates | Org Settings F09 card | Enabling changes nothing until an assignment; disabling requires zero assignments. |
| Create/rename/archive group | Access Policies → Agent groups | Delete/archive copy includes membership, assignment and generated-rule impact. |
| Add/remove group member | Group detail | Removal copy names assignments/compiled tuples withdrawn for that agent; shared rules remain. |
| Create template/new version/archive | Access Policies → Templates | Versions are immutable; editing creates `vN+1`; archive does not remove applied access. |
| Apply/replace/remove assignment | Template assignment dialog | Fresh preview, exact affected agents/rules/gateways, then refetch. |

There is no F09 mutation without a released route caller. Preview is read-only
and cannot be reused as a hidden apply endpoint.

## Narrow implementation slices

1. **Reversible model:** migration `0097`, tenant/refusal contracts, typed
   queries, new permission and default-off organization flag.
2. **One observable vertical slice:** create one group, add active agents,
   create immutable template/version, preview, apply, and observe ordinary
   agent-group rules expanded through the existing compiler.
3. **Convergence and lifecycle:** membership add/remove, replacement,
   assignment removal, suspended/revoked handling, rollback and audit.
4. **Released UI:** groups/templates/version editor, fresh preview confirmation,
   managed-rule labels, impact copy, refetch, absence and org-switch guards.
5. **Review and one combined DEV walk:** multi-finder story-end review, exact
   local gates, then a single optimized AWS DEV walk using the F08 harness.

## Observable acceptance

- one template version applied to a two-agent group produces the exact ordinary
  agent-group rules and compiled tuples for both agents;
- preview and apply counts/tuples match, with zero write during preview;
- member add/remove converges atomically without rule-ID churn or touching
  hand-authored rules;
- replacing a version changes only assignment-owned rules and retains immutable
  history;
- a stale preview, unresolved destination, suspended/revoked agent, cross-org
  reference or unauthorized caller cannot mutate or leak tenant facts;
- assignment removal withdraws the exact compiled access; F08 Test Access then
  reports the resulting allowed/denied truth without any F09 special case;
- migration empty down/up and non-empty refusal preserve existing rules, hashes
  and all F09 rows;
- released owner/admin UI completes the workflow and unrelated-member DOM/API
  contains no group, template, preview or assignment facts.

## Explicit non-goals

- no reuse or redesign of human `user_groups`; no generic teams/IAM/custom roles;
- no nested groups, dynamic label selectors or automatic fleet classification;
- no template variables, expressions, inheritance, schedules or JIT expiry
  workflow (F10);
- no approval-gated Kubernetes cluster-scope template item; that destination has
  its own candidate/approval lifecycle and is not an ordinary reusable rule;
- no parallel policy evaluator/compiler, node/runtime template awareness or new
  wire format;
- no automatic upgrade of assignments to a newer version;
- no F08 active probe, alert/webhook/SIEM history (F11), or MCP/tool policy
  semantics (F12+).

## Review and optimized box-walk contract

The combined F09 walk reuses `scripts/ai-agent-dev-walk.sh` for exact-SHA
preflight, rollback inventory, changed-component deploy verification and scoped
cleanup. One disposable two-agent group and one disposable template prove:
preview no-write; apply/compiler parity; add/remove convergence; stale-preview
refusal; replacement; assignment removal; owner/admin UI; unrelated-member
absence; migration rollback/refusal; and zero story-prefixed rows/scratch after
cleanup. No separate slice walks and no reusable secret enters an artifact.

The preceding F08 member-session absence leg remained an explicit SUBSTITUTE;
F09 did not reuse it as live evidence. F09's independent wire and permission
proof is recorded in `docs/F09-boxwalk.md` and
`walk-artifacts/F09/20260816T1159Z/`.
