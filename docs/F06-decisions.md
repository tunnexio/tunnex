# F06 — Agent ownership and delegated RBAC decisions

Status: **SATISFIES**. Commit-one locked the smallest F06 contract measured
from the F01–F05 foundation at content tip `d71f86f`; exact implementation
`8c3fed8` passed review, required local gates, and the combined AWS DEV walk.
Redacted live evidence is committed under
`walk-artifacts/F06/20260816T0410Z/`.

## Acceptance question

Can Tunnex keep one accountable human owner for every agent, optionally let the
members of one existing organization group manage that agent, and expose each
agent verb through a distinct permission without giving the agent principal or
an unrelated member policy-authoring or privileged-read authority?

## Measured foundation

- The agent is already the canonical `devices` row. `devices.user_id` is
  non-null and described as the owner; `agent_profiles.device_id` is keyed to
  that row and deliberately excludes owner/lifecycle duplication
  (`apps/api/db/migrations/0010_devices.up.sql:8-22`,
  `apps/api/db/migrations/0088_agent_profiles.up.sql:1-9,47-58`). F06 preserves
  this identity and owner.
- Organization authorization has three human membership roles
  (`owner|admin|member`) and a generated role-to-permission mirror. The Go grant
  table is authoritative and generates the web JSON
  (`apps/api/db/migrations/0002_tenancy.up.sql:43-56`,
  `apps/api/internal/rbac/rbac.go:128-219`).
- The only existing team-shaped relation is `user_groups` plus
  `group_members`. It is organization-scoped, group membership requires a
  current organization membership, and membership removal cascades the group
  row (`apps/api/db/migrations/0018_zero_trust.up.sql:13-45`). These groups are
  also Zero Trust policy subjects; F06 reuses their membership only and does
  not change their policy meaning.
- F01 profile access currently permits the accountable owner or a
  `member:manage` holder; only the latter may suspend/resume
  (`apps/api/internal/http/agent_profile_handlers.go:18-112`). F04 runtime
  status follows the same profile-access helper, while F05 rotation has its own
  `agent_credential:rotate` boundary. F06 replaces the broad member-management
  coupling for agent-owned verbs; it does not rewrite F04/F05 state machines.
- The agent runtime principal is intentionally the narrow `agent` role with
  only `org:view` and no policy-management or device verbs
  (`apps/api/internal/rbac/rbac.go:196-205`). F06 removes even accidental access
  to its new agent-governance permissions by granting it none.
- The released Agents route already clears roster, profile, runtime, rotation,
  gateway, and role state on organization switch before loading the next
  organization (`apps/web/src/pages/Agents.tsx:318-410`). F06 extends that same
  clearing boundary to assignment candidates and permission summaries.

## Decisions — LOCKED

### D1 — Canonical owner stays `devices.user_id`

F06 does not add `owner_id` to `agent_profiles` or create a second ownership
record. Reassignment updates the existing agent device's `user_id`. The target
must be an active, non-revoked membership in the same organization, read and
locked inside the assignment transaction. The agent identity, assigned address,
gateway, public key, lifecycle, runtime state, rotation state, and policy-rule
device ID do not change.

The previous and new owner IDs are recorded in one append-only
`agent.assignment_updated` audit event. The actor is the authenticated human;
the agent principal can never assign itself. Owner reassignment is an
accountability change, not a new identity or an access grant.

Rejected: duplicate owner metadata on `agent_profiles`. Two writable owners
would disagree and all F01/F07 attribution joins already resolve the canonical
device owner.

### D2 — Reuse one existing organization group as the optional managing team

Add one nullable `agent_profiles.managing_group_id` referencing an existing
`user_groups` row with `ON DELETE SET NULL`. A same-organization database
trigger rejects a group from another tenant. A current member of that selected
group is a scoped manager for that one agent; removing the member from the
group removes the delegation immediately. The group remains a normal Zero
Trust subject and no group is created implicitly.

This is the narrowest schema addition that expresses “optional managing team.”
It reuses the existing manual and IdP-synchronized membership machinery and
its audit trail. Selecting a group for management is explicit; merely belonging
to any policy group grants nothing.

Rejected: a generic team/IAM subsystem, team roles, per-agent ACL rows, or an
agent-manager role engine. Those duplicate existing organization membership
and group membership and exceed F06.

### D3 — Five new named permissions, one relational scope rule

The authoritative RBAC table gains exactly these permissions:

| Permission | Governs |
| --- | --- |
| `agent:enroll` | Issue a one-time managed-agent bootstrap token. |
| `agent:view_privileged` | Read owner/team, profile metadata, runtime status, rotation status, and the effective permission summary. |
| `agent:manage` | Edit metadata and request active↔suspended lifecycle changes. An org-wide holder may also change owner/team; a scoped owner/team manager may not change the governance boundary. |
| `agent:grant_access` | Create, replace, extend, enable/disable, or delete a policy rule whose source is an agent. It is required in addition to `policy:manage`. |
| `agent:revoke` | Revoke an agent and remove its already-revoked roster row. |

`agent_runtime:manage` remains the F04 organization opt-in permission.
`agent_credential:rotate` remains the F05 rotation-action permission. Neither is
renamed or absorbed into F06.

The server computes effective permissions for a specific agent. A normal role
grant is organization-wide. The accountable owner and each current managing
group member receive only scoped `agent:view_privileged` and `agent:manage`;
the accountable owner also receives scoped `agent:revoke`, preserving the
existing own-device revoke contract. Scoped authority never includes enroll,
grant access, credential rotation, or changing owner/team.

### D4 — Minimal role and relationship matrix

| Principal in the current org | Enroll | Privileged view | Manage metadata/lifecycle | Change owner/team | Grant agent access | Revoke/remove | Rotate credential |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Human org owner/admin | yes | all agents | all agents | yes | yes | all agents | yes, existing F05 permission |
| Accountable owner with human `member` role | no | owned agent | owned agent | no | no | owned agent | no |
| Current member of selected managing group | no | assigned agent | assigned agent | no | no | no | no |
| Unrelated human member | no | no | no | no | no | no | no |
| Machine `operator` | no | no | no | no | yes, with existing `policy:manage` | no | no |
| Data-plane `agent` principal | no | no | no | no | no | no | no |

Owner/admin receive all five new organization-wide grants. `operator` receives
only `agent:grant_access`, because its existing purpose is reconciling policy.
`member` and `agent` receive none in the global grant table; their scoped human
rights, when any, come only from the accountable-owner/managing-group relation.

### D5 — Permission first, edition second, identity last

Every human F06 endpoint performs organization authorization before the
Enterprise gate and before loading an agent, owner, group, profile, runtime, or
rotation row. A cross-organization/non-member caller keeps the established
normalized organization-not-found behavior. An authenticated but unauthorized
member gets the same 403 for a missing, foreign, or inaccessible agent. No
response may disclose whether the agent, target owner, managing group, edition,
runtime state, or rotation state exists before permission is established.

Machine poll/report/candidate endpoints retain the F04/F05 uniform 401 contract;
F06 adds no human permission checks to the runtime bearer path.

### D6 — Owner/team assignment is one atomic mutation

The existing agent profile PATCH is extended with optional `owner_id` and
`managing_group_update: {group_id: uuid|null}` fields; no second assignment
endpoint is added. The nested update shape was explicitly approved on
2026-08-16 because generated Go request types cannot otherwise distinguish an
omitted nullable UUID from an explicit null. The service
locks the device/profile, validates the new owner membership and managing group
tenant, updates both canonical owner and optional team, and inserts one audit
row in one transaction. Any validation, concurrent lifecycle change, or audit
failure leaves both assignment fields unchanged.

Only an organization-wide `agent:manage` holder may include assignment fields.
A scoped owner or team manager may use the same endpoint for metadata/lifecycle
but receives 403 if either assignment field is present. Omitted fields mean
unchanged; explicit `managing_group_update: {group_id: null}` clears the team.
The response and
a fresh GET are server truth; the UI never applies an optimistic assignment.

### D7 — Privileged facts and DOM absence are server-shaped

The basic roster remains available under `org:view` with its current truthful
liveness/traffic facts. Owner attribution is shown only where current rules
already permit it or the caller has scoped privileged view. Profile, owner/team,
runtime, rotation, and permission summary are returned only after
`agent:view_privileged` is effective for that specific agent.

The released page renders controls from the returned effective permission
summary rather than inferring owner/team authority from the human role. For an
unrelated member, restricted owner/team/profile/runtime/rotation values and
actions are absent from the DOM, not hidden with CSS. On organization switch,
all assignment candidates, effective permission summaries, expanded rows, and
in-flight results are cleared before the target organization renders.

### D8 — Access granting remains policy-authoring, with an extra agent gate

F06 does not create a parallel grant API or authorize policy writes from the
Agents page. The existing Access Policies operation remains the only writer.
When a rule has `src_kind=agent`, create and every later mutation require both
`policy:manage` and `agent:grant_access`. Rules for other source kinds are
unchanged. The data-plane agent role receives neither permission and can never
author the rule that grants its own access.

The released Access Policies dialog offers “AI agent” as a source only when the
human/machine principal has the extra permission. Selecting a managing team does
not grant the team policy-authoring authority.

### D9 — Audit events and retained provenance

F06 adds only `agent.assignment_updated`, atomically recording old/new owner
and old/new managing group IDs. Existing events remain authoritative:

- bootstrap redemption records `device.created` with owner and gateway
  (`apps/api/internal/devices/service.go:731-754`);
- profile/lifecycle mutation records `agent.profile_updated`
  (`apps/api/internal/devices/service.go:878-906`);
- rotation records `agent.credential_rotation_requested`
  (`apps/api/internal/devices/service.go:141-180`);
- revoke/cancel and roster removal record `device.revoked|device.cancelled` and
  `device.removed` (`apps/api/internal/devices/service.go:1155-1209`);
- policy service events remain the grant audit authority.

F06 does not rewrite historical events when ownership changes. F07 owns richer
event/workflow attribution; old events keep the actor/owner facts actually
recorded at their event time.

### D10 — Migration and rollback preserve canonical identity

The migration adds only the nullable team FK, same-org trigger, and indexes
needed by the scoped authorization query. Existing rows backfill to no managing
team; `devices.user_id` is untouched. Down refuses before dropping anything if
any live profile has a managing team, then removes the trigger/index/column.

Owner changes survive rollback because they use the pre-existing canonical
column; rollback must never guess or restore an earlier owner. Empty-assignment
down/up-again preserves device IDs, owners, statuses, profile metadata, runtime
state, rotations, and policy rules. Non-empty down refusal preserves the exact
team assignment and leaves the migration dirty in the repository's established
refusal convention.

## Absence audit 1 — every F06 mutation has a released-web caller

| Mutation after F06 | Required permission | Released production caller |
| --- | --- | --- |
| Issue bootstrap token | `agent:enroll` | Existing Agents enrollment form, `apps/web/src/pages/Agents.tsx:473-496`. The form/button become absent without the permission. |
| Update metadata/lifecycle/owner/team | effective `agent:manage`; org-wide for assignment fields | Existing profile PATCH caller, `apps/web/src/pages/Agents.tsx:412-445`, extended with owner/team selectors and a server-refetch permission summary. |
| Request credential rotation | existing `agent_credential:rotate` | Existing rotate action and refetch, `apps/web/src/pages/Agents.tsx:447-470`; F06 only shapes privileged status visibility. |
| Revoke then remove an agent | effective `agent:revoke` | Existing confirmation flow, `apps/web/src/pages/Agents.tsx:498-525,784-798`, updated to use the effective per-agent permission. |
| Create/replace an agent-source grant | `policy:manage` + `agent:grant_access` | Existing Access Policies create/swap flow, `apps/web/src/pages/Access.tsx:1546-1567,1631-1689`. |
| Extend/enable/disable/delete an agent-source grant | `policy:manage` + `agent:grant_access` | Existing Access Policies row actions; no F06-only policy endpoint is added. |

There is no F06 mutation without a released-route call site. Machine-only
bootstrap redemption and F04/F05 runtime candidate operations are not F06
human mutations and remain host/runtime callers.

## Absence audit 2 — destructive FK and operator-impact review

| Destructive/change verb | Database/runtime consequence | Required operator-visible impact |
| --- | --- | --- |
| Change accountable owner | Changes only `devices.user_id`; device ID, tunnel key/address, gateway, grants, runtime and rotation remain. Future attribution resolves to the new owner; historical audit stays unchanged. | “Changes who is accountable for this agent. It does not change the tunnel or access grants.” Show old→new owner and refetch. |
| Assign/clear managing team | Adds/removes only scoped management authority. It does not change policy membership, agent access, owner, tunnel, or runtime. | “Members of this group can view and manage this agent, but cannot grant access, rotate credentials, or revoke it.” |
| Delete selected `user_group` | New FK sets `managing_group_id` to null. Existing group delete also cascades its policy subject/destination rules under the established model (`apps/api/db/migrations/0018_zero_trust.up.sql:9-11,71-90`). | Existing group-delete confirmation must add the count of agents that will lose delegated management, alongside its existing rule impact; after delete, owner remains and Agents refetch shows no managing team. |
| Remove a group member / remove org membership | Group membership disappears (membership removal cascades `group_members`); scoped agent management disappears immediately. Canonical owner is not auto-transferred. Existing active-peer queries also require current owner membership (`apps/api/db/queries/devices.sql:305-346`). | Group/member offboarding confirmation must state how many managed-agent delegations are lost. F06 does not auto-pick a replacement owner. |
| Revoke and remove agent | Existing revoke invalidates runtime/candidate state, removes live peer/status, and F04 offboards. “Remove” is a soft delete, preserving CRL/history; no hard-delete FK cascade runs (`apps/api/internal/devices/service.go:1137-1171`). | Confirmation states tunnel/runtime stop, pending rotations cancel, and saved agent-source grants remain recorded but cannot match a revoked agent. A failed remove must still say revoke succeeded. |
| Hypothetical hard delete of device | Would cascade profile, runtime/rotation rows, and agent-source policy rules (`apps/api/db/migrations/0070_policy_src_agent.up.sql:15-19`), and could erase revocation records. | No F06 call site exposes hard delete. Preserve the existing revoke-then-soft-remove contract. |

## Narrow implementation slices

1. **Observable authorization slice:** add the five permissions and generated
   mirror; replace bootstrap/profile/runtime-status/rotation-view and
   agent-specific revoke authorization; return a server-computed effective
   permission summary. Prove permission-before-edition and uniform inaccessible
   agent responses before any schema/UI expansion.
2. **Atomic assignment slice:** reversible migration, same-org team guard,
   transactional owner/team update, scoped owner/team authorization, and audit.
   Prove concurrency, audit-failure rollback, membership/group removal effects,
   and rollback preservation on PostgreSQL.
3. **Released-route slice:** owner/team selectors and readable permission
   summary on Agents; per-agent controls from server truth; enrollment/revoke
   visibility; Access Policies extra agent-grant gate; org-switch and
   unauthorized DOM-absence tests.
4. **Review/gates:** focused default+enterprise API/DB/web tests, generated RBAC
   drift, current migration chain/rollback, full repository gates, and a
   multi-finder story-end review before the walk.

## One combined AWS DEV acceptance walk

Run only after all F06 code and exact-head gates are complete:

1. Deploy one exact signed F06 commit to the authorized AWS DEV CP; preserve
   rollback images and prove the new migration clean.
2. With an owner/admin, assign a current member as accountable owner and one
   existing group as managing team. Refetch must show persisted server truth and
   one audit event; the existing connected agent, runtime PID, key revision,
   gateway handshake, address, grants, and desired/applied revisions stay
   unchanged.
3. As the accountable member, prove privileged profile/runtime/rotation summary,
   metadata/lifecycle change, and revoke visibility for only the owned agent;
   prove assignment, enrollment, rotation and access-grant controls are absent.
4. As a managing-group member, prove scoped view/manage for the assigned agent
   only, with revoke/grant/rotation/assignment controls absent. As an unrelated
   member, capture normalized API refusals and prove owner/team/profile/runtime/
   rotation facts and actions are absent from the released DOM.
5. Create and refetch one agent-source grant as an authorized policy operator;
   prove a principal without `agent:grant_access` cannot render or call that
   source while ordinary non-agent policy work is unchanged. The agent principal
   receives no authoring path.
6. Remove the team member, then the managing group, and refetch after each:
   scoped authority disappears immediately, the owner and running tunnel remain,
   and impact copy/audit are truthful. Restore only the disposable group/member
   state used by the walk.
7. Exercise suspend/resume, then revoke. Prove existing F04/F05 offboard and
   rotation cleanup, saved grant non-match, owner/team API/DOM behavior, and the
   revoke-success/remove-failure message boundary.
8. On a disposable database, prove empty down/up-again preservation and
   non-empty rollback refusal. Clean only F06 disposable identities/groups/rules;
   do not disturb unrelated gateways, peers, users, policies, or AWS resources.

## Strict non-goals / deferred work

- No F07 access-event or workflow attribution, historical event rewrite, or
  claim about a human trigger without signed provenance.
- No F08 Test Access evaluator or probe.
- No generic IAM/team/custom-role system, per-agent ACL engine, team hierarchy,
  or auto-role engine.
- No agent group/policy-template work (F09) and no new policy-authoring surface
  on the Agents page.
- No implicit policy-authoring authority for the data-plane agent role.
- No F05 bearer/WireGuard rotation rewrite and no F04 runtime protocol change.
- No automatic owner transfer when a member leaves; the operator must explicitly
  reassign accountability before offboarding when continuity is required.

## Stop condition

Stop F06 when the five permissions, canonical owner plus optional managing
group, scoped effective authorization, atomic assignment/audit, released UI
call sites, DOM absence/org-switch behavior, rollback preservation, both
editions, exact-head CI, review, and the single combined AWS walk pass. Do not
add another delegation model or proceed into F07/F08 to make F06 look complete.

## Unresolved decide-items

None. The repository already supplies a fitting current-member group relation,
the canonical owner, generated RBAC, audit transaction pattern, released
callers, and live F04/F05 lifecycle. The reuse/build/defer choices above are
therefore LOCKED for the first implementation review; any newly discovered
semantic conflict halts product code and returns to this paper.
