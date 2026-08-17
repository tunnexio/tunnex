# F10 — Just-in-time agent access decisions

Status: **Done — exact local gates and the combined AWS DEV walk satisfy F10**.

## Customer outcome

An accountable human can request temporary access for one managed agent to one
existing Tunnex destination. An owner or administrator can approve or reject
the request with the destination, reason and bounded duration visible. Approval
materializes one ordinary expiring Tunnex policy rule; expiry or emergency
revocation withdraws that rule through the existing policy compiler and gateway
reconciliation path.

## Reuse census

- `devices` remains the canonical agent identity, owner, lifecycle and tunnel.
  F10 adds no agent principal, address, credential or runtime state.
- `policy_rules` already supports `src_kind='agent'`, canonical destination
  references and `expires_at`. The existing deterministic compiler, push path and
  gateway enforcement remain the only authorization plane.
- F06 owner/managing-group scope remains the accountable-human boundary. F10
  adds named request/approval permissions; it does not give an agent or machine
  credential policy-writing authority.
- F07 audit actors and causes remain authoritative. F10 records workflow events
  and ordinary policy audit without inventing another actor model.
- F08 Test Access remains read-only diagnostics before and after approval. A JIT
  request never invokes it as an enforcement oracle or mutates through it.
- F09 templates/groups remain reusable long-lived policy authoring. F10 grants
  exactly one agent temporary access and does not add expiry to templates.

## Locked decisions

### D1 — A human requests on behalf of an agent

F10 v1 is not agent self-service. The request caller is an authenticated human
who either owns the agent, belongs to its F06 managing group, or has organization-
wide request authority. The managed-agent bearer, node reporter and machine
operator can never create, approve, reject, cancel or revoke a request.

This preserves the epic boundary: a prompt-injected but correctly authenticated
agent cannot author the rule that grants itself more access. Agent-originated
workflow protocols and notifications are deferred; no hidden polling field is
added to the F04 runtime channel.

### D2 — One request is one agent, one canonical destination and one duration

A request names an active or suspended managed-agent device and one existing
destination of kind `resource`, `group`, `site`, or `k8s_service`. It stores the
destination UUID plus an immutable display-name snapshot. Enforcement always
resolves the live canonical destination while the request is pending or approved;
the snapshot is history-only and never becomes policy input.

Cluster-scope Kubernetes approval is excluded because it has its own candidate
and approval lifecycle. F09 templates, agent groups, arbitrary CIDRs, nested
requests and multi-destination bundles are non-goals.

The requester supplies a required reason (1–500 characters) and duration. The
released UI defaults to **1 hour**. The server accepts durations from **5 minutes
through 24 hours**, calculates the absolute expiry at approval time, and never
trusts a client-supplied absolute timestamp. Approval after a long queue therefore
still grants the approved duration, capped at 24 hours.

### D3 — Explicit idempotent state machine

`agent_access_requests` owns current state:

`pending -> approved -> expired | revoked`

`pending -> rejected | cancelled`

Every other transition is refused except an exact retry of an already-completed
operation with the same idempotency key, which returns the existing result. A
request cannot be reopened or re-approved. New access after any terminal state is
a new request with a new ID.

Create, approve, reject, cancel and revoke each take a caller-generated
idempotency key scoped to organization and operation. Reusing a key with different
parameters is a conflict. Database row locks serialize approval versus
cancel/reject and expiry versus emergency revoke.

### D4 — Append-only workflow events carry provenance

`agent_access_request_events` is append-only and records request ID, resulting
state, human or system actor, timestamp and bounded metadata. The request row also
stores the current state and terminal timestamps for efficient listing; events
are the provenance record.

The lifecycle actions are:

- `agent_access.requested`
- `agent_access.approved`
- `agent_access.rejected`
- `agent_access.cancelled`
- `agent_access.expired`
- `agent_access.revoked`

Each transition and its ordinary Tunnex audit row commit in the same transaction.
Automatic expiry uses the F07 system actor `agent-access-expiry` and an explicit
cause. Reasons are operator-visible audit metadata but never credentials or
configuration bytes.

### D5 — Approval materializes one ordinary expiring policy rule

Approval creates one `policy_rules` row with `src_kind='agent'`, the request's
device, the referenced destination and `expires_at=approval_time+duration`.
`agent_access_requests.policy_rule_id` binds the workflow to that rule. The rule
uses the existing compiler and gateway push; no node/runtime JIT schema or second
evaluator is introduced.

Request-owned rules cannot be edited, extended, toggled or deleted through the
ordinary Access rule endpoints. The approval duration is immutable. Revoke the
request or create a new one rather than turning an approval record into another
authority. The ordinary rule list labels it as JIT-managed and links to the
request status.

Approval is atomic: lock request/agent/destination and organization opt-in,
revalidate current authorization and lifecycle, insert rule, append event/audit,
commit, then use the existing post-commit policy push. A failed audit or rule
insert leaves the request pending and creates no access.

Deleting a destination is refused with an explicit conflict while any request
for it is pending or approved. Terminal request history never permanently owns
the destination: after rejection, cancellation, expiry or revocation the
destination may be deleted, while the request retains its UUID and immutable
display name for operator history. F10 does not silently close a live request as
a side effect of an unrelated destructive action.

### D6 — F10 owns expiry for request-bound rules

The existing temporary-grant sweeper continues to own hand-authored temporary
rules. Its delete query excludes rules bound to a live F10 request. A stateless
F10 sweeper locks due approved requests, deletes the bound rule, marks the request
expired, writes event/audit in the same transaction, then pushes each affected
organization once.

Downtime creates no skipped window: every tick selects all approved requests with
`expires_at <= now()`. The compiler's existing `expires_at > now()` filter remains
the correctness backstop, so access stops compiling even before cleanup runs.

### D7 — Cancellation and emergency revoke are distinct

- The original requester, current agent owner/managing-group member, owner or
  admin may cancel a pending request. Cancellation creates no rule and no push.
- Only an owner/admin approver may reject a pending request. A bounded rejection
  reason is required.
- Only an owner/admin approver may emergency-revoke approved access. Revocation
  atomically deletes the bound policy rule, appends provenance and triggers the
  ordinary policy push. Repeated revoke with the same key is a no-op response.
- Revoking, removing or soft-deleting the agent automatically cancels pending
  requests and revokes approved ones in the same device lifecycle transaction;
  it never leaves a request claiming access that the canonical device lost.
- Suspension cancels pending requests and revokes approved access. Resume does
  not restore it; a new human request is required.

Historical request/event rows survive lifecycle operations. Their device FK is
restrictive and the existing soft-delete path remains canonical.

### D8 — Named permissions and no-oracle ordering

Add two permissions:

- `agent_access:request` — owner/admin organization-wide; an agent's accountable
  owner and F06 managing-group members receive it only for that agent.
- `agent_access:approve` — owner/admin organization-wide only.

Request/list/detail/cancel checks organization membership and scoped request
authority before loading object identity. Approval inbox and approve/reject/revoke
check approval authority before edition and before request lookup. Missing,
foreign and unauthorized IDs return the same forbidden shape. No permission is
reused from F04/F05/F09.

### D9 — Enterprise unlock then explicit opt-in

F10 is Enterprise and adds `organizations.agent_jit_access_enabled`, default
`false`. License unlock alone changes no policy. An owner/admin explicitly enables
JIT access in Org Settings using `agent_access:approve`.

Disabling is allowed only when there are no pending or approved requests. The UI
shows the blocking counts; operators cancel/reject/revoke them first. Disable
therefore cannot silently retain or withdraw access.

### D10 — Lists are bounded, tenant-scoped and role-shaped

The approval inbox is keyset-paginated and defaults to pending requests. An
approver may filter by state/agent. Scoped requesters see only requests for agents
they may request for. Responses include destination name/type, duration, state,
actors and timestamps but never policy compiler internals, agent credentials,
private keys, bootstrap data or audit-only metadata.

Organization switches synchronously clear request form, inbox, selected agent,
destination, pending mutations and previous-org results before target-org DOM is
rendered.

### D11 — Migration and rollback preserve every existing grant

Migration `0098` adds the organization flag, request/event tables, tenant-scoped
device/user FKs, destination UUID/name snapshots, indexes/checks and a
request-owned reference to the materialized policy rule. Destination identity is
validated and snapshotted at creation, but terminal history intentionally has no
hard destination FK so it cannot permanently block canonical deletion.
Existing rules are untouched and remain unbound. Up is valid with existing permanent,
temporary, F09-managed and machine-managed rules.

Down succeeds only when every organization opt-in is off and all F10 request/event
rows and bindings are empty. Otherwise it refuses before dropping anything and
preserves request rows, events, rule IDs and expiry values. Empty down/up-again
preserves every pre-F10 rule and compiled hash.

### D12 — No secret or reachability claim

Request IDs and idempotency keys are not credentials. No bearer, cookie, private
key, WireGuard config or raw policy artifact enters a request, event, audit row,
response, DOM or walk artifact. Approval means policy intent was installed; it
does not claim the destination is healthy or the network path works. F08 remains
the explicit current-state diagnostic.

## API and released UI contract

- OpenAPI owns enable/disable, create/list/detail, approve, reject, cancel and
  revoke operations plus generated Go/TypeScript types.
- Access Policies adds `Request temporary agent access` and an owner/admin
  `Agent access approvals` inbox. The form shows agent, destination, reason and
  requested duration, stating that exact expiry is calculated on approval; the
  approval card shows the resulting server timestamp.
- Every mutation refetches the server result. No optimistic approval, countdown,
  rule ID or state is rendered.
- The existing rule table labels active request-owned rules `JIT access` and
  disables ordinary edit/extend/toggle/delete actions.
- Org Settings adds a default-off JIT card with blocking pending/approved counts.
- Unrelated members and data-plane agents receive no request, inbox, actor,
  destination or approval DOM/API facts.

## Absence audit — mutation caller and consequence

| Mutation | Released caller | Required consequence copy |
| --- | --- | --- |
| Enable/disable JIT | Org Settings | Enabling grants nothing; disable requires zero pending/approved requests. |
| Create request | Access Policies request form | Shows exact agent, destination, reason, duration and no access until approval. |
| Cancel request | Request detail/list | Pending request ends; no policy rule existed. |
| Approve/reject | Approval inbox | Approval creates one expiring rule; rejection creates none. |
| Emergency revoke | Approved request detail | Rule is removed immediately and access will not return on agent resume. |
| Delete referenced destination | Existing destination delete surface | Refused while a JIT request is pending/approved; terminal request history remains readable after deletion. |

There is no F10 mutation without a released route caller.

## Narrow implementation slices

1. Reversible `0098` model, named permissions, default-off flag, typed queries
   and migration preservation/refusal tests.
2. One vertical wire: scoped human request -> owner approval -> ordinary
   expiring agent rule -> compiled policy change -> automatic expiry.
3. Cancellation/rejection/revoke, agent lifecycle composition, idempotent races,
   event/audit provenance and pagination.
4. Released request/inbox/settings/rule-label UI with refetch, impact copy,
   absence and organization-switch tests.
5. Story-end review, one frozen full gate matrix, then one combined optimized
   AWS DEV walk reusing the F08/F09 harness.

## Observable acceptance

- an accountable human requests one destination for one hour and no policy
  changes while pending;
- an owner sees the exact facts, approves once, and one ordinary rule compiles
  for the selected agent with a server-calculated expiry;
- retrying create/approve is idempotent, while conflicting keys/parameters and
  concurrent cancel/approve resolve to one terminal truth;
- rejection/cancellation create no rule; emergency revoke and automatic expiry
  withdraw the exact rule and produce system/human provenance;
- suspend/revoke mid-request cannot leave pending or active JIT access, and
  resume never restores it;
- owner/admin inbox and scoped requester views are correct; unrelated-member and
  agent DOM/API contain no F10 facts;
- migration empty down/up and non-empty refusal preserve pre-F10 policy rows,
  request/event rows, expiry values and compiled hashes;
- F08 before/after diagnostics agree with the ordinary compiled policy without
  any F10-specific evaluator.

## Explicit non-goals

- no agent self-service protocol, runtime request polling or agent approval;
- no multi-destination bundle, F09 template request, nested approval chain,
  quorum, escalation, schedule, recurring grant or external ticket integration;
- no arbitrary CIDR request or Kubernetes cluster-scope approval;
- no new policy compiler, node/runtime wire schema or L7/MCP tool authorization;
- no notification/email/Slack workflow, generic BPM engine or custom roles;
- no permanent approval and no extension of an approved request.
