# REGISTER — generic access simulation and temporary access requests

**Status:** PENDING — founder-directed product direction recorded on 2026-08-23.

**Implementation:** NOT STARTED. This document records a future story; it does
not amend the active story, authorize product changes, or disposition the
decide-items below.

**Trigger:** open a dedicated Access UX/API story after the current AI Agents
workspace and its MCP lifecycle work are completed and separately approved.

## Customer direction

`Test access` and approval-gated temporary access should become generic Tunnex
Zero Trust capabilities. They must use the same source/destination vocabulary as
ordinary access rules instead of being presented as AI-agent-only features.

The intended product grammar is:

```text
Test access
  source -> destination -> protocol/port -> explanation (read-only)

Temporary access request
  requester -> source subject -> canonical destination -> duration -> reason
  -> approval -> one expiring ordinary policy rule
```

The generic surfaces should cover users, user groups, devices, AI agents, agent
groups, sites/CIDRs and Kubernetes identities wherever the server has a truthful
canonical identity for that role.

## Locked direction

1. **One enforcement plane.** Approval materializes an ordinary expiring
   `policy_rules` row. No second evaluator or parallel dataplane is introduced.
2. **Simulation remains read-only.** `Test access` explains current control-plane
   intent and never sends packets, performs DNS, or mutates policy.
3. **One generic request state machine.** The lifecycle remains
   `pending -> approved -> expired|revoked` and
   `pending -> rejected|cancelled`, with idempotent transitions and append-only
   provenance.
4. **Long-lived policy remains in Access Policies.** Request-owned rules appear
   there as read-only, labelled rules with expiry and request provenance.
5. **Entity pages provide contextual entry points, not duplicate editors.** A
   User, Device, Agent, Site or Kubernetes detail page may deep-link to generic
   `Test access`, `Request temporary access`, `View effective policies` and
   `View request history` flows with the subject preselected.
6. **Canonical destinations only for mutation.** A temporary request targets a
   named, current Tunnex destination. A raw IP/hostname may be useful for
   read-only simulation, but must not silently become unauditable policy input.
7. **Authority is human-owned.** A device, agent, runtime or machine credential
   cannot request or approve additional access for itself.
8. **Unlock then opt in.** If generic temporary access is licensed, installing a
   key only makes the capability available; organization enablement remains
   explicit and defaults OFF.

## Current contract baseline

| Identity or destination | Ordinary rule support today | Generic request support today |
| --- | --- | --- |
| User / user group as source | Yes | No |
| Site / CIDR as source | Yes | No |
| AI agent as source | Yes | Agent-specific F10 only |
| Agent group as source | Materialized by the template path | No |
| Resource / group as destination | Yes | Agent-specific F10 only |
| Site as destination | Yes | Agent-specific F10 only |
| Kubernetes Service as destination | Yes | Agent-specific F10 only |
| Specific human device as source | No first-class rule kind | No |
| Kubernetes workload as source | No first-class rule kind | No |

The current F10 implementation is deliberately agent-specific:
`agent_access_requests`, agent-scoped permissions and agent lifecycle closures.
Making the feature generic is therefore an API, RBAC, schema, lifecycle and UX
story, not a label or component rename.

## Proposed information architecture

- **Access Policies / Rules:** authoritative permanent and temporary rule
  inventory.
- **Access Policies / Requests:** generic requester and approver inbox, history,
  revoke and recovery paths.
- **Access Policies / Test:** generic read-only simulation and explanation.
- **Entity detail pages:** scoped summaries and deep links into those shared
  workspaces.
- **Organization Settings:** availability, explicit opt-in and blocking counts.

The current `Just-in-time agent access` panel should not remain duplicated on
the Access Policies overview and an Agent detail page. When the generic story
lands, it becomes `Temporary access requests`; Agent pages retain only their
contextual view and entry point.

## Decide-items for the future story

These are intentionally unresolved until the trigger fires:

1. **Exact-device subject:** add a first-class human-device source kind, or keep
   human access owner/group based and explain that one user resolves to all
   eligible devices.
2. **Kubernetes source identity:** define a stable workload identity before
   offering workload-originated simulation or temporary grants. A Service VIP
   is a destination, not a workload principal.
3. **Site blast radius:** determine whether whole-site/CIDR temporary requests
   require owner-only approval, separation of duties, or an additional impact
   confirmation.
4. **Kubernetes cluster-scope approvals:** retain their existing specialized
   candidate/approval lifecycle or adapt them behind the common request shell
   without erasing their distinct security semantics.
5. **Requester authority by subject:** self-user, device owner, agent owner,
   managing group, site operator and organization-wide requester scopes need an
   explicit no-oracle RBAC matrix.
6. **Protocol/port ownership:** ordinary policy rules currently target canonical
   destinations whose resource definition owns protocol/port. Decide whether a
   request can narrow that scope without creating a second destination model.
7. **Migration:** evolve or replace `agent_access_requests` while preserving all
   F10 history, audit actors, request IDs, terminal states and bound-rule
   provenance.
8. **Entitlement naming:** decide which licence tiers unlock generic temporary
   access and remove agent-only product copy without reviving Open/Enterprise
   terminology.
9. **Approval policy:** decide whether one owner/admin approval is sufficient for
   every subject class or whether high-blast-radius requests need a distinct
   approver/separation-of-duties policy.
10. **Simulation truth contract:** define a common response that identifies the
    matched rule, first blocker, policy mode, stale/unknown inputs and the exact
    reason for allow or deny without claiming live reachability.

## Future story acceptance gates

- Every supported ordinary-rule source/destination combination is either
  available in simulation/requests or explicitly refused with a documented
  reason.
- Request approval creates exactly one ordinary expiring rule atomically with
  request event and audit evidence.
- Expiry, revoke, subject suspension/removal and destination deletion have
  explicit effects and recovery paths.
- Request-owned rules cannot be edited, extended, toggled or deleted through the
  ordinary rule mutation surface.
- Entity pages and the central Access workspace show the same server-owned state;
  no duplicate client-side lifecycle exists.
- Unsupported or unknown identities fail closed and never appear as successful
  zero-result simulation.
- Existing F10 request history survives migration byte-for-byte where the schema
  permits, with a documented compatibility mapping for every field.

## Related records

- `docs/F10-decisions.md` — current agent-specific approval workflow.
- `docs/S7.5.4-decisions.md` — ordinary per-user and temporary grants.
- `openapi/openapi.yaml` — current policy and agent-access contracts.
