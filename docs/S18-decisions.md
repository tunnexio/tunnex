# S18 — AI Agents console workspace decisions

**Status:** proposed decision paper; no product implementation is authorized until
the founder approves this paper and creates the story branch.

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
| Overview | `getAgentProfile` | Profile, lifecycle, ownership/governance, connection facts, contextual related links. |
| Runtime | `getAgentRuntimeStatus`, `getAgentCredentialRotation` | Runtime state and existing rotation facts/actions subject to existing permissions. |
| MCP | `getAgentMCPInventory`, `getAgentMCPToolPolicy`, `listAgentMCPToolApprovalRequests`, `listAgentMCPOAuthConnections`, `listAgentMCPProfiles` | Inventory, policy/approval state, and group-derived profile provenance. |
| Access | Existing agent JIT settings, destinations, request list/detail reads | Agent-specific JIT posture and links/actions; no duplicated Access Policy editor. |
| Activity | `listAgentWorkflowProvenance` | Workflow provenance; link out to cross-domain access/audit evidence rather than copying it. |

### D4 — Add Agent is staged token issuance, not claimed enrolment

The browser may call authenticated `issueAgentBootstrapToken` (`POST
/organizations/{orgId}/agents/bootstrap-token`) to issue an operator-visible
one-time bootstrap token. The current `201` response returns the shown-once
token and release metadata, **not an expiry**; the UI must not invent one. It
shows safe copy guidance, next runtime command/instructions, and explicit
**pending enrolment** state. The browser never calls `POST /api/v1/agent/bootstrap`: that
is an unauthenticated machine protocol redemption route, not an operator UI
action. The flow must not infer enrolment from a gateway name or token issuance.

Gateway-enrolment correlation remains outside S18 under D-UX-03.

### D5 — MCP profile lifecycle is not silently left unreachable

D-UX-02 assigns reusable MCP profiles to AI Agents. The existing
`createAgentMCPProfile` and `assignAgentMCPProfile` operations require an
explicit S18 implementation disposition before code begins:

1. include profile inventory plus group-targeted creation/assignment in an
   Agents-owned Profiles/Groups workspace, with the individual MCP tab showing
   group-derived provenance and a contextual link; or
2. defer all three together to a named immediate follow-up story, leaving an
honest unavailable state and no false management claim.

This paper recommends option 1 if the endpoint contracts and fixture data are
ready. The final founder approval must select it; an implicit defer is invalid.

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

No S18 change may weaken existing RBAC, edition enforcement, audit writes, or
server-side refusal semantics. UI hidden/disabled/restricted states distinguish
missing permission from Open-edition capability absence.

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
visible. Existing handler permissions and Enterprise gates remain authoritative;
the UI must preserve an actionable distinction among loading, no data, stale or
partial data, pending, permission denied, and edition unavailable.

Any lifecycle/revoke/disable action included in S18 must state before execution:
the exact target, access/runtime consequence, server-provided affected-resource
facts only, recovery route (or no recovery), and audit evidence. It refetches
the authoritative profile/index/activity evidence after success; it does not
invent a client-side cascade preview.

## 6. Required rapid visual-review states

Before story completion, review in the browser with fixture owner/admin and a
restricted persona:

- populated, fresh, empty, loading, failure, partial/stale, permission-denied,
  and Open-edition-unavailable index states;
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
operation-specific (not a blanket Enterprise label), and activity remains an
unpaged array until a later API contract changes it. Those are implementation
decisions, not missing investigation.

The isolated non-production fixture procedure in
`docs/ux-console/07-azure-fixture-and-live-review-plan.md` must be followed;
production credentials and production data are forbidden.
