# MCP authenticated discovery review — 2026-09-09

Status: INCOMPLETE / findings held for user disposition. This is not a clean review.
Base: `ai-improvement`, paper commit `a247e445` over `b33e2177`.
Product changes remain uncommitted and are not installed into the local API.

## Ranked findings

| ID | Priority | Finding | Required correction | Disposition |
|---|---|---|---|---|
| B1 | P1 | Private jobs select runner/revision before loading current credentials; a reassigned old runner can receive the new credential. | Bind runner, revision and secret retrieval in a transaction; reject superseded jobs. | Held |
| B2 | P1 | New machine lease/jobs/report operations omit the current organization runtime opt-in check. | Withdraw all three operations when runtime is off. | Held |
| B3 | P1 | An OAuth Start awaiting metadata can insert stale trust after connection replacement. | Fence OAuth creation/completion by configuration revision and serialize with configure/disconnect. | Held |
| U1 | P1 | The server-scoped inventory is passed into an agent-wide policy replacement editor, dropping rules for other endpoints. | Preserve rules outside the visible server or keep the full policy inventory. | Held |
| B4 | P2 | Failed shared credentials fall back to anonymous inventory collection. | Permit anonymous authorization metadata only; never publish anonymous tools as the configured identity. | Held |
| B5 | P2 | Profile OAuth Start is a plain insert, so cancelled/failed consent cannot be retried. | Revision-safe retry of pending/failed flows; explicit already-connected result. | Held |
| B6 | P2 | Assigned agents can concurrently refresh the same shared rotating token. | Serialize refresh across API instances and reread current token state. | Held |
| U2 | P2 | Freshly allocated agent arrays retrigger inventory loading and discard unsaved tool edits. | Stabilize membership dependencies and retain the editor during background refresh. | Held |
| U3 | P2 | An old status GET may overwrite a successful disconnect/rotation result. | Invalidate outstanding reads at mutation and reject superseded revisions/responses. | Held |
| B7 | P2 | Private discovery jobs are ordered by profile ID, while the runtime executes only the first job. Other configured servers can wait forever. | Schedule the oldest/unobserved job first and prove progress across multiple servers. | Held |
| B8 | P2 | Deleting a selected private discovery runner sets its FK to null, which also means control-plane discovery. | Preserve the configured network mode; a missing private runner must require replacement rather than changing execution host. | Held |
| B9 | P2 | OAuth inventory accepts a null authorization-server list; StartOAuth uses an unchecked slice assertion. | Reject missing/empty issuer metadata and safely type-check stored data before starting consent. | Held |

Backend review: independent `mcp_connection_review` agent. Frontend review:
independent `mcp_ui_review` agent. Reviews were read-only. Their findings have not
been folded. A subsequent review of the completed fixes is required.

## Verification already performed

- Pagination regression failed before the shared collector change and passed after.
- Shared collector: authenticated pagination, failed second page, malformed list,
  repeated cursor and redirect refusal tests pass.
- CLI: existing MCP proxy/policy refusal and collector tests plus endpoint-bound
  shared header injection pass.
- API: four focused connection tests pass against disposable databases in the
  explicitly verified `tunnexai0907` PostgreSQL container/network. They cover
  sealed storage, endpoint/organization binding, rotation/disconnect, failed HTTP
  response sanitization, and private runner/revision report binding.
- Existing OAuth tests pass with migration 152.
- Web: 11 focused MCP tests pass (authentication fields, secret clearing, first
  policy creation, permission refusal, status guidance, existing profile lifecycle).
- API packages compile in open and enterprise modes; web typecheck passed.
- Runtime opt-out regression has been added to demonstrate B2. It is intentionally
  unresolved until disposition; do not describe the whole suite as green.
- Full gates, installed API migration, private runtime wire walk, OAuth consent
  wire walk, final documentation publication and final checkpoint remain pending.

All credentials used by tests are synthetic. Existing preview database volumes,
real Azure credentials and external servers were not changed.

## Full AI Agents flow re-review requested on 2026-09-09

These additional findings are held separately from B1–B9 and U1–U3. A second
read-only pass checked the Agents roster, detail tabs, groups, templates and MCP
handoffs against the API and the AI Gateway workflow. It asked both absence
questions from AGENTS.md: unreachable supported mutations and destructive-action
consequences. No existing agent, grant, template or real credential was mutated.

| ID | Priority | Finding and evidence | Recommended correction | Disposition |
|---|---|---|---|---|
| A1 | P1 | Archiving a template leaves assignments active, but archived templates disappear from the list and the only Remove buttons are inside a selected template (`AgentsPolicyTemplates.tsx`; `agent_templates.sql`). | Keep current assignments independently reachable, including assignments to archived templates. Preserve existing grants until explicitly removed. | Held |
| A2 | P2 | Group membership loads one `/agents` page and ignores `next_cursor` (`AccessGroups.tsx`). Agents beyond the default 50 cannot be selected. | Add paginated/searchable membership selection and verify a later-page agent can be selected. | Held |
| A3 | P2 | Search updates URL state on every keystroke; the loading state unmounts the whole toolbar (`AgentsIndex.tsx`). Browser reproduction: after typing `installed`, the search input disappeared and active-element label became null. | Keep the search/filter toolbar mounted during result refresh and debounce typing. | Held |
| A4 | P2 | Agent Detail's Manage MCP profiles link includes only the group, not the effective profile ID. MCP chooses the first profile (`AgentDetail.tsx`, `AgentsMCP.tsx`). | Carry the effective profile ID and preserve agent context. | Held |
| A5 | P2 | Bootstrap's displayed prerequisites omit curl, jq and the required Tunnex `releaseverify` binary (`AddAgentFlow.tsx`, `agentview.ts`). | Show complete prerequisites before token issuance and link a supported verifier installation path. Do not weaken release verification. | Held |
| A6 | P2 | Template authoring exposes one resource, while its API accepts 1–100 destinations of resource/group/site/k8s_service (`AgentsPolicyTemplates.tsx`, OpenAPI AgentPolicyTemplateItem). | Expose destination kinds and multiple selections using existing APIs, with the same impact-preview step. | Held |
| A7 | P2 | Browser shows a generic red Information unavailable / Retry for an opted-out runtime and for MCP inventory that has never been observed. Retrying cannot finish setup. | Distinguish setup-required and no-observation states from failures; link to the appropriate settings/group/server setup without enabling anything automatically. | Held |

A1–A6: independent UI reviewer; confirmed against source by the main agent.
A7: main-agent rendered browser review. The existing shared navigation and dark
theme are consistent at the inspected viewport. The flow is not accepted as
complete: setup handoffs and action availability above still need correction.

## Local MCP transport wire proof

`walk-artifacts/mcp-auth0909/result.json` records a separate local HTTPS MCP
server process and the production collector/proxy. Two pages exposed three tools;
the selected tool returned 200, unselected and revoked tools returned 403, and
only the allowed call reached the server. Anonymous discovery returned 401;
second-page 403 did not publish a partial catalog. This proves the transport and
proxy behavior only. Installed credential leasing, managed enrollment, browser
connect/grant flow and OAuth consent remain separate pending acceptance checks.
