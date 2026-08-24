# AI Agents Console API Contract

**Evidence revision:** `fe7ccf5`. This document separates what the current OpenAPI/handler implementation actually provides from the target required by the first Agents workspace. A target item is not an implied backend capability.

## Current inventory and detail reads

| Workspace need | Current operation and response | Authorization / edition | Current UI evidence | Target disposition |
|---|---|---|---|---|
| Agent index | `GET /api/v1/organizations/{orgId}/agents` (`listAgents`) returns a bare `Agent[]`: device ID, name, gateway/node, status, address, `config_issued`, handshake, RX/TX, derived `online`, `gateway_reporting`, and conditionally owner email. | `org:view`; Enterprise; owner email requires `member:manage` unless caller owns agent (`agent_handlers.go:125`). | `Agents.tsx:632` invokes `api.GET` directly. | **Change required.** No query parameters, page envelope, cursor, filters, sort, or exact total exist today. |
| Profile / Overview tab | `GET .../agents/{deviceId}` (`getAgentProfile`) returns profile fields, lifecycle, traffic/handshake and effective permissions. | `org:view` plus scoped or global `agent:view_privileged`; Enterprise (`agent_profile_handlers.go:18`). | `Agents.tsx:667`. | Existing; detail route is a UI routing change, not a new read. |
| Runtime tab | `GET .../runtime-status` (`getAgentRuntimeStatus`). | Handler permission/edition gate must be preserved; Enterprise. | `Agents.tsx:673`. | Existing read; preserve its current response schema. |
| MCP inventory tab | `GET .../mcp-inventory` (`getAgentMCPInventory`). | Agent-scoped read permission; Enterprise. | `Agents.tsx:685`. | Existing read. |
| MCP policy tab | `GET .../mcp-tool-policy` and `GET .../mcp-tool-approval-requests`; OAuth connections use `GET .../mcp-oauth-connections`. | Agent-scoped privilege; policy mutation needs `agent_mcp_tool_policy:manage`; approvals need their dedicated permission; Enterprise. | `Agents.tsx:105`, `74`, `145`. | Existing reads; profile assignment is separate below. |
| Activity tab | `GET .../workflow-provenance` (`listAgentWorkflowProvenance`). | Agent-scoped privileged read; Enterprise. | `Agents.tsx:689`. | Existing read; access/audit events remain contextual links, not duplicate storage. |
| Credential rotation panel | `GET .../credential-rotation` (`getAgentCredentialRotation`). | `agent_credential:rotate`; Enterprise. | `Agents.tsx:693`. | Existing read. |
| JIT tab / queue | `GET /organizations/{orgId}/agent-jit-access-settings`, `GET .../agent-access-destinations`, `GET .../agent-access-requests` and `GET .../agent-access-requests/{requestId}`. The request list already uses keyset fields `state`, `device_id`, `before_requested_at`, `before_id`, `page_size` (`openapi.yaml:4061`). | JIT handlers apply their request/approve permissions and Enterprise/explicit opt-in checks. | Current implementation is in `Access.tsx`, not Agents. | Move surface ownership in the UI; no duplicate editor. Normalize query names only in a later API change. |

## Target index query contract — API change required

The current `listAgents` route cannot implement D-UX-01. The replacement must retain the path and change its `200` body from `Agent[]` to an explicit keyset page, or introduce a versioned/list-specific operation with a migration plan. Proposed request keys are `q`, allowlisted domain filters (`status`, `gateway_id`, `runtime`, `environment`, `owner_id`, `managed_group_id`), `sort`, `dir`, `limit`, and opaque `cursor`.

- `sort` is allowlisted only: `name`, `status`, `last_handshake_at`, `gateway_name`, `owner`, `runtime`, and `created_at` **only if** the server can supply each fact. Unknown sort/filter keys are `400 invalid_request`.
- `limit` is bounded by the server; `cursor` is opaque and tied to the active filter/sort contract. The browser preserves the full URL, including `cursor`, for Back/Forward; it does not synthesize numbered pages.
- Response target: `{ items: Agent[], next_cursor?: string, total?: number }`. `total` is absent unless calculated and returned by the server; the UI never infers it from the loaded batch.
- Each status needs its source/freshness facts in the response: agent handshake time and gateway status-channel freshness. `ListAgents` already derives `online` and `gateway_reporting` (`agent_handlers.go:125`), but does not return a general `updated_at`/index freshness field.

## MCP profile lifecycle

`GET /organizations/{orgId}/agent-mcp-profiles` (`listAgentMCPProfiles`), `POST` to the same path (`createAgentMCPProfile`, `201 AgentMCPProfile`), and `POST .../{profileId}/assignments` (`assignAgentMCPProfile`, `201 AgentMCPProfileAssignment`) exist in OpenAPI and handlers (`agent_template_handlers.go:72`, `90`, `116`). They are not called by the current browser. Their handlers require `agent_template:manage`, the Enterprise agent-template capability, and the organization opt-in (`requireAgentTemplates`).

D-UX-02 locks their UX ownership to AI Agents: a reusable profile inventory lives in Agents, and assignment appears under `/agents/:agentId?tab=mcp` with contextual policy provenance only in Access. The first story must either expose these two create/assignment operations or explicitly defer them in its story decisions paper; it must not leave them silently unreachable.

## Mutation truth for the reference slice

Existing profile changes use `PATCH .../agents/{deviceId}` at `Agents.tsx:738`, `758`, and `775`; the handler returns `200 AgentProfile` and emits `agent.profile_updated` for profile/lifecycle fields and `agent.assignment_updated` for governance changes (`agent_profile_handlers.go:35`, `devices/service.go:1015`). The source page explicitly refetches the profile after its update at `Agents.tsx:802`.

The staged Add Agent workflow can currently issue a bootstrap token with `POST .../agents/bootstrap-token` (`201 AgentBootstrapTokenResponse`, `agent:enroll`, Enterprise) but has no browser caller. `POST /api/v1/agent/bootstrap` is a machine redemption route with no browser authentication; it returns `200 AgentBootstrapResponse` once and is protocol-only (`agent_handlers.go:99`). The first UI story may expose token issuance but must never call or display the runtime bootstrap redemption as a browser action.

## Explicit first-slice API gaps / decisions

1. **Required API change:** cursor/filter/sort agent index envelope described above.
2. **Required product decision:** whether the index response needs a server-provided `created_at` to support its proposed sort; do not advertise that sort until it exists.
3. **Required story disposition:** MCP profile create/assignment UI: include, or defer with a named follow-up and an explicit reason.
4. **Not an API gap:** detail routes, URL tab state, DataTable presentation, and moving JIT ownership are browser architecture changes using current reads.
5. **Out of scope:** Device mode (D-UX-04), CP-admin governance (D-UX-05), and gateway enrollment correlation (D-UX-03).
