# Console UX Decision Register

## D-UX-01 — List query contract — LOCKED

All scalable indexes use keyset/cursor pagination. Query strings use `q`, domain-specific filters, allowlisted `sort`, `dir`, `limit`, and opaque `cursor`. Browser history preserves the complete query. The UI never promises numbered pages or infers a total from a batch; it renders an exact total only if the server explicitly returns one.

**Owner:** shell/query-contract foundation story.

## D-UX-02 — AI MCP profile ownership — LOCKED

AI Agents owns reusable MCP-profile lifecycle. Profile inventory belongs under the AI Agents domain and assignment belongs on `/agents/:agentId?tab=mcp`. Access Policies may show provenance and contextual links but never duplicate the editor. The first Agents story must expose or explicitly defer `createAgentMCPProfile` and `assignAgentMCPProfile`.

**Owner:** first AI Agents vertical slice.

## D-UX-03 — Gateway enrollment correlation — LOCKED DIRECTION

The Gateway enrollment story uses an opaque enrollment record. Token issue returns a one-time join token, opaque `enrollment_id`, and `expires_at`; authenticated/RBAC-protected status returns `pending`, `enrolled`, `expired`, or `cancelled`, plus `node_id` only after enrollment. It never returns or persists plaintext token. The UI must not correlate by gateway name.

Exact OpenAPI, retention, and cancellation semantics are deferred to that story’s `S<story>-decisions.md`.

## D-UX-04 — Device mode — DEFERRED

Do not add a Device mode control during the Agents slice. Keep `updateDeviceMode` API-only/held until the Device story documents semantics, safety impact, and intended operator.

**Owner:** Device detail story.

## D-UX-05 — CP-admin governance — DEFERRED

Keep `adminSetOrgRole` and `adminSetCpAdmin` API-only during the first console UX epic. Do not put deployment governance in organization Users & Roles.

**Owner:** named CP-admin governance story.
