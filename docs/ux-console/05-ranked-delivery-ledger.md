# Ranked UX Delivery Ledger

## Prerequisites and sequence

| Rank | Slice | Dependencies / decision gates | Done when |
|---|---|---|---|
| 0 | UX discovery close | Principles/inventories complete; ledgers reconcile; Agents dependencies dispositioned. | No product code changed; deferred decisions have named owning stories. |
| 1 | Query and state contract | D-UX-01: keyset/cursor, `q`, domain filters, allowlisted `sort`, `dir`, `limit`, opaque `cursor`. | OpenAPI/data requirements written; no numbered pages or inferred totals. |
| 2 | Shell and primitives extension | Extend existing AppShell/PageHeader/DataTable/SettingsRail/VisualGallery only as two real needs demonstrate. | Shell/error/offline/breadcrumb/table state conventions are visual-reviewable. |
| 3 | AI Agents reference vertical slice | Decisions paper `docs/S<story>-decisions.md`; D-UX-02 ownership; fixture org/agents; detail route/read shape. | Agents index → detail → staged Add Agent covers every meaningful UI state and proves ownership pattern. |
| 4 | Agent ownership cleanup | Depends on slice 3 detail tabs. | JIT/templates/groups move from Access with contextual links and no capability loss. |
| 5 | Devices vertical slice | Depends on query/state contract; decide `updateDeviceMode` UI/API-only disposition. | Device index/detail and lifecycle safety use proven pattern. |
| 6 | Gateways index/detail | Depends on detail pattern and destructive preview decisions. | Gateway operations are route-owned and list remains a dense index. |
| 7 | Gateway enrolment security story | Separate OpenAPI/API/security decision paper; enrollment correlation and expiry/retry design. | Wizard never misreports token issuance as successful connection. |
| 8 | Sites/Routed ranges/Kubernetes | Depends on Network detail grammar and cascade-preview contracts. | Topology actions have accurate effect/reconcile feedback. |
| 9 | Access/Users/Settings/Observe | Depends on agent ownership handoff and query-state contract. | No duplicated configuration; all remaining indexes use shared proven grammar. |

## Held decisions, ranked

1. **D-UX-03 Gateway enrollment:** direction locked; exact OpenAPI/retention/cancel in Gateway enrollment decisions paper.
2. **D-UX-04 Device mode:** API-only/held until Device story; not an Agents blocker.
3. **D-UX-05 CP-admin governance:** API-only for first console epic; separate governance story.
4. **User detail route/read model:** defer to Users story.
5. **Destructive preview contracts:** per owning story; never manufacture browser-side counts.
6. **Personal CLI credential revocation:** defer to Personal Security/CLI Credentials story.
7. **Offline/retry and notification retention:** shell foundation story.

## Story protocol reminder

Every implementation slice begins on its own story branch with its own `docs/S<story>-decisions.md`, implements one vertical surface, receives review/sign-off, and only then advances. Rapid visual iteration may defer tests honestly, but typecheck, build, required local gates, and exact-head CI remain mandatory before story completion/PR merge.

## Proposed first story — held for approval

**Identifier:** `S18` — proposed because `S16` / `S16.1` and `S17` already occupy the current story namespace and `PLAN.md` has no authorized next product story.  
**Branch:** `story/S18-ai-agents-console-workspace`  
**Decisions paper:** `docs/S18-decisions.md`

**Scope:** one reference vertical slice: a cursor-capable Agents index; `/agents/:agentId?tab=overview|runtime|mcp|access|activity`; URL-preserved list return; staged Add Agent token-issuance flow; existing profile/runtime/MCP/activity reads; dark/crimson shell primitives proven on this real surface; and contextual links rather than duplicated JIT/template editors.

**Required product/API work:** a backwards-compatible decision and implementation for the `listAgents` page envelope/query contract; new routes; browser state/layout work; an explicit D-UX-02 disposition for existing MCP profile create/assignment operations. No implementation is authorized by this proposal.

**Non-goals:** Device mode, CP-admin governance, gateway enrollment, gateway/device redesign, a generic EntityIndex/EntityDetail abstraction, a duplicate Access editor, and any promise of index totals absent from the server.

**Rapid visual-review states:** enterprise owner/admin and restricted operator; empty and populated index; query/filter/sort/cursor Back navigation; loading/error/partial/stale/edition-unavailable/permission-denied; healthy/offline/pending/revoked/suspended agent; each detail tab; bootstrap token shown once/expiry/failure; MCP profile disposition; JIT contextual link; destructive lifecycle confirmation and subsequent audit evidence. Browser console, request failures and response truth are reviewed continuously. This remains a proposal until the user approves the story and its decision paper.
