# Tunnex Console UX Principles and Design System

**Status:** discovery draft; no implementation authorization.  
**Evidence base:** `apps/web`, `openapi/openapi.yaml`, API handlers and SQL migrations at `fe7ccf5`.

## Product stance

Tunnex is a dark, crimson, security-operations console. LiteLLM is a reference only for operational hierarchy, information density, compact tables, detail workspaces, contextual guidance, and staged setup. It is not a visual source: do not copy its light theme, blue controls, typography, or iconography.

## Non-negotiable rules

1. **One capability, one primary home.** Network owns topology; Access owns human/device policy; AI Agents owns agent lifecycle/runtime/MCP/JIT/templates; Settings owns deployment and organization defaults. Other screens link to the owner; they do not duplicate its editor.
2. **A list is an operator index.** It answers “what exists, what needs attention, and what can I do next?” It has breadcrumb, title/count, one primary action, URL-backed query controls, a compact status table, and row-to-detail navigation.
3. **Details have stable URLs.** Entity workspaces retain their state in the URL and retain the originating list query on Back. A modal is for a short atomic mutation, never an entity’s permanent configuration surface.
4. **Stepper only for a real external process.** A setup flow exposes prerequisites, one-time secrets, an observable wait state, completion, expiry/failure, and a safe exit. It does not disguise an ordinary form.
5. **Status explains itself.** Each status has source, timestamp/freshness window, meaning, next action, and an unknown/stale state. Colour reinforces text; it never supplies the meaning.
6. **Permission and edition are different states.** Permission-denied means the user cannot act; edition-unavailable means the deployment lacks a capability. Never render the latter as an error or sell a feature to a user who lacks its permission.
7. **Destructive impact is visible before and after.** Confirmation names affected resources and irreversibility. The success state names the result, recovery path where one exists, and links to the audit evidence.
8. **Progressive reuse, not abstraction theatre.** Extend `AppShell`, `PageHeader`, `DataTable`, `SettingsRail`/`SettingGroup`, `Modal`, `Toasts`, and `VisualGallery`. Extract a new shared primitive only after two real screens prove the same API and interaction shape.

## Shared interaction contract

| Surface | Required behavior |
|---|---|
| App shell | Current organization is visible and switchable; shell-level failure, offline, and authentication-expiry states do not masquerade as page failures. |
| Breadcrumb | Present below the global shell on nested detail/setup routes; last item is the current entity and is not a link. |
| Page header | Title, count where applicable, one-sentence operator purpose, primary action, and optional contextual status. |
| Tables | Semantic table, visible caption, sortable headers, keyset query controls, keyboard-focusable rows/links, and overflow actions that retain the row name in their accessible label. |
| Detail workspace | Header identity/status/freshness, contextual back link preserving the complete index query, tab links in the URL, action menu, and a stable activity/audit link. |
| Dialog/panel | Existing `Modal` focus trap, escape/backdrop policy, restored opener focus, explicit busy state, and no destructive submit until the impact text has rendered. |
| Feedback | `Toasts` are transient confirmation only. Durable failures/results stay in page context; every mutation supplies request-ID-aware API error copy. |
| Visual review | Add each shared state to `VisualGallery`: normal, loading, empty, error, permission denied, edition unavailable, stale/partial, and destructive confirmation. |

## URL contract

- Indexes use `?q=&status=&sort=&dir=&limit=&cursor=` plus domain filters. Cursor state is opaque, filters are validated/normalized/shareable, and totals appear only when returned by the server.
- Detail routes use `/domain/:id?tab=overview`; unknown/forbidden tabs fall back to the first permitted tab.
- The detail back link preserves the full prior index search string via `state.from` and has a deterministic domain-index fallback for direct URLs.
- Browser Back must return to the exact page, sort, and filters—not a blank default list.

## Responsive and keyboard baseline

- Desktop: dense tables and fixed information hierarchy; responsive does not remove destinations or authorized actions.
- Narrow view: table columns collapse only to a named row summary/detail disclosure; actions remain reachable; filter controls wrap without changing order.
- Keyboard: skip-to-content, visible focus, semantic headings, native buttons/links, tablist keyboard semantics, focus-trapped dialogs, and announced async status/error regions.

## Semantic visual foundation

Existing evidence is the Tailwind/UI vocabulary in `components/ui.tsx`, `index.css`, and Visual Gallery: `ink-*`, `surface*`, `line`/`hairline`, `accent-*`, `ok`, `warn`, `danger`, `rounded-*`, and `min-h-*`. Preserve these roles; do not introduce LiteLLM colours.

| Role | Rule |
|---|---|
| Canvas/surfaces | Dark ink canvas; page glow behind glass/surface cards. `surface` groups, `surface-inset` recesses, `line`/`hairline` separates. |
| Text/accent | `ink-heading` for headings/actions; `ink-body` for content; lower text roles only for metadata. Crimson semantic accent is primary/focus/selected, never the sole state signal. |
| Status | `ok`, `warn`, `danger`, `neutral`, `unknown` always pair textual cause with source/freshness. |
| Type/density | Inter body; JetBrains Mono for identifiers/commands. Existing `min-h-11` controls, `min-h-8` compact actions, 44px row target, and 2/3/4/6 spacing rhythm. |
| Radius/elevation | Existing rounded-md/rounded-card language; glass groups content, never contains a fixed overlay. |
| Icons/badges | Existing `Icon`, `StatusDot`, `Badge`; icon has an accessible label/tooltip and badge never relies on colour alone. |

### Reference screen anatomy

- **Index/list:** breadcrumb → title/count/explainer + CTA → durable notice → cursor toolbar → table → load-more/next cursor → empty/error help.
- **Entity workspace:** breadcrumb/back query → header/status/freshness/actions → URL tab rail → focused panel → related links → audit.
- **Atomic modal:** title → impact/validation → compact fields → cancel/explicit submit; destructive copy names entity and consequence.
- **Setup flow:** titled panel → numbered prerequisites → one-time secret discipline → observed wait → connected/failed/expired terminal state.
- **Settings rail:** desktop rail/content track; narrow compact selector without content reorder.
- **Dashboard priority queue:** severity/reason/entity/last observed/next action, not decorative metrics.
- **Evidence table:** compact semantic columns, URL filters, deep links.

Focus uses the existing visible accent outline; hover changes surface/border, not meaning; selected tab/row has text plus indicator. Disabled is temporary busy/unavailable only; permission actions are absent with explanation and edition is an explicit boundary. Loading, empty, partial, stale, and durable-error anatomy follows the state matrix with request ID where available.

## Held global decisions

1. **Breadcrumb data source:** decide whether API list payloads supply stable human labels or the client may use list-cache labels on detail routes.
2. **Offline policy:** decide whether mutations queue nowhere (recommended for security actions) and present explicit retry only after reconnection.
3. **Global notification retention:** decide whether high-impact server notifications need an inbox beyond existing toast/audit surfaces.
