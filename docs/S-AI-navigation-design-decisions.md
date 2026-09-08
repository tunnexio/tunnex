# AI navigation and shared design — 2026-09-08

The user approved the read-only navigation recommendation and requested matching
colors, theme, and design across every AI workspace.

## Locked scope

- Give AI Gateway and AI Agents sibling entries in a dedicated AI sidebar section.
  Gateway pages have direct routes for models, credentials, model access, usage,
  My models, and settings. Add Model is an action within Models, not another
  navigation level. Preserve old gateway and group links with redirects.
- Put people and directory groups in Users & Groups, alongside users, role
  assignments, and invitations. Agent groups remain with AI Agents. Reuse the
  existing group APIs and editor, filtering each workspace to its own group kind.
  Directory ownership, permission gates, and mutation semantics stay intact.
- Grant access from a model row by opening Model access with that exact connection
  and model selected. Show group membership counts and links to membership management.
  One canonical group is shared by model grants and network rules.
- My models is the ordinary member destination, with existing login-authenticated
  model calls and copyable endpoint/CLI information. AI roles do not confer model
  inference grants or organization membership administration. Combine existing
  role permissions for UI gates; add no new permissions or API contracts.
- Reuse shared tabs, cards, controls, semantic colors, and typography. Replace the
  separate blue/cyan usage/configuration palettes. Preserve usage data, chart
  interactions, settings, agent policies, credentials, and test behavior.
- Use URL navigation so refresh, Back, and links retain the selected workspace.
  Keep controls accessible at narrow widths. Clear secret-bearing editors on
  navigation; do not save or call a real provider during visual verification.

## Verification and boundaries

Exercise redirects, group-kind isolation, exact model grant selection, combined
role gates, and back/forward routes. Run the full web typecheck/test/build gate,
then inspect the local rendered pages, including usage, settings, forms, and
narrow layout. Review the diff with independent finders at the end.

This slice changes web navigation and presentation only. No database migration,
provider credential changes, group membership changes, cloud operations, engine
changes, push, or merge. Existing local preview is used for visual proof.

## Navigation and visual follow-up — 2026-09-09

The user asked us to choose and implement the clearer position for agent model
access and MCP, and to re-review every AI page for consistent design.

- Keep automated-agent model policies under AI Agents; put Model access directly
  after Agent groups, before Policy templates. Human group grants stay in AI Gateway.
- Give MCP its own AI sidebar destination at `/mcp`. Reuse the existing profile,
  endpoint, assignment, and impact workflow without adding a new server feature.
  Agent detail retains its contextual MCP tab and links to the shared workspace.
- Preserve `/agents/mcp` bookmarks, group/profile queries, and hashes through a
  redirect. Keep agent group management links explicit and correctly labeled.
- Inspect Gateway, Agents, and MCP pages and their empty/form states for matching
  spacing, alignment, typography, colors, and narrow layouts. Prefer the existing
  shared components and responsive styles over a separate AI design system.

Review disposition within the user's authorized design-consistency request:
apply the three P3 findings before final visual verification: remove the Agents
rail's competing size override, match provider form controls to shared control
sizes, and restrict credential metadata spacing so model IDs align with their row.

Rendered review: the existing model-table override already removed model-code
margins, so the earlier reported row offset was not reproduced. At 857px, provider
names and API paths did break inside words; preserve readable columns and use the
existing table scroll container. This is a layout-only correction. Metadata
spacing is now scoped to metadata. The independent follow-up review found no new
CSS/navigation issue.

## Authorized threshold fixture verification

The user additionally requested fixture data for Daily USD soft threshold.
Exercise blank, positive decimal, invalid limits and reload persistence in the
local UI using a clearly named, unassigned agent group. Run synthetic-cost native
engine and disposable PostgreSQL tests for below/at-threshold authorization and
spend persistence. No external provider inference or real credential change is
needed. Keep the named UI fixture available for the user to inspect.

Threshold verification review: within the requested fixture test, require both HTTP 403 and `ai_daily_threshold_reached` in the native-accounting and policy-edit tests. A generic 403 could be an unknown-price refusal and is insufficient evidence. No admission behavior changes.

The agent credential boundary deliberately maps resolver failures to public `403 ai_policy_denied`. Preserve that established behavior; assert the exact `ai_daily_threshold_reached` reason at the policy resolver, and the public refusal separately. The pinned-native ledger test asserts the exact internal reason.

Final review disposition (within requested completion/testing/docs scope): register rollback before the threshold assertion so a failing test releases its isolated DB; restore text-only/no-tool and output limits in the website agent API guide; clarify saving credential scope never grants callers access. These are correctness fixes with no product protocol or permission changes.
