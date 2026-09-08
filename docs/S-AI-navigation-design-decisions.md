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
