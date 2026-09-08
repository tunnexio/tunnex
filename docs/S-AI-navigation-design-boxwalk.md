# AI navigation and shared design — local verification

Date: 2026-09-08 to 2026-09-09 (Asia/Kolkata). Branch: `ai-improvement`.
Decision record: [S-AI-navigation-design-decisions.md](S-AI-navigation-design-decisions.md),
paper commit `fffab33d`. This is a frontend navigation/presentation slice.

## Implemented behavior

- AI Gateway and AI Agents are siblings in the AI sidebar section. Gateway has
  addressable Models & endpoints, LLM credentials, Model access, Usage & cost,
  My models, and Settings pages. Add Model is an action within Models.
- Users & Groups contains Users, Groups, Roles, and Invitations. People/directory
  membership is separate from the agent groups in AI Agents. Both reuse the
  existing canonical group APIs and editors, with their existing permission gates.
- A configured model's Grant access action selects its exact connection and model.
  Group choices and grant rows show membership counts; group links open membership
  management. Stale model links cannot enable a grant.
- Usage and settings use the existing app surface, border, text, status, and focus
  tokens. Workspace tabs, form sizing, table typography, and spacing are consistent.
  Routed Add Model shows one title. Secret-bearing editors clear on navigation.
- Old gateway/group URLs redirect to the new homes. Vite's `/ai/` proxy matches
  the actual path boundary, allowing direct loads of the new `/ai-gateway` UI routes.

## Rendered local check

Used a separate in-app browser tab against the running preview at
`http://127.0.0.1:5180`. Original user tabs were left intact. Inspected the rendered
DOM and screenshots at 1280 × 720; no model, credential, grant, membership,
invitation, role, or setting was saved, and no inference/test request was submitted.

Verified:

1. The old `/agents/ai-gateway` URL redirects to `/ai-gateway/models`. Sidebar and
   workspace links open the expected pages; the selected section is underlined.
2. Models and credentials show the existing six models/five credentials present
   during this check. New model and credential actions remain reachable.
3. Grant access on the Azure GPT model opens Model access with that full model ID
   and its `azure` connection selected. Grant remains disabled until a user group
   is chosen. The Engineering group is offered with four users. Existing grants
   are displayed, with links to the canonical user group.
4. My models renders the authenticated inference endpoint, Copy endpoint action,
   login/CLI instructions, model selection, and call control. No call was made.
5. Usage retains its current metrics and incomplete-pricing warning. Settings
   retains its organization control and link to agent model policies. Both now
   match the app's neutral theme; the warning remains legible.
6. Agent model policies and assignments remain reachable under AI Agents → Model
   access. Agent groups contain only the two existing agent teams. Users & Groups
   shows the existing four-member people group, role assignments (including a
   combined AI-admin/member assignment), and invitation history.
7. Add Model retains eight mode choices and all saved credential suggestions.
   Cancel returns to Models. No key was entered during the check.

Screenshots: [models](../walk-artifacts/ai-navigation-design-20260909/models.png),
[model form](../walk-artifacts/ai-navigation-design-20260909/add-model.png),
[model access](../walk-artifacts/ai-navigation-design-20260909/model-access.png),
[usage](../walk-artifacts/ai-navigation-design-20260909/usage.png),
[settings](../walk-artifacts/ai-navigation-design-20260909/settings.png),
[user groups](../walk-artifacts/ai-navigation-design-20260909/user-groups.png).

## Automated checks and review

- Full web suite: **122 files, 1,469 tests passed**.
- Final cosmetic follow-up: **9 navigation tests and 92 provider/responsive
  contract tests passed**. TypeScript and production Vite build passed afterward.
- `git diff --check` passed. The build retains the existing large-chunk warning.
- Two independent read-only reviews covered navigation/group/role reachability
  and model access/editor clearing/shared styling. No actionable findings.
- New navigation coverage includes legacy redirects, exact model selection,
  stale model refusal, browser Back behavior, member-only routing, and AI-view
  restrictions. Existing responsive contract tests retain all navigation
  destinations across the five layout capability modes.

## Proof boundaries

This verifies the local web slice, not the full composite gates or remote CI.
API, OpenAPI, migrations, and engine code were unchanged, so no database or
backend deployment was performed. No push or merge was performed.

Handset rendering was not exercised in this browser session. Source review and
the responsive capability tests are a **SUBSTITUTE**, not a handset visual proof;
the named trigger is the next mobile visual acceptance pass before release.
User visual acceptance and production deployment remain separate from this check.
