# AI navigation, invitations and threshold fixture — local walkthrough

Date: 2026-09-09 (Asia/Kolkata). Branch: `ai-improvement`.
Decision papers: [navigation/design](S-AI-navigation-design-decisions.md),
[invitation roles](S-AI-invite-role-followup-decisions.md).
This extends [the initial navigation walkthrough](S-AI-navigation-design-boxwalk.md).

## Delivered behavior

- AI Gateway, AI Agents and MCP are separate destinations in the AI sidebar.
  Agent Model access follows Agent groups; human group grants remain in Gateway.
  `/agents/mcp?group=fixture-navigation#profiles` resolves to
  `/mcp?group=fixture-navigation#profiles`, preserving query and fragment.
- Usage, settings, model forms, agent forms and tabs use shared app colors,
  borders, spacing and control sizes. Wide model tables scroll inside their
  container instead of breaking provider names and API paths into unreadable words.
- Users & Groups has Users, Groups, Roles and Invitations. The redundant role-count
  card is removed. Invitations offer owner, admin, member, ai-admin and ai-view
  according to the inviter's authority. Only an owner can invite/resend an owner.
  Resend preserves the original role and rotates the token. Multiple roles remain
  assignable through Roles after joining.
- Migration 0151 extends the invitation-role constraint without rewriting existing
  invitations. OpenAPI Go/TS and sqlc outputs were regenerated. The rollback refuses
  incompatible AI-role invitations rather than deleting them.

## Preview and mutation boundary

Preview: `http://127.0.0.1:5180`, Docker context `colima-tunnex-sso-review`.
The identified installation project is `tunnexaiwalk0907repro4`, network
`tunnexaiwalk0907repro4_engine`. Container names end in `-cp-api` and
`-cp-postgres` (no `-1`). Labels, network membership and running state were
verified. A first guard using incorrect `-1` names failed; the corrected guard
passed before policy saves. The group had already been created through the UI.

Schema 150 clean → 151 clean was applied to this isolated preview; six users,
six memberships and zero invitations were preserved. Only its API process was
refreshed, with its existing environment and stored engine state retained.
API binary SHA-256:
`5b9e3220c1b4fc9dbcef25d7c62abb43ea42be1404f0befc0358bcc73077a6bc`.
No Docker VM or MacBook restart was needed in this follow-up.

The browser walk used task-owned tabs. No real invitation, role change, provider
key change, model creation or real-provider inference was submitted. The only
new persistent fixture is the unassigned agent group described below.

## Rendered UI coverage

Inspected actual rendered pages and screenshots, including their form/empty
states: Models, Add Model, LLM Credentials, Add Credentials, human Model access,
My models, Usage, Settings, Agents, Agent groups, Policy templates, Agent Model
access, MCP and Create profile. Checked the Users roster and invitation form.
Also inspected agent-detail Overview, Runtime, MCP, Access and Activity. Runtime
synchronization is disabled for this fixture organization, MCP has no observed
inventory, and Activity is empty; those gated/empty states are the visual evidence,
not proof of populated runtime or tool inventory.

Saved credentials are offered before provider selection. Choosing a credential
fills its provider and hides the upstream endpoint and API-key fields. Existing
model/test behavior is preserved. Invite form options include both AI roles;
the empty invitation form was cancelled without sending anything.

Compact desktop rendering was inspected at 857 × 926; website documentation and
fresh Users/invitation captures were inspected at 1280 × 720. These are browser
visual checks, not handset acceptance. Responsive contract coverage substitutes
for a handset walk until the mobile visual acceptance pass before release.

Evidence: [models](../walk-artifacts/ai-mcp-invite-design-20260909/models.png),
[usage](../walk-artifacts/ai-mcp-invite-design-20260909/usage.png),
[settings](../walk-artifacts/ai-mcp-invite-design-20260909/settings.png),
[MCP](../walk-artifacts/ai-mcp-invite-design-20260909/mcp.png),
[saved credentials](../walk-artifacts/ai-mcp-invite-design-20260909/saved-credentials.txt),
[invitation](../walk-artifacts/ai-mcp-invite-design-20260909/website-invite-ai-role.png).

## Daily USD soft threshold fixture

Retained **AI threshold UI fixture**, zero members and no agent assignment.
Its policy has exactly `openrouter/openai/gpt-4o-mini`, only the synthetic
**Engineering demo (fixture)** connection, and a final threshold of **USD 2.50**,
revision **4**. It does not change an existing agent's policy or call Azure.

Browser observations:

1. `0`, `-1` and `100000.01` disable Save; `2.5` permits it.
2. Saving `2.5` and reopening the policy preserves it.
3. Clearing the number with Select All/Backspace, saving and reopening produces
   an empty optional value. The automation's initial `fill('')` was a no-op, so
   that first attempt was not counted as blank-value proof.
4. Restored `2.5` and reloaded; the retained policy shows revision 4.

[Final fixture DOM](../walk-artifacts/ai-mcp-invite-design-20260909/threshold-fixture.txt)
and [visible threshold](../walk-artifacts/ai-mcp-invite-design-20260909/threshold-value.png).

The actual pinned Bifrost v2.0.0 binary was also exercised with fake HTTP providers
and disposable PostgreSQL databases in verified project `tunnexai0907`, container
`tunnexai0907-postgres-1`, network `tunnexai0907_default`. Synthetic pricing makes
seven tokens cost seven test USD units; this is not a real provider price.

- Below-threshold access succeeds; the internal resolver reports exactly HTTP 403
  `ai_daily_threshold_reached` once recorded spending reaches the threshold.
- The public agent credential boundary intentionally maps that to HTTP 403
  `ai_policy_denied`; the test asserts this separately. Generic 403 alone is not
  evidence of spending refusal. Editing policy scope does not reset observed cost.
- Separate native-engine tests cover concurrent and streamed accounting and its
  persistence through a graceful engine restart. A native USD 1 budget allows two
  overlapping USD 5 fixture requests, then refuses another with native HTTP 402.
  Native 402 and control-plane 403 are separate boundaries.
- No single test is claimed to combine restart, public admission and real-provider
  billing. Thresholds remain observational: accepted concurrent work may overshoot.

## Website documentation

Pulled `origin/main` with `--ff-only` in the clean existing website AI worktree
`/private/tmp/tunnex-web-ai-improvement`. It was already current: origin/main
`c785aa095c0c975b9a2eb393ae18e9fc7fe55438`, with local AI documentation commits on top.
Website docs commit: `e23eed8e0158351fbee86730e707592348b10d2d`.
The unrelated dirty `docs/gateway-enrollment` checkout in
`/Users/pawangupta/tunnex-web` was preserved.

Updated the AI Gateway guide and its missing public route, AI docs navigation,
Users/roles, groups/access policies, agents, MCP and affected setup references.
The guide includes saved-key reuse, Foundry/Claude endpoints, mode limits,
Engineering-group access, login/CLI endpoints and threshold semantics. Current
fixture-only Users/invitation screenshots replace obsolete images in that guide.
The local docs pages and links were rendered at `http://127.0.0.1:4329/docs/ai-gateway/`.

## Checks and review

Validation results are recorded in
[checks.txt](../walk-artifacts/ai-mcp-invite-design-20260909/checks.txt).
Two independent reviews covered navigation/design and invitation/threshold/docs
behavior. Dispositioned fixes were applied and re-reviewed; final review found no
remaining issue in those changes. Reviews were source reviews, complemented by
the separate browser walk above.

User visual acceptance, production private-Azure reachability and remote CI are
not established by this local fixture walk. Publication and merge are separate
from these local changes.
