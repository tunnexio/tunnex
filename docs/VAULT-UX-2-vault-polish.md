# VAULT-UX-2 — Vault polish from the v0.1.51 walk

Story branch `story/vault-ux-2`, cut from `origin/main` 174a5e0f (after VAULT-UX-1, PR #138, paper
`VAULT-UX-1-vault-experience.md`). Founder rule: audit every Vault page, state and role again and fix
everything found in one branch. This paper is commit one; tests follow, then code.

Ground rules carried over unchanged from VAULT-UX-1: security never gets weaker (administrators still
cannot read personal entries by API, audit or UI); Vault depends on no other feature; no secret value is
logged, audited or echoed.

Scope boundaries: `story/rbac-0` owns people management and role gating, `story/ls-ux-4` owns Local Sharing
web. Changes to the shared Audit Log page are kept to the Vault filter so the two branches merge cleanly.

## Walk findings (W1–W6)

### W1 (high) — "Vault activity" misses Vault events

The quick filter sent `target_type=vault_entry`. Vault writes three target types: `vault_entry`
(credential events), `vault_service` (`vault.service_created`) and `user`
(`vault.personal_entries_purged`, written by the membership trigger in migration 0245). The audit API
matches one exact target type and one exact action and pages by keyset, so the browser cannot OR filters
together without short pages and a wrong "next" flag, and a list of target types would still either miss
the purge row or pull in unrelated `user` events.

**Locked.** The audit API gains one optional filter, `action_prefix` (`^[a-z][a-z0-9_]*\.$`, at most 64
characters), matched with `starts_with(action, prefix)` so no LIKE metacharacter can widen it. It composes
with every existing filter and with the member self-scope (members still see only their own rows). The
"Vault activity" button sends `action_prefix=vault.` and no target type, so every current and future
`vault.*` action is included by construction. The action suggestions still come from the one
`VAULT_ACTION_LABELS` list, and a test checks that every `vault.*` action the API or its migrations write
has a label there, so a new action cannot ship unlabelled.

The applied prefix shows in the Action field as `vault.*` (labelled "All Vault activity"), so the person can
see and clear what is applied; typing `<family>.*` there applies the same prefix filter.

Local Sharing's button has the same shape of bug (`beam.policy.updated` is not a `beam_share` row). The fix
is a one-line switch to `action_prefix=beam.`, but it changes which events Local Sharing reviewers see, so it
is **deferred to `story/ls-ux-4`**, which owns that surface, and recorded here so it is not lost.

This is the one change outside the Vault packages (`openapi`, `audit_logs.sql`, the tenancy filter struct,
the audit handler). It is additive: no existing parameter changes meaning.

### W2 — the Access column named a person without their email

`VaultEntry` carried only `subject_name`, already collapsed to name-or-email, so the list could not show
"reviewer (reviewer@tunnex.io)".

**Locked.** `VaultEntry` gains `subject_email` (user recipients) and `subject_member_count` (group
recipients, counted exactly as the recipient picker counts `member_count`, so picker and list agree). Who
sees them: anyone who can already read the entry — administrators, and recipients (a user recipient sees
their own email; a group recipient sees the group's size). No new person becomes visible to anyone. One label
function renders the recipient everywhere it appears: the list Access cell, the detail drawer's Access fact
and the Change secret summary — `Name (email)` for a person (`personLabel`), `Group · N members` for a group.

### W3 — the generated secret rendered as a grey block

After **Generate password** the hidden Secret field filled with a solid light block. The field is
`type=password autocomplete=new-password` inside the dark theme; a filled password field takes the browser's
autofill / password-manager decoration, which paints its own background and text colour over ours.

**Locked.**
- The secret inputs (Add credential, Change secret) keep `type=password` while hidden — a browser that ignores
  every hint still masks the value — and are styled through a Vault-scoped rule that pins the normal input
  background and text colour in the `:autofill` / `:-webkit-autofill` states, so hidden reads as dots in the
  normal field and **Show secret** reveals it.
- They carry the password-manager opt-outs (`data-1p-ignore`, `data-lpignore`, `data-bwignore`,
  `data-form-type="other"`): a Vault secret is not a login for this site, and a manager must neither fill the
  operator's own control-plane password into it nor offer to save the secret against the control-plane
  origin. Security is stronger, not weaker.
- jsdom cannot show paint, so the proof is a browser check on a local stack (recorded under Verification),
  plus a unit test that the attributes and the scoped class are present on both forms.

### W4 — no visible page heading

Vault uses `PageHeader navigationTitle`, which renders a screen-reader-only `<h1>`. That is the app pattern
for every workspace in the navigation: Local Sharing, Server Access, App Access, Gateways, Users & Groups,
Devices, Kubernetes scopes and others all do the same — the selected sidebar item names the page.

**Locked: no change.** Making only Vault's heading visible would make it the odd one out in its own
navigation group. If the app adopts visible page titles, that is a shell-wide change (one `PageHeader`
switch), not a Vault one. The accessible `<h1>Vault</h1>` stays, and the e2e locator keeps passing.

### W5 — a separate Search button

Local Sharing filters as you type (300 ms debounce, Enter applies at once, no Search button). Vault had an
input plus a Search button.

**Locked.** Vault matches: the server-side search runs 300 ms after typing stops; Enter applies immediately;
the Search button goes. The query stays in the URL (`?q=`) but debounced updates **replace** the history entry
instead of adding one per pause, and a URL change from outside (Back/Forward) still updates the field without
overwriting what the person is typing. While a search is loading the current rows stay on screen (marked busy)
instead of flashing "Loading credentials…" on every keystroke. Clear search stays.

### W6 — Quick generate opened as a short panel

Four Vault-only CSS rules pinned the Quick generate drawer to the top right at content height.

**Locked.** The rules go, so Quick generate is the same full-height right drawer as Add credential and Add
details. Its actions become the standard buttons (Regenerate, Close, Save & copy — names unchanged).

## Full pass (F1–F10): admin, member recipient, member without access, AI view

| # | Finding | Disposition |
| --- | --- | --- |
| F1 | Step-up note said "your password and a recent two-factor check" whenever MFA was required, even for an account with no local password (SSO), and said nothing useful when the account had no way to re-authenticate. | **Fix.** The sentence is built from both flags: password and MFA → "your password and a recent two-factor check"; password only → "your password"; MFA only → "a recent two-factor check"; `available=false` → "Set up an authenticator app before you can open shared credentials." |
| F2 | "Shared with me" empty state offered "Add your first credential", which creates a *personal* credential — wrong promise on that tab. | **Fix.** No add action on Shared with me; Personal offers "Add a personal credential"; All and Organization keep "Add your first credential" / "Add credential". |
| F3 | Search empty state's button said "Clear filters" while the toolbar says "Clear search". | **Fix.** One name: "Clear search". |
| F4 | A success notice ("Credential saved.") stayed on screen after switching view or paging. | **Fix.** Switching view clears it, as a search already did. |
| F5 | Detail drawer Access fact and Change secret summary named the recipient without email or group size. | **Fix** with W2's shared label. |
| F6 | Member without the Vault role: navigation hides Vault and a direct `/vault` shows "Vault is managed by organization admins". | **No change.** Correct and calm; role gating belongs to `story/rbac-0`. |
| F7 | AI view (AI administration roles without `vault:use`): same as F6 — nav hidden, direct URL refused calmly. | **No change.** |
| F8 | History paging: Previous/Next disabled correctly at the ends; paging conceals any revealed value. | **No change.** Covered by existing tests. |
| F9 | Delete confirm: names the credential, the version count and "for every recipient" on shared entries; a stale version refuses with a refresh instruction. | **No change.** |
| F10 | Errors: list failure keeps Add/Quick generate available; reveal errors map to plain sentences; stale saves offer Close and refresh. | **No change.** |

## Verification plan

- Web: typecheck, build, full vitest (`LANG/LC_ALL=en_US.UTF-8`, `TZ=UTC`).
- Go: `internal/vault`, `internal/http` (audit handler) and `internal/tenancy` for both editions; DB-backed
  tests against a `vaultux2-` stack.
- `make generate-check` (OpenAPI and sqlc change).
- Real stack (`vaultux2-` compose project): `e2e/tests/vault.spec.ts`, plus a browser check of W3 and W6.
