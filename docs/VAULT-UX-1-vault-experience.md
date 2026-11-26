# VAULT-UX-1 — Vault experience, access and audit fixes

Story branch `story/vault-ux-1`, cut from `origin/main` 80cd04d2 and rebased onto `origin/main` after
PR #137 (LS-UX-2) merged. This paper is commit one: every audit finding (V1–V20) is dispositioned here
before tests or product code. Existing Vault records: `S-tunnex-vault-decisions.md`,
`S-tunnex-vault-development.md`, `S-tunnex-vault-box-walk.md`. Nothing here weakens a decision in those
papers; where this story changes behaviour, the old rule and the new rule are both named.

Ground rules carried into every item:

- **Security never gets weaker.** Administrators still cannot read personal entries, by API, audit or UI.
- **Vault depends on no other feature.** It uses core identity (memberships, users, groups, sessions,
  the master-key sealer) and nothing else. The membership purge (V6) is a database trigger owned by a
  Vault migration, so tenancy code does not import Vault and Vault does not import tenancy.
- **No secret value is logged, audited or echoed.** Audit rows carry labels only, and only labels the
  reader is already allowed to see.

## Decisions

### V1 (high) — recipients must be able to use Vault

`begin()` admits a caller only with an active, verified, unrevoked membership holding `vault:use`. The
recipient picker (`Subjects`) and `validateTargets` checked membership but not the role or the verified
email, so an administrator could assign a credential to someone who can never open it.

**Locked.** One eligibility rule, evaluated in Go with `rbac.CanAny(roles, PermVaultUse)` (no role names
in SQL), shared by `begin()`, `Subjects` and `validateTargets`:
active user, not deleted, verified email, membership not revoked, organization not deleted, `vault:use`.

- `Subjects` returns only eligible users, each with name **and email** (V9).
- Groups stay assignable (a group is a standing audience), but each group reports `member_count` and
  `members_without_access` (name + email) so the picker names who will not be able to open it.
- `validateTargets` refuses an ineligible user with `400 vault_recipient_without_access`
  ("This person can't use Vault yet. They need the Vault role and a verified email.").

### V2 — recipients could rename an assigned entry

**Locked.** Changing an entry's details (title, username, service, recipient) is a *details* edit. On an
assigned entry only `vault:assign` holders may do it; on a personal entry only its owner. Recipients may
only **rotate** (save a new secret version). `VaultUpdateInput.title` becomes optional: a rotation that
sends a title different from the current one, by someone who cannot edit details, is refused with
`403 vault_details_forbidden`. The UI shows the title read-only in the rotation form. New flag
`can_edit_details` on `VaultEntry` drives the UI; `can_edit` keeps meaning "can rotate".

### V3 — audit rows only held entry id and version

**Locked.** Each Vault audit row now carries non-secret labels, with a privacy split:

| Entry | Metadata recorded |
| --- | --- |
| Personal | `version`, `kind`, `visibility` only. **No title, service or username**: organization audit is readable by owners and admins, and admins must not learn what is in someone's personal Vault. |
| Assigned | `version`, `kind`, `visibility`, `title`, `service`, `recipient_kind`, `recipient` (the same labels administrators already see in the list) |

- Reveal and copy are separate actions: `vault.revealed` and `vault.copied`. The client states the purpose
  in `VaultRevealInput.purpose`; the server cannot see a clipboard, so `copied` is **client-asserted** — it
  records the stated intent of an authorized, audited read, not proof of a paste. Both are equally
  authorized and rate limited.
- `vault.details_changed` records which fields changed (`fields`), and for an assigned entry the old and
  new recipient labels.
- `vault.service_created` records the service name (catalog names are organization-visible).
- Web: `lib/auditview.ts` gets Vault action labels ("Secret revealed", "Secret copied", …), the target
  type reads "Vault credential", the detail view renders Vault details through an allowlist (as Local
  Sharing does with `beamAuditDetails`), and the Audit Log gets Vault actions in the action picker, a
  `vault_entry` target option and a "Vault activity" quick filter.

### V4 — step-up for shared secrets, and a reveal rate limit (founder decision)

**Locked (founder).** Revealing or copying an **assigned** (organization) entry requires recent
re-authentication; personal entries need none.

- The check is the existing `requireRecentReauthentication` with its own scope `vault_reveal`. It is not
  forked, so Vault behaves exactly like the other step-up actions:
  - an account with a confirmed authenticator must have verified MFA in this session within 5 minutes;
  - an account with a local password must enter it (`VaultRevealInput.current_password`, write-only),
    with the existing failure-only budget (5 failures per 5 minutes, per scope);
  - an SSO account with neither uses a fresh IdP MFA assertion;
  - an account with none of these is refused (`reauthentication_unavailable`) and is offered authenticator
    setup inline.
- Every reveal attempt is charged to the rate limit (below) before any other work, refused ones included.
- The check runs **inside** the reveal transaction, after the entry row is locked and its visibility is
  known, so an entry cannot be reassigned between the check and the read.
- **Decide-item recorded, not changed:** for local-password accounts this means typing the password for
  every shared reveal (there is no password-freshness window in `requireRecentReauthentication`). Inventing
  one would change shared security semantics; it is left for the founder. The UI keeps the password field
  filled for the life of the open drawer so a second action in the same drawer is one click.
- `VaultWorkspace.reauthentication` (`password`, `mfa`, `available`) tells the UI what will be asked, so
  the password field is shown up front and the MFA prompt appears only when the server asks.
- UI: `current_password_required`/`invalid_credentials` show the password field with a plain message;
  `mfa_step_up_required` shows the shared inline verification (`InlineTerminalMfa`, 5-minute freshness) and
  then continues the same reveal or copy; `reauthentication_unavailable` offers authenticator setup. No raw
  error codes reach the user.
- **Rate limit:** 30 reveals or copies per person per organization per rolling minute (fixed window in
  Redis, personal and shared alike). Exceeding it returns `429 vault_reveal_rate_limited` ("You've opened
  a lot of secrets in a short time. Wait a minute and try again."). 30/min is far above human use and far
  below scripted bulk export.

### V5 — details edits created fake versions; nothing could be reassigned

**Locked.** New `PATCH /vault/entries/{entryId}` (`updateVaultEntryDetails`), metadata only, never a new
secret version. Concurrency uses a new `revision` column (bumped by every change) as `expected_revision`,
because `current_version` does not move on a details edit.

- Personal entry, owner: title, username, service (catalog or private name).
- Assigned entry, `vault:assign`: title, username, service, and **reassignment** of the recipient (user or
  group). The UI warns: "The new recipient can open every saved version. The current recipient loses
  access."
- **Visibility changes are refused** (`400 vault_visibility_change_unsupported`), and the UI says so:
  personal → assigned would expose a private history to every administrator; assigned → personal has no
  meaningful owner (the creator is not necessarily the person using it). To share a personal credential,
  add it again as Assigned. This is a deliberate safety limit, not a missing feature.
- Username is now entry metadata. Each version's sealed envelope still keeps the username it was saved
  with, as history. Revealing the current version returns the entry's current username; revealing an
  earlier version returns the username saved with it.
- Rotation (`PUT`) stays the only way to add a version.

### V6 — purge personal entries when a membership ends (founder decision)

**Locked (founder).** When a membership is removed (row deleted) or its organization access is revoked
(`access_revoked_at` set, the IdP-sync path), that person's **personal** Vault entries in that
organization, with all their versions, are deleted in the same transaction. Assigned entries they
created are untouched (they belong to the organization's audience). Deactivation is not removal — it
keeps the membership so reactivation is clean — and does not purge.

- Mechanism: a Vault-owned database trigger on `memberships` (`AFTER DELETE`, and `AFTER UPDATE` when
  `access_revoked_at` goes from null to set). It covers every present and future removal path without
  tenancy importing Vault, and it is transactional with the membership change by construction.
- Audit: `vault.personal_entries_purged`, system actor `vault`, target the user, metadata
  `{entries: <count>, reason: "membership_removed" | "organization_access_revoked"}`. No titles. Skipped
  when there was nothing to purge, and when the organization itself is being deleted.
- **Consequence named for the founder:** a directory-sync revocation that is later restored — including a
  transient IdP glitch that drops and re-adds someone — permanently deletes that person's personal entries in
  the organization. Revocation keeps the membership row by design, but Vault treats it as the end of the
  membership, as decided. There is no undo.
- A re-invited or restored person starts with an empty personal Vault. Tested on both re-entry routes
  (hard removal then re-add, and IdP revoke then restore).

### V7 — "Unconfigured password" naming and the duplicate version

**Locked.** Quick entries read "Generated password · add details" in the list (service column "Details not
added yet"), and the row action is **Add details**. Adding details is now metadata-only (V5's rule): the
entry stays at version 1 and no duplicate value is written. Entries configured before this story keep
their existing version 2 (history is append-only and is never rewritten).

### V8 — Quick generate copy and close were silent

**Locked.** The button reads **Save & copy**, with one line beneath: "Saving keeps this password in your
Vault so you can add details later." Closing an unsaved password asks first ("This password isn't saved.
Discard it?" with Discard / Keep it). Closing after it is saved needs no prompt.

### V9 — names only in the picker and history

**Locked.** `VaultSubject.email` and `VaultVersion.changed_by_email` are returned (OpenAPI + regenerated
clients) and rendered with `personLabel` ("Name (email)").

### V10 — the lone "My Vault" tab and jargon

**Locked.** The single tab becomes useful views: **All**, **Personal**, **Shared with me**, and for
administrators **Organization** (every assigned credential). Server-side `view` filter on the list. The
summary reads in plain words ("3 credentials"). Add-credential options read "Personal · only you",
"Assigned · administrators and recipients", and the service picker's free-text option "Use a private
service name".

### V11 — load failure blocked everything

**Locked.** A `403` on the list renders the shared `AdminOnlyNotice` from #137 for missing role, and a
distinct "Verify your email to use Vault" notice for `email_not_verified`. Any other load failure shows
the retry message but leaves **Add credential** and **Quick generate** available.

### V12 — Vault shown to people without `vault:use`

**Resolved by #137 plus one route gate.** #137 (merged before this branch was rebased) added
`lib/navaccess.ts` with `"/vault": ["vault:use"]`, gating the sidebar, the command palette and the member
dashboard's workspace card. This story adds no duplicate gating; it wraps the `/vault` route in #137's
`AdminOnlyRoute`, so someone arriving by URL gets the same calm notice. (Before the rebase, main had no
Vault dashboard card at all; the card is #137's.)

### V13 — "Tunnex Vault" → "Vault"

**Locked.** Sidebar, palette (same source), page title, dashboard card (#137's) and user docs read
"Vault". Historical story papers keep their names.

### V14 — backup and the master key

**Locked.** `docs/backup-restore.md` lists Vault secrets among what is unrecoverable without the master
key. **Deferred, named:** master-key versioning and rotation (re-sealing every Vault version and every
other sealed column) is separate future work — trigger: "first customer key-rotation requirement" — and
is recorded in `DEFERRAL-REGISTER.md`.

### V15 — clipboard clearing

**Locked (least-confusing variant).** About 30 seconds after a copy, Vault clears the clipboard **only if it
still holds the copied value**, and only where reading the clipboard is **already granted** to the site
(`navigator.permissions.query({name: "clipboard-read"})` returns `granted`). It never triggers a permission
prompt half a minute after the action, which would be unexplained. Where the state is `prompt`/`denied`, the
browser cannot answer (Firefox), or the page is not focused (Chromium refuses the read), nothing is cleared.
The notice is honest about it: "Clear it after use. Where this browser allows Vault to read the clipboard,
Vault clears it after about 30 seconds if it still holds this secret." The timer lives at module level so
closing the drawer does not cancel it.

### V16 — search wildcards

**Locked.** `%`, `_` and `\` in the search are escaped in Go and the query uses `ESCAPE '\'`.

### V17 — body limit versus secret length

**Locked.** Secrets stay limited to 16,384 characters (runes; existing multibyte secrets must keep
opening, so the limit is not changed to bytes). The Vault body limit rises from 64 KiB to 256 KiB, which
covers the worst case of 16,384 characters each JSON-escaped to 12 bytes plus the other fields. Over-limit
requests get `413 vault_request_too_large` ("Vault request is too large. Secrets can be up to 16,384
characters."). Tested at the maximum and one past it.

### V18 — quick request retention, and 0231's down-migration

**Locked.** `vault_quick_requests` rows older than 30 days are deleted by a leader-only hourly job (in
batches), owned by the Vault package. A retry that old is not a real client. **Documented:** the 0231
down-migration still refuses while any quick entry has no details; operators add details or delete those
entries first. That refusal protects data and is kept.

### V19 — associated data in the envelope

**Locked (low-risk path taken).** New writes use a v2 envelope: AES-GCM with associated data binding the
format, organization, entry and version, stored with a `v2.` prefix (not a base64 character, so v1 and v2
cannot be confused). v1 rows are still read. The crypto package gains `SealWithAAD`/`OpenWithAAD`;
`Seal`/`Open` are unchanged for every other caller. Tested: a v2 payload moved to another entry, version or
organization fails to open.

### V20 — end-to-end proof and user docs

**Locked.** New Playwright spec `e2e/tests/vault.spec.ts`: an admin quick-generates, adds details, assigns
the credential to a member; the member reveals it through the password step-up, cannot assign or delete
it, and the admin deletes it. User docs: `docs/vault.md` in this repo. The public docs site
(tunnex-web, a separate repository) needs a matching page; that is outside this story and is noted here.

## Extra friction found in the full pass

Found in the role-by-role pass (owner, admin, member, member in a group, ai-admin/ai-view, unverified email,
SSO account without MFA) and fixed in this story:

- E1: a rotation or details conflict (409) left the form open with a disabled Save button and the advice to
  "refresh Vault", with no way to do so from the form. The form now offers **Close and refresh**, which
  reloads the list and says why.
- E2: the delete confirmation read "all 1 saved versions"; it now reads "its saved version" for one.
- E3: every reveal failure read "Refresh Vault to check your current access". Each case now has its own
  words: wrong password, too many wrong passwords, rate limit, no authenticator, removed from the group (404:
  "no longer available to you").
- E4: copying an earlier version required revealing it first; each history row now has Copy as well as Reveal.
- E5: a rotation that omitted the username blanked it (the API treated "absent" as empty). An omitted
  username now keeps the current one.
- E6: the help disclosure ("Vault access") did not say that personal credentials are deleted when you leave
  the organization, or that shared ones ask you to confirm it is you. It is now "Who can see what" and says both.
- E7: an empty filtered view showed the generic "No credentials yet"; each view has its own empty message.
- E8: an SSO account with no IdP MFA and no authenticator could never open a shared credential and got no
  path forward; the reveal now opens the inline verification panel, which offers authenticator setup.
- E10: on a plain-HTTP install (development, or before TLS) Quick generate said "secure generation is
  unavailable": `crypto.randomUUID` exists only in secure contexts. The request id now falls back to a v4 id
  from `getRandomValues`, the same randomness source the password generator already uses. Found by the e2e run.
- E9: ai-admin/ai-view reaching `/vault` by URL saw "Could not load your Vault"; they now see the calm access
  notice (V11/V12).

Decide-item recorded during the build (not changed): a recipient rotating a shared credential may also set
its username, because the username is saved with each version. Title, service and recipient remain
administrator-only.

## Overlap with #137

#137 merged while this story was in progress. The branch was rebased on it (no stash). This story reuses
its `navaccess.ts`, `AdminOnlyNotice` and `AdminOnlyRoute` and changes only the Vault card's title text
in its dashboard list.

## Verification plan

gofmt, go vet, Go tests in open and enterprise editions on a throwaway Postgres/Redis
(`vaultux1-` prefix), migration up/down, `make generate-check`, web typecheck/build/full test suite,
Playwright `vault.spec.ts` and `users.spec.ts` against a throwaway stack. Results are recorded in the
final report.
