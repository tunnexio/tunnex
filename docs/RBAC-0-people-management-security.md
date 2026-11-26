# RBAC-0 — people management must not let an admin act on owners or across organizations

Story branch: `story/rbac-0`. Founder-approved scope from a read-only audit of people management.
Every finding below was re-verified in code before a fix was chosen; where the audit was wrong or
incomplete that is recorded against the item. Decision-first: this paper is commit one, the failing
tests are commit two, the code follows.

Principles that bound every decision (product principles, `CLAUDE.md`):

- **Security only gets stronger.** No fix may reopen something to close something else.
- **One-click upgrades.** The migration is additive (nullable columns plus a backfill). It never
  rewrites a role and is safe on existing data.
- **Features stay independent.** No fix makes one feature depend on another being enabled.
- **No user confusion.** Every new refusal has a plain-language message that says what to do
  instead, and the dashboard explains or hides an action rather than letting it fail.

## Findings and decisions

### D1 — Invitations could replace any member's roles, including the sole owner (HIGH) — FIXED

**Verified.** `invites.Create` accepted any email, including one that already had a membership.
`Accept` is public, attached the invitation to an existing account with no password, and wrote the
membership with `UpsertMembership` (`ON CONFLICT DO UPDATE SET role`). The migration-0152 trigger
then replaced the member's primary role. So an admin could invite the sole owner's address as
`member`, open the link (the raw token comes back to the admin), and demote the owner. This bypassed
`CanManageMembership` and `guardLastOwner`.

**Decisions.**

1. **An existing member cannot be invited.** Create and resend refuse an email that already has a
   membership row in the organization, active or deactivated. The 409 `already_member` says: "…is
   already a member of this organization. Change their roles on the Users page instead." A
   deactivated member gets the reactivate wording instead.
2. **Accepting never changes an existing membership.** Accept inserts with `ON CONFLICT DO NOTHING`
   (`InsertMembershipIfAbsent`). If a row already exists the accept is refused with `already_member`
   and the transaction rolls back, so roles are never lowered or replaced and a deactivated
   membership is never silently restored.
3. **An existing account must be signed in to accept.** When the invited address already has an
   account, the request must carry a session for *that* account. If it doesn't, it gets
   `sign_in_required`, or `invite_account_mismatch` when someone else is signed in. The accept page
   sends the person to sign in and brings them back. Holding the token is no longer enough to attach
   anyone's account to an organization. New accounts are unchanged: the token creates them, which is
   how a person first joins.
4. **The raw token reaches the admin only when the email did not leave.** `invite_token` is returned
   only with `delivered: false` (no SMTP, or delivery failed). That is the one case where the admin
   has to hand the link over themselves. When the email is delivered, only the inbox has the link,
   so "accepting verifies the email" is true again on deployments that send mail. The dashboard
   shows "Invitation emailed to …" in that case.
   *Residual (recorded):* on a deployment with no SMTP the admin necessarily holds the link and
   could set the password of a brand-new account. Point 3 means this can no longer take over an
   existing account. A new account gets only the role the admin could grant anyway.
5. **Owner invitations only by owners.** This was already true (`authorizeInvitationRole` calls
   `CanManageMembership(actor, "", role)`). It is now pinned by a regression test.

**Extra finding (same class), fixed.** SSO JIT `ensureMembership` checked `GetMembership`, which
excludes revoked rows, and then called `UpsertMembership(..., member)`. An SSO login by a member whose
access had been revoked therefore rewrote their role to `member`, demoting an owner, without
restoring access. It now inserts only if absent. `UpsertMembership` remains in use only for org
creation, bootstrap and the deployment-administrator grant, all of which mean "set this role".

### D2 — Admin MFA reset acted on any user id, across organizations (HIGH) — FIXED

**Verified.** `AdminResetMfa` checked `mfa:manage` in the caller's org, then `revokeAllMfa(target)`
ran for any user id: a non-member, a member of another org, or an owner.

**Decisions.** In the reset transaction:

- The target must be an active member of the caller's org. Otherwise the result is a 404
  `member_not_found`, with no existence oracle.
- The caller cannot reset their own factor here (409 `self_reset`). That goes through account
  settings.
- Only an owner can reset an owner's factor (403 "Only an owner can reset another owner's two-factor
  authentication.").
- A deployment administrator's (`cp_admin`) factor can be reset only by another deployment
  administrator. That is the cp_admin path, and nothing else can reach it.
- The reset requires step-up (D9) and stays audited (`mfa.admin_reset`, with the actor role in the
  metadata).

### D3 — Deactivate/reactivate skipped owner rules and acted deployment-wide (HIGH) — FIXED

**Verified.** `DeactivateMember` had no actor-role check, so an admin could deactivate an owner. The
only guard was "sole owner of some org". The act flipped `users.status`, which locks the person out
of every organization, so an admin of org A could lock a member of A out of org B where they are an
owner. `ReactivateMember` flipped the status back regardless of who had deactivated the person,
including directory sync (IdP deprovisioning) or another org.

**Decisions.**

0. **People act on active memberships only; sync may act on a retained one.** A person deactivating a
   membership that is already revoked here gets `member_not_found`, which was the existing rule. Sync
   may still act on a retained, revoked row, which is the existing directory flow.
1. **Relational rules.** Deactivate and reactivate apply `CanManageMembership(actor, target, "")`:
   an admin cannot deactivate or reactivate an owner. Last-owner: deactivating an *active* owner is
   refused when they are the org's only active owner. The check runs inside the transaction under the
   org lock (`LockMembershipOrganization`), so two concurrent deactivations cannot both pass.
2. **Scope.** A person's deactivation is **organization-scoped** (the membership's
   `access_revoked_at`, which roughly 30 queries already enforce) when **either**:
   - they have an active membership in any *other* organization, **or**
   - they are a deployment administrator.

   Otherwise it is **account-wide** as before (`users.status`, CLI credentials, sessions). That is
   today's behaviour for the common single-org deployment, and it stays.
   *Rationale:* an org's admins have authority over that org, not over the person's other tenancies.
   A deployment administrator must never be locked out of the deployment from an org seat. Changing
   account-wide status for someone in other orgs is left to a deployment administrator. They can
   still remove access org by org, and an account-wide control for them is deferred (see Deferred).
3. **Directory sync follows the same rule.** One org's directory sync disabling a user used to
   deactivate them account-wide, a cross-org effect from another tenant's IdP. It now uses the same
   scope rule.
4. **Provenance is recorded** so reactivation can tell whose act it is reversing. Migration 0246 adds
   two things. On `memberships`, `access_revoked_source` (`member_admin` | `idp_sync`). On `users`,
   `deactivation_source` (`member_admin` | `idp_sync`) and `deactivated_by_org_id`. The backfill sets
   existing revoked memberships to `idp_sync`, their only previous writer. Existing deactivated users
   are backfilled from their latest `user.deactivated` audit row: `idp-sync` actor gives `idp_sync`,
   anything else gives `member_admin`, plus that row's org. With no audit row the fields stay NULL
   (legacy).
5. **Reactivation reverses only this org's own act**:
   - An org-scoped `member_admin` revocation in this org is restored.
   - An account-wide `member_admin` deactivation made from this org is reactivated.
   - **Directory sync's deactivation is never reversed by a person.** The refusal is 409
     `directory_managed`: "Directory sync removed this person's access because they are disabled or
     removed in your identity provider. Re-enable them there; the next sync restores access." To make
     that sentence true, sync's re-grant path now restores only `idp_sync`-sourced revocations and
     deactivations, through one tenancy seam that also restores OpenVPN certificates and rebuilds the
     CRL. Sync previously cleared *any* revocation on re-grant, which would have silently undone an
     admin's org-scoped deactivation. It is licence-gated like every other sync grant.
   - **Another org's deactivation** is refused (409 `deactivated_elsewhere`: "…was deactivated by
     another organization. Ask a deployment administrator."). Legacy rows with unknown provenance
     follow the same rule: reactivation is allowed when this is the person's only organization,
     otherwise only a deployment administrator acting as a member of this org may reactivate.
6. **Machine credentials die with org-scoped deactivation too.** *Extra finding:*
   `GetMachineOwnerStanding` checked only `users.status`, and its comment said "removed-from-org is
   not a reachable state". `RevokeOrgAccessBySync` already reached it, so a directory-removed owner's
   GitOps credential kept working. Standing now also requires an active membership in the
   credential's org.
7. **The roster says what is true per org.** `ListOrgMembersWithUser` returned `users.status`, so a
   member whose access in this org was revoked showed as *Active*. Status is now derived per org, and
   a new `deactivated_by` field (`organization` | `directory` | `other_organization`) lets the
   dashboard explain why Reactivate is unavailable.

### D4 — The GitOps operator token could switch Zero Trust off and edit groups (MEDIUM) — FIXED

**Verified, and wider than reported.** `RoleOperator` held `policy:manage`, which gates more than
rules. It also covers the Zero Trust mode, group create/update/delete and membership, resources,
rule enable/disable, grant extension, IdP-sync configuration and group mapping, Kubernetes scope
creation and agent template application. The operator calls only `POST/DELETE /policies` plus
reads (`apps/operator/internal/cp/client.go`).

**Decision.** A per-feature permission, as the RBAC rules require: **`policy_rule:manage`** gates
creating and deleting a policy rule and is held by owner, admin and operator. **`policy:manage` is
removed from the operator.** Every other `policy:manage` route therefore refuses the machine by
construction, without a per-route deny list to maintain. The operator's TunnexGrant flow keeps
working (pinned by test). Humans are unaffected because owner and admin hold both permissions.
*Residual:* a grant is an allow rule, so the operator can still author broad rules. That is its job
(S10.2 D3) and is attributed to the machine actor in audit.

### D5 — Mutations gated only by `org:view` skipped the verified-email gate (LOW) — FIXED

**Verified, partly.** `CreateDevice` and `ExportOVPNProfile` already checked a verified email inside
the handler, so the audit over-reported them. The real gaps were `UpdateDeviceMode`,
`UpdateAgentProfile`, `CreateAgentAccessRequest`, `StartAgentMCPOAuthConnection`, and revoke/remove
of *someone else's* device.

**Decision.** One helper, `authorizeMutation(ctx, org, perm)`: `authorize` plus the verified-email
rule even when the permission is a read. Machines stay exempt, as in `authorize`. It is applied to
`UpdateDeviceMode`, `UpdateAgentProfile`, `CreateAgentAccessRequest` and
`StartAgentMCPOAuthConnection`. Revoking or removing *someone else's* device now requires a verified
email. `CreateDevice` and `ExportOVPNProfile` keep their existing in-handler check, which was already
correct and carries a more specific message. The edition-order guard test recognises the new helper
as a permission gate.
**Deliberately not gated:** revoking or removing *your own* device, cancelling your own access
request, and device health reports. These reduce your own access or report facts about your own
device. Blocking them for an unverified account would make things less safe, because a lost laptop
could not be cut off. First-device enrollment is unchanged: `CreateDevice` already required a
verified email.

### D6 — `CountOwners` counted revoked and deactivated owners (LOW–MED) — FIXED

`CountOwners` now counts owners whose membership is not revoked and whose account is active and not
deleted. The same definition is used by `CountOrgsWhereSoleOwner`, the role-change guard, deactivate
and the cp_admin grant. A dead owner can no longer satisfy the last-owner guard. The dashboard's
owner count mirrors it.

### D7 — cp_admin `GrantOrgRole` accepted machine roles → 500 (LOW) — FIXED

It now validates with `NormalizeHumanRoles` and returns 400 `invalid_role` for `operator` and
`agent`.

### D8 — Agent JIT approval allowed self-approval (LOW) — FIXED

Approval is refused when the approver is the requester (403 `self_approval_forbidden`: "You
requested this access, so another administrator must approve it."). The check runs in the approval
transaction after the row lock.

### D9 — Step-up for the dangerous people-management verbs — ADDED

Recent re-authentication (the existing `requireRecentReauthentication`: current password if the
account has one, plus MFA within 5 minutes if it has a factor or an IdP-asserted MFA) on:

- role changes (`PUT …/role`, `PUT …/roles`), which covers granting or transferring ownership;
- deactivate;
- admin MFA reset of another member;
- minting a machine credential;
- the cp_admin org-role grant.

Each request body takes an optional `current_password`. Deactivate and MFA reset had no body. A
bodyless call still works on the wire, because the router's empty-body shim now covers those two
routes, so an old client gets the clear step-up error and not a decode failure.

The step-up runs **after** the relational checks (membership, owner rules, last owner). An admin is
never asked for a password and then refused for a reason that did not need one. `/me` now reports
`reauthentication` (password / mfa / available), so the dashboard asks for the password up front and
handles `mfa_step_up_required` inline with the existing `InlineTerminalMfa`. Bulk deactivation runs
sequentially and pauses for one MFA prompt.

*Consequence (recorded for upgrade notes):* these verbs now need a browser session. A CLI bearer or
machine token cannot change roles, deactivate or reset MFA. Neither the CLI nor the operator calls
them. An SSO-only admin whose IdP does not assert MFA and who has no authenticator app gets
`reauthentication_unavailable` with the instruction to set up an authenticator app. This is the same
rule as every other step-up action in the product.

### Scan for other admin-on-owner / cross-org paths

| Path | Finding | Disposition |
|---|---|---|
| Invite resend | Re-mints for a pending invite; owner role re-checked (`authorizeInvitationRole`) | Already-member refusal added (D1) |
| Invite revoke | Org-scoped by email; cancels only pending invites | OK |
| SSO JIT join | Role rewrite of revoked member | Fixed (D1 extra) |
| SSO link (`linkSsoConnection`) | Self-link only; requires a verified session user | OK, no change |
| Directory sync deprovision | Account-wide from one org | Fixed (D3.3) |
| Directory sync re-grant | Cleared any revocation, including an admin's | Fixed (D3.5) |
| Machine owner standing | Ignored org-scoped revocation | Fixed (D3.6) |
| Machine owner assignment | `machine:manage` (owner-only); owner must be a verified member | OK |
| Session revoke of others | No org-admin endpoint exists; sessions die only via account-wide deactivation | OK |
| `RemoveMember` | No HTTP endpoint; already applies `CanManageMembership` + last-owner | Uses the fixed active-owner count |
| cp_admin grant | Machine roles → 500 | Fixed (D7); step-up added (D9) |

## Tests (red first)

Each attack in D1–D8 has a regression test that fails on `origin/main` and passes after the fix:
admin demotes the sole owner via invite; token-only accept of an existing account; owner invite by an
admin; cross-org MFA reset; admin resets an owner; admin deactivates an owner; deactivate in A locks
the person out of B; reactivate reverses directory sync; reactivate reverses another org; dead owner
satisfies the last-owner guard; operator flips Zero Trust or edits groups (plus the operator's own
rule create/delete still working); unverified mutations; machine role via cp_admin; self-approval;
role change without step-up.

## Upgrade notes

- Migration **0246** is additive. It adds nullable columns and a CHECK that only constrains the new
  columns, and backfills from data that already exists. It does not touch roles or status. The down
  migration drops the columns.
- Behaviour visible after upgrade:
  - Members whose access was revoked by directory sync now show as *Deactivated* (directory), not
    *Active*.
  - The invite dialog no longer shows a link when the email was delivered.
  - Role changes, deactivation, MFA reset and machine-credential minting ask the admin to confirm it
    is them.
- The GitOps operator needs no change: its permissions shrink to exactly the calls it makes.

## Folded during the build

- Accepting an invitation checks its state before sign-in. A consumed, revoked or expired invitation is
  `invalid_invite`, and the sign-in check runs before the single-use transition. So a refused attempt
  never consumes the invitation, even without a transaction.
- When directory sync restores a membership, it also re-issues the OpenVPN certificates that the
  deprovisioning revoked in that org. The restore goes through the `RestoreForSync` seam for every person
  the directory lists as active. Only an `idp_sync` act is reversed. It is licence-gated.
- The "renewed but not sent" resend message now tells the admin to revoke and re-invite to get a link.
  The old message pointed at the invitations list, which never carries tokens.
- The deactivation dialog states that a person in other organizations loses access to this one only. The
  machine-credential number is now worded "up to", because the roster counts credentials across every
  organization and an org-scoped deactivation stops only this org's credentials.

## For the founder's disposition (decided provisionally, flagged)

1. **No self-approval (D8) in a single-administrator org.** The sole owner cannot approve their own
   agent's JIT request. They can still grant the access directly with a policy rule, which needs
   `policy:manage`. If that friction is unwanted, the alternative is "self-approval allowed only when no
   other approver exists", which weakens separation of duties.
2. **Step-up needs a browser session (D9).** CLI bearer tokens can no longer change roles, deactivate,
   reset MFA or mint machine credentials. Neither the CLI nor the operator does this today.
3. **Sync now reactivates (D3.5).** A directory-deprovisioned person whom the directory lists as active
   again is restored by sync. This replaces "an admin reactivates them", which could also reverse a
   deprovisioning that was still current.
4. **Reactivation has no step-up.** It was not in the requested list. It only reverses this org's own act.

## Deferred (named triggers)

- **Account-wide deactivate/reactivate of a multi-org person by a deployment administrator** (a
  `/admin/users/{id}/status` surface). Trigger: the first deployment-administrator people screen.
  Until then such a person can be removed org by org, which is strictly safer than today.
- **Resend when delivery fails** still cannot show a link (the list never carries tokens). The
  message points at revoke + re-invite. Trigger: the next invitation UX pass.
