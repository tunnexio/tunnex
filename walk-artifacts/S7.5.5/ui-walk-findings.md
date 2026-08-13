# S7.5.5 — UI walk close-out: the complete finding ledger

Founder-driven UI walk (Pawan clicks, Claude guides) over the six slice-3 features, enterprise build,
behind nginx at `http://40.65.63.141`. Backend was already wire-proven; this walk proved the SPA
renders and the human journeys complete. Findings below are the full ledger — several fixes were
applied live during the walk and are reconciled here for the record.

## Ledger

| ID | Severity | What | Disposition | Commit | Pin / re-review |
|----|----------|------|-------------|--------|-----------------|
| WF-1 | low (UX / key-retention) | Recovery-codes modal had **Copy** only, no **Download** | **FIXED** | `294ecd2` | no unit pin (pure affordance); wire-verified (file saves); inline re-review |
| WF-2 | medium (ops gap) | No first-class break-glass for a **sole-owner** MFA lockout — only raw SQL / another-admin reset | **DEFERRED (named trigger)** | — | held; substitute = another-admin AdminReset (walked) + operator DB access |
| WF-3 | **high** (blocks grandfather UI + traps enrolled users) | Forced-enroll page had **no exit**: RequireAuth routed only TO `/enroll-mfa`, never FROM it | **FIXED** | `4092761` → pinned `c9ff488` | pure-fn table pin (`resolveMfaGateRoute`, both directions incl. the WF-3 case); targeted re-review below |
| WF-4 | n/a (environment) | "Locked out of both accounts" after sign-out | **NOT A DEFECT — residue** | — | see paragraph below |
| WF-5 | **high** (data loss) | Recovery codes destroyed on forced-enroll — WF-3 redirect unmounted the one-time modal | **FIXED** | `5c16dda` | no pure pin (interaction timing); guarded by the gate-clear-on-dismiss invariant + wire-verified; re-review below |

### WF-3 — fix shape (the record)

Landed shape: **the release-redirect (continue affordance), not a dedicated forced-flow page.** The
gate's client routing was made symmetric — confine a gated user to `/enroll-mfa`, and RELEASE a
non-gated user off it. First landed inline in `RequireAuth` (`4092761`); then extracted to a pure
function `resolveMfaGateRoute(gated, pathname)` in `src/lib/authroute.ts` and **table-pinned in both
directions** (`c9ff488`, `test/authroute.test.ts`), including the exact WF-3 case
(`resolveMfaGateRoute(false, "/enroll-mfa") === "/dashboard"`). The pin fails loudly if the release
branch is ever deleted. The **reassuring comment** on `ForcedEnroll` ("RequireAuth then releases the
user to the app") is now TRUE — corrected from asserting a behavior the code did not have.

### Targeted re-review (folded React, read as hard as the code)

- **WF-3 / authroute:** confine+release symmetric; no loop — a gated user (`true`) → `/enroll-mfa` and
  stays; a non-gated user on the ceremony → `/dashboard`; a no-org user then handled by `RequireOrg`,
  not bounced back (not gated). Pure fn, pinned both directions. **Clean.**
- **WF-5 / MfaSettings:** `confirm()` no longer refreshes; the gate clears only on the recovery modal's
  `onDismiss`, so the modal is never skipped on either the forced or the Settings path. Residual edge:
  a hard reload BEFORE dismissing loses the one-time codes (`/me` returns gate-cleared → redirect skips
  the modal) — inherent to one-time display + reload, pre-existing, out of scope. Normal flow fixed.
  **Clean (edge noted).**
- **WF-1 / OneTimeSecretModal:** opt-in `downloadFilename` prop; Blob object-URL works in an insecure
  (plain-HTTP) context, matching the `legacyCopy` posture; scoped to recovery codes. No new secret
  exposure (codes are already on screen). **Clean.**

Verdict: all folds clean, no new findings. This was the FIRST interaction defect (WF-5) from the WF-3
fold; the budget rule (repeated fold-induced defects in one component → halt-and-paper) was not tripped.

## WF-4 — the lockout: environment residue, not a defect

The API log showed every `/auth/login` and `/auth/mfa/verify` from Pawan's IP returning **200** — the
server never refused a login. The "lockout" was a client/state artifact: enforce had been turned ON,
and the member account hit the **WF-3 trap**, whose only affordance was "Turn off 2FA" — clicking it
disenrolled the member (audit `mfa.disenrolled`), re-gating them; owner was enrolled and simply
retried. Compounded by stale browser state (the SPA rendered a cached authed shell over a dead cookie
after the web container was recreated). So: residue driven by WF-3 + stale client, no code defect.
Future walks avoid it by (a) the WF-3 fix (the trap no longer offers only disable), (b) a full
logout + fresh tab between state resets, (c) not conflating owner and member accounts.

## Re-walk coverage (previously-broken journeys, now observed)

- **Leg E (grandfather) end-to-end:** member (enforce ON, unenrolled) → forced `/enroll-mfa` → enroll →
  confirm → recovery modal **stays** (WF-5) showing **Download · Copy codes · I've saved it** (WF-1) →
  "I've saved it" → **auto-lands on dashboard** (WF-3). Pawan: "working as expected." Enrollment into
  the app observed.
- **Leg F:** admin-reset + the target Mailpit notification were wire-proven (`audited-mutations.md`);
  the post-reset member login lands on forced-enroll correctly (same E path, now with the exit).
- **No adjacent breakage:** web typecheck + build + **72 tests** green; every fold is additive (release
  guard, deferred refresh, download button, pure-fn extraction) — no existing behavior removed. The
  Settings self-enroll path (not gated) is unaffected: no redirect, modal dismiss just refreshes state.

## D5 clarification surfaced during the walk (SSO users)

Pawan asked whether an Entra/Google (SSO) user is prompted for a Tunnex TOTP. Answer (D5, locked):
**no** — SSO sessions are exempt; the IdP owns the second factor (Entra Conditional Access / Google
2SV). Org MFA enforcement does not gate an SSO user into enrolling a Tunnex TOTP. Enforced by
construction (gate keys on mint-time auth method; `sso` skips it — the bearer rider proved the shared
mechanism on the wire). The SSO-specific click-through remains deferred (box Entra config is a stub).
