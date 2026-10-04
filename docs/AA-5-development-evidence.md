# AA-5 local development acceptance

Status: **Locally accepted** on 2026-10-03 against uncommitted `feature/app-access` work. Native publication is still disabled; positive publication and a complete served-browser journey belong to AA-6/AA-8.

## Implemented authority

The proxy registers a bounded ten-minute pending transaction before setting its host-only nonce cookie or redirecting to the console. A verified local/SSO parent can consume that exact transaction once to issue a 60-second random launch code. Redemption atomically checks the browser nonce and creates an independently hashed app token. A failed or replayed exchange creates no cookie. Successful redemption removes the code from the visible URL. Failed unsafe requests require deliberate resubmission.

App authorization rechecks the immutable active tuple, current dedicated proxy identity, parent authority, membership, explicit grant union and configured native MFA enforcement. Parent reads and passive app/stream activity never extend parent idle. Only an accepted foreground request may refresh app idle; capacity denial cannot refresh it. Persistent stream identifiers and conservative four-second leases bind renewals to the same proxy/session/tuple.

Migration 171 captures verified credential epochs in native local, MFA and SSO parents. Rehash and password change use the verified hash/epoch snapshot. Reset increments the epoch transactionally. Logout records a durable exact-parent denial before secondary Redis cleanup. Native console authentication also checks that denial and the captured epoch. Legacy console parents remain compatible only at initial epoch one and require fresh login for app handoff. Password change replaces the current parent using the committed epoch, original authentication method and original absolute deadline. If its password commits but replacement storage fails, the UI states that the password changed and offers fresh login.

The member catalog filters current granted active revisions before pagination, keeps published metadata independent of newer drafts, and exposes no origin or gateway topology. Own-session APIs return public UUID/time/app labels, enforce ownership and remain available after launch permission is lost. The UI distinguishes failed reads, unavailable parent, unavailable feature and an empty granted catalog; SSO/MFA/password-change returns preserve a validated internal app destination.

## Qualification

- Guarded owned PostgreSQL child databases plus real isolated Redis passed all 16 registry/authority tests. These cover missing/replayed pending state, wrong nonce/hostname, concurrent redemption with exactly one success, exact binding, current user/membership/grant/group/feature/entitlement changes, overlapping grant expiry, configured local-MFA gate and SSO method behavior, legacy/changed epoch denial, durable parent logout, own-session privacy and stream-capacity refusal without an idle extension.
- Actual generated public HTTP router and dedicated TLS 1.3 private listener passed pending→human launch→redeem→persisted lease tests, browser CSRF and role-loss cleanup. Positive publications are explicitly injected in disposable child databases; native publication remains empty.
- Signed fake OIDC provider and connection flows passed server-state return binding, other-browser refusal, one-time/ten-minute state boundaries, safe callback errors and captured-epoch preservation across a later credential change.
- Real password verification/reset races proved a late rehash cannot replace a reset password. MFA challenges stamped before a reset and legacy unstamped challenges are denied without consuming a recovery factor.
- Actual HTTP logout tests passed retained/restored parent denial, commit-before-failing-Redis-delete, idempotent recorded logout during outage, unconfirmed missing parent/outage failures, duplicate-cookie refusal and database failure without falsely clearing the cookie.
- Actual password-change HTTP tests passed local and SSO-method replacement cookies, original absolute lifetime, post-commit Redis-write failure with the typed fresh-login outcome, and old-parent denial.
- Affected native API race suites, full app-proxy race suite, generated private TLS client checks, scoped generator tests and Linux arm64 proxy/API builds passed. Focused web handoff, catalog, permissions, password recovery and SSO/MFA return checks passed; full web suite passed 149 files with 1,840 passing tests and two expected failures; typecheck passed.

## Rendered owned preview

The owned project remains `tunnex-app-access-aa0-1003`. A private 792,517-byte pre-171 backup was saved before the additive local upgrade. Native schema is clean 171; native serving publications and proxy credentials remain empty. The paid fixture uses actual handlers with a nonshipping ephemeral entitlement and retained CA/gateway/account data. Its current test binary SHA-256 is `014307ca890674e903015ab41021aac9b151cf6052b6f6cc4555fa3b62ccdca1`.

At `http://localhost:15174/app-access/my-applications`, the actual browser first displayed a legacy-parent fresh-login state and an empty own-session list. The Sign in again action completed durable native logout; login with the provided owned account returned to that exact page. It then displayed the available catalog with no granted published applications and no active app sessions. This is not proof of published application traffic.

Desktop and 390-pixel screenshots were inspected: `/private/tmp/app-access-aa5-parent-unavailable.png`, `/private/tmp/app-access-aa5-my-apps-desktop.png`, `/private/tmp/app-access-aa5-my-apps-mobile.png`. The mobile document width equaled its 390-pixel viewport. The gateway remained ready after the fixture update. No release, push, deployment or external infrastructure change occurred.

## Remaining qualification

AA-6 enables staged publication only after independent browser capability, current certificate, pending-channel origin proof and actual proxy/public DNS/TLS readiness. AA-7 must qualify all withdrawal triggers, safe audit/operations/packaging and restore behavior. Redis app-session deletion alone is not claimed safe against restoring stale app-session records: recovery requires a qualified durable installation invalidation procedure. Database restore, full served-browser compatibility and load/release acceptance remain AA-7/AA-8 work. AA-9 per-app step-up remains later.
