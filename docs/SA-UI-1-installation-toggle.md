# SA-UI-1: turn Server Access on or off from the dashboard

2026-11-24; local branch `story/server-access-ui-enable`, base `origin/main` 4d693d12 (v0.1.45). Not pushed.

## Problem

Server Access (browser SSH/RDP, "terminal capability") is gated per installation by the host env
`TUNNEX_SERVER_ACCESS_ENABLED`, read once at API start (`serveraccess.New(..., env == "true")`) and once at
gateway start (`apps/node/cmd/agent/main.go`). The installer writes `TUNNEX_SERVER_ACCESS_ENABLED=false`, so an
administrator who later wants Server Access has to edit `.env` on the host and restart the API and the gateway.
The Features page then only says "Unavailable" with no reason and no way forward.

## Decisions (founder, already made)

1. **Env is the initial value; a separate env is a hard lock.** `TUNNEX_SERVER_ACCESS_ENABLED` seeds the
   installation setting until a server administrator first saves it. After that the saved database value wins.
   `TUNNEX_SERVER_ACCESS_LOCKED=true` is an operator hard-off: effective capability is off, saving "on" is refused
   (`server_access_locked`), and the dashboard shows the setting as locked by the server environment. Saving
   "off" while locked is allowed (it only records intent; effective is off either way). Existing installs with
   `=false` written can enable from the dashboard.
2. **Server administrators only, with recent re-authentication, audited, immediate off.** See "Re-authentication"
   below. Every save writes an `audit_logs` row (`server_access.installation_updated`, target
   `server_access_installation_settings/deployment`, metadata `{enabled, previous_enabled, previous_source, effective, locked, version, active_sessions}` where
   `active_sessions` is the count about to be ended; each ending is then audited individually).
   Turning it off refuses new terminal sessions at once and ends every active session (reason
   `server_access_disabled`), on every API replica.
3. **Gateways follow the control plane.** Gateway env is tri-state: `true` = on (as today), `false` = this gateway
   never runs Server Access (gateway-local lock), unset/empty = follow the control plane. The gateway learns the
   effective value over its existing mTLS agent channel and starts/stops its server-access runtime without a
   restart. Compose and Helm gateway defaults change from `false` to empty.
4. **The per-organization toggle stays.** Effective for an organization = installation effective AND
   `server_access_settings.enabled` for that organization.

## Design

- Table `server_access_installation_settings` (singleton, `enabled`, `version`, `updated_by`, `updated_at`),
  migration 0243. No row = environment seed (`source: environment`); a row = `source: database`.
- `serveraccess.Service` replaces its start-time `enabled bool` with an installation authority: env seed + lock +
  database row. Reads are fail-closed (a database error is "off", never "fall back to env"), cached for at most
  one second per replica. `available()`, `Enabled()`, `Run`, `Boot` and the per-session renew check all go through
  it. `Run` (leader sweeps) keeps looping while off so a later "on" resumes sweeping without restart.
- Turning it off: the replica that served the PATCH ends every active session durably (reason
  `server_access_disabled`, each audited) and closes its local `live` streams before replying. No separate watcher
  is needed: every live terminal on every replica re-validates its authority each second through `available()`
  and the durable session row, so streams held elsewhere close within ~1–2 s.
- API: `GET/PATCH /api/v1/admin/server-access/installation` (`getServerAccessInstallation`,
  `updateServerAccessInstallation`), same authorization shape as Application domains (`requireCPAdmin` + human
  browser session), optimistic `expected_version`, advisory lock, CSRF as for every cookie PATCH.
- Gateway: new `GET /agent/server-access/capability` on the mTLS agent channel returns
  `{"enabled": installation effective AND the gateway's organization setting}`. This follows the existing
  per-feature agent endpoints (`/agent/server-access/desired-state`, `/agent/app-access/desired-state`) rather than
  the WireGuard `DesiredState` document, because the server-access runtime already polls its own endpoints on that
  channel every second and a change here must not perturb dataplane reconcile or its watch versioning. A
  supervisor in the agent polls it every 5 s, starts `serveraccess.Run`/`RunEnrollment` under a child context when
  enabled and cancels it when disabled (in-flight terminal executions are children of that context and close).
  An unreachable control plane keeps the current state (the runtime itself already fails closed without CP
  authority). The tri-state decision is a pure function with unit tests.
- Dashboard: Settings → "Server Access" section in the installation group next to "Application domains"
  (server administrators only): current effective state, source (saved / server environment), lock notice,
  switch, re-authentication step, result. Features → Server Access, when the org read fails with
  `server_access_disabled`, explains that Server Access is off for this installation and links server
  administrators to that section (others: ask a server administrator).

## Re-authentication (decision 2) — what exists and what was built

The repository has no general "recent password" step-up. What it has:

- **MFA step-up**: `POST /api/v1/auth/mfa/step-up` stamps `MFAVerifiedAt` + a trusted assurance source on the
  current session; consumers check `session.ValidMFAAssurance` plus a freshness window (Local Sharing uses 5
  minutes, Server Access sessions use the org's 60–900 s window). Attempts share a Redis budget
  (`AllowMFAStepUp`: 5 per 5 minutes per user and per session). Dashboard component: `InlineTerminalMfa`.
- **Password proof while signed in**: `ChangePassword` requires `current_password`, checked with
  `password.Verify` against the stored hash. It has no per-attempt limiter of its own.

Implementation, all in one function (`requireServerAccessInstallationStepUp`), so a different founder answer is a
one-site change:

- Password: when the account has a local password, the PATCH must carry `current_password`, verified with the
  same `password.Verify` primitive. The endpoint has its own Redis budget (`session.ReauthPasswordAllowed` /
  `RecordReauthPasswordFailure`, scope `server_access_installation`), separate from the MFA step-up budget and
  charged only by FAILED passwords: 5 failures per 5 minutes per user, after which even the correct password is
  refused (`reauthentication_rate_limited`) until the window passes. Correct re-entries never consume budget.
- MFA: when the account has a confirmed TOTP factor, the session must carry valid MFA assurance no older than 5
  minutes (the Local Sharing window); otherwise `mfa_step_up_required` and the UI runs the existing step-up.
- An account with neither a local password nor a confirmed TOTP (SSO-only, no local MFA) is refused with
  `reauthentication_unavailable` — it cannot prove recent authentication with any existing mechanism. The
  refusal tells them to set up an authenticator app (TOTP) to change this setting. An SSO login that carried a
  verified IdP MFA claim (`sso_mfa` assurance) counts as MFA when fresh (within 5 minutes).

A real SSO re-login step-up (re-authenticate at the IdP on demand) does not exist today and is **deferred** (founder
ruling below).

## Threat notes

- Enabling creates a remote-shell capability for every organization that has also opted in. Only CP administrators
  (deployment authority, `users.cp_admin`) can change it; org owners cannot. Machine, agent and bearer principals
  are refused (`human_session_required`). The CP-admin check is beside `authorize`, never inside it
  (`cpadmin_gate_test`).
- Re-authentication defeats a borrowed or stolen browser session; attempts are rate-limited.
- Every change is audited with the actor and previous value. Session terminations caused by the change are
  individually audited (`server_access.session_ended`, reason `server_access_disabled`).
- `TUNNEX_SERVER_ACCESS_LOCKED=true` lets an operator guarantee the capability is off regardless of the database
  (for example after a compromise of an admin account, or for hosts where shell access is not acceptable).
- `TUNNEX_SERVER_ACCESS_ENABLED=false` on a gateway guarantees that gateway never runs the runtime, even if the
  control plane says on. A compromised control plane can still turn on gateways that follow it — same as today
  for gateways with `=true`; the gateway lock is the mitigation.
- Fail-closed: an unreadable setting is "off" on the API; the gateway keeps its last state, but the runtime cannot
  get sessions without CP authority anyway.

## Compose trap (resolved)

Compose used one variable for both the API and the co-located `node-agent`. The installer writes `=false`, which
under the tri-state rule would have hard-locked the co-located gateway and broken decision 1. The `node-agent`
service now reads `TUNNEX_GATEWAY_SERVER_ACCESS_ENABLED` (default empty = follow); `TUNNEX_SERVER_ACCESS_ENABLED`
only seeds the API. `TUNNEX_SERVER_ACCESS_LOCKED` is passed to the API (compose, Helm `serverAccess.locked`).

## Helm single-replica fence (found during implementation)

The CP chart refuses `serverAccess.enabled=true` with `api.replicas != 1` (terminal sessions are bound to one
API process; no HA). A dashboard toggle would have bypassed that fence, so the chart now renders
`TUNNEX_SERVER_ACCESS_LOCKED=true` whenever `api.replicas != 1` (or `serverAccess.locked=true`).

## Upgrade order

A new gateway agent with an empty env asks the control plane at `GET /agent/server-access/capability`. An old
control plane answers 404, which the gateway treats as "keep current state" (off), the same as before for an
unset env. Upgrade the control plane first; gateways then follow within ~5 seconds.

## Upgrade notes (release-note text)

**Server Access can now be turned on or off from the dashboard.** Server administrators use Settings → Server
Access. `TUNNEX_SERVER_ACCESS_ENABLED` on the control plane is now only the initial value; once an administrator
saves the setting, the saved value wins. Each organization still turns Server Access on for itself in Settings →
Features.

- **New lock:** set `TUNNEX_SERVER_ACCESS_LOCKED=true` on the control plane (Helm: `serverAccess.locked: true`) to
  keep Server Access off whatever is saved; the dashboard cannot turn it on. Helm control planes with more than
  one API replica are always locked off, because terminal sessions do not support HA.
- **Gateways follow the control plane.** On a gateway, `TUNNEX_SERVER_ACCESS_ENABLED` now means: `true` always on,
  `false` never on (a gateway-local lock), unset or empty follows the control plane, with no restart needed.
- **Docker Compose:** the bundled gateway (`node-agent`) now reads `TUNNEX_GATEWAY_SERVER_ACCESS_ENABLED`
  (default empty, follow the control plane) instead of `TUNNEX_SERVER_ACCESS_ENABLED`. If you relied on
  `TUNNEX_SERVER_ACCESS_ENABLED=true` to force the bundled gateway on, it now follows the dashboard setting; set
  `TUNNEX_GATEWAY_SERVER_ACCESS_ENABLED=true` to keep forcing it.
- **Helm gateways:** the chart default for `serverAccess.enabled` is now `""` (follow). A gateway whose own values
  file sets `serverAccess.enabled: false` explicitly stays locked off after the upgrade; remove that line to let it
  follow the control plane.
- **Upgrade the control plane before gateways.** An older control plane does not answer the new capability request
  (404), and a following gateway then stays off until the control plane is upgraded.

## Founder rulings 2026-11-24

Original decisions (see "Decisions"): env is the initial value plus a separate hard lock; server administrators
only, with recent re-authentication, audit and immediate off; gateways follow the control plane (tri-state env);
the per-organization toggle stays and effective = installation AND organization.

Rulings on the questions raised during implementation ("do recommended"):

1. **Password re-authentication budget:** this endpoint gets its own limiter, separate from the MFA step-up
   budget, counting only failed passwords (5 failures per 5 minutes per user). Successful saves never consume it.
2. **SSO-only administrators:** keep the behaviour — a fresh IdP MFA (`sso_mfa`, within 5 minutes) is accepted,
   otherwise refused with a message telling them to set up an authenticator app (TOTP). A real SSO re-login step-up
   is deferred.
3. **Multi-replica Helm control planes:** keep the automatic lock (`TUNNEX_SERVER_ACCESS_LOCKED=true` whenever
   `api.replicas != 1`); those installs cannot enable Server Access from the dashboard until terminal HA exists.
4. Upgrade notes above are the release-note text for the Helm explicit-false lock, the Compose variable rename,
   the control-plane-first upgrade order and the new lock variable.

## Migration and rollback

- Up: creates the empty singleton table. No row is written, so every install keeps its current env behaviour until
  an administrator saves.
- Down: drops the table; the API falls back to env-only behaviour of the previous release.
- Rolling back the binaries to v0.1.45 ignores the table: capability returns to the env value, so an installation
  enabled only in the dashboard turns off. Gateways on the old agent with an empty env run no Server Access (old
  behaviour: only `=true` runs it).
- Gateways deployed with Helm that set `serverAccess.enabled: false` explicitly in their own values stay locked
  after upgrade (indistinguishable from intent). Remote Docker gateways installed by the dashboard command never set
  the variable and will follow the control plane. Release notes must say this.

## Local walk 2026-11-24 (tests/server-access-local harness, loopback only)

Real API + enrolled gateway + OpenSSH target in the owned harness project, browser through the Vite dev console.

- Upgrade: v0.1.45 binaries (installer defaults, gateway `false`) → branch binaries (seed `false`, gateway empty).
  Migration 243 applied; no installation row written; setting reads `source: environment`, off; gateway healthy.
- Fresh install with defaults: same view; organization read refuses with `server_access_disabled`.
- Features shows "Turned off for this installation" with the link for server administrators; the link opens
  Settings → Server Access (Source: Server environment).
- Enable from the UI: wrong password refused inline, correct password saves (Source: Saved settings), one
  `server_access.installation_updated` audit row. With TOTP enrolled and MFA older than 5 minutes the UI ran the
  step-up and then saved.
- Gateway with empty env started its runtime ~4 s after the organization was turned on, no restart. Connection
  check passed against the org CA; a browser terminal ran a command on the target.
- Turning it off (API, password + fresh MFA) ended the live terminal in the open browser immediately (reason
  `server_access_disabled`, audited), refused a new session (503), and the gateway stopped its runtime ~3 s later.
- `TUNNEX_SERVER_ACCESS_LOCKED=true`: view locked, enabling refused (`server_access_locked`), gateway stopped;
  removing the lock re-applied the saved On. Gateway `false`: `server_access_gateway_locked`, never started, and the
  control plane refused checks with `gateway_terminal_unavailable`.
- App Access endpoints answered normally while Server Access was off; Server Access ran while App Access was
  unlicensed. No dependency either way.
- Fixed from the walk: the locked view showed a green switch next to "Off" (now shows the enforced Off, disabled,
  with "Saved setting: On"); the Server Access page's installation-off notice now links server administrators to
  the setting; "0 active sessions were ended" now reads "no sessions were open".
- Follow-up (no user confusion): Sessions and recordings stay behind the installation gate while it is off — the
  workspace read carries servers, addresses and grants, so reopening it would widen what an off capability exposes.
  Instead an ended terminal asks the API and, if Server Access was turned off, says so instead of pointing at
  Sessions. Every refusal code now has a plain sentence (a locked gateway names the operator setting), session
  details show sentences instead of codes, and the MFA step-up hides "Authenticator setup" from users who already
  have a confirmed factor.

## Tests

- `serveraccess`: installation authority — env seed, saved value wins, lock forces off and refuses enabling,
  fail-closed on read error, version conflict, audit row, active sessions ended on disable (Postgres fixture).
- HTTP: non-CP-admin refused, machine/bearer refused, missing password refused, wrong password refused, stale MFA
  refused for enrolled users, no-factor refusal names the authenticator fix, repeated successful saves are never
  limited, five failures are, the MFA step-up budget is untouched, CSRF/operation census lists updated.
- Agent channel: capability endpoint requires gateway identity and reflects installation AND org.
- Node: tri-state decision table; supervisor starts and stops the runtime on changes (fake poller).
- Deploy: installer still writes `TUNNEX_SERVER_ACCESS_ENABLED=false`; compose node-agent default is empty; Helm
  gateway default empty; Helm CP renders `TUNNEX_SERVER_ACCESS_LOCKED`.
- Web: Settings section renders source/lock, runs step-up, saves; Features unavailable state links to it.
