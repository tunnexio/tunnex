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
  same `password.Verify` primitive; each attempt consumes the existing `AllowMFAStepUp` budget so password guessing
  through this endpoint is limited to the same 5 per 5 minutes.
- MFA: when the account has a confirmed TOTP factor, the session must carry valid MFA assurance no older than 5
  minutes (the Local Sharing window); otherwise `mfa_step_up_required` and the UI runs the existing step-up.
- An account with neither a local password nor a confirmed TOTP (SSO-only, no local MFA) is refused with
  `reauthentication_unavailable` — it cannot prove recent authentication with any existing mechanism. An SSO
  login that carried a verified IdP MFA claim (`sso_mfa` assurance) counts as MFA when fresh.

**Open question for the founder:** SSO-only server administrators without local MFA cannot change this setting.
Options: accept (they enrol TOTP first), or accept fresh `sso_mfa` assurance only (already accepted), or add a
real SSO re-login step-up (does not exist today).

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

## Tests

- `serveraccess`: installation authority — env seed, saved value wins, lock forces off and refuses enabling,
  fail-closed on read error, version conflict, audit row, active sessions ended on disable (Postgres fixture).
- HTTP: non-CP-admin refused, machine/bearer refused, missing password refused, wrong password refused, stale MFA
  refused for enrolled users, CSRF/operation census lists updated.
- Agent channel: capability endpoint requires gateway identity and reflects installation AND org.
- Node: tri-state decision table; supervisor starts and stops the runtime on changes (fake poller).
- Deploy: installer still writes `TUNNEX_SERVER_ACCESS_ENABLED=false`; compose node-agent default is empty; Helm
  gateway default empty; Helm CP renders `TUNNEX_SERVER_ACCESS_LOCKED`.
- Web: Settings section renders source/lock, runs step-up, saves; Features unavailable state links to it.
