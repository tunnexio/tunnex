# F11 — Alerting: notification destinations, owner-configured

**Commit-one is paper.** Decide-items below are dispositioned before product code. Rejected
alternatives stay in the paper so they are findable later.

---

## Context

Tunnex computes rich health state and writes a thorough audit log, and **tells nobody**. When a gateway
stops reconciling, a site link drops, a licence lapses or a device is revoked, the only way anyone finds
out is by opening the app and looking.

Today that gap is assumed to be Prometheus's problem. `nodes/fleethealth.go:18-20` — the doc comment on
`FleetHealthCounts` — literally reasons about *"an alert on `site_link_down > 0`"*, and its only consumer
is the `tunnex_gateway_policy_health` gauge (`metrics/metrics.go:49-50`). That works for the operator of
a single deployment. It does not work for **per-tenant** alerting: an org admin cannot be given scrape
access to the control plane's metrics, and a SaaS deployment cannot route one Alertmanager per customer.
Per-tenant alerting is precisely the part Prometheus cannot do, which is why this belongs in the product.

**Outcome:** an org owner picks destinations (Slack, Teams, PagerDuty, Opsgenie, Discord, Google Chat,
generic webhook, email), chooses **per destination** which events go there, and can prove it works.

## Scope ruling: LEAN

Lean means: no new infrastructure that a reconciler can already do, no refactor of code this feature does
not own, and the smallest primitive that actually closes the security hole. Each departure from "lean" in
this paper is named and justified.

---

## What already exists (measured, not assumed)

| Need | Status today | Evidence |
| --- | --- | --- |
| Health event vocabulary | **Exists, typed** — `PolicyDegradedKind` enum + `transitionTable` + pure `degradedKind()` projector | `nodes/policyhealth.go:14-100,184,217` |
| Per-org health computation | **Exists** — walks every org already | `nodes/fleethealth.go:32` |
| Email transport | **Exists, clean seam** — `Mailer.Send(ctx, Message)`, hard-fails `ErrNotConfigured` with no SMTP | `mail/mail.go:82-86,143-155` |
| Sealed per-org secrets | **Exists** — `Seal`/`Open`/`Fingerprint`; `sso_configs` is the reference shape | `crypto/aesgcm.go:36-96`, `0005_sso_configs.up.sql` |
| Org-level opt-in toggle | **Exists as a convention** — boolean column on `organizations`, never a side table | `0044_org_ovpn_enabled.up.sql:6`, `0098_agent_jit_access.up.sql:6` |
| Leader-gated periodic work | **Exists** — `mayTick()` = `IsLeader() && ConfirmLeader()` | `cmd/server/main.go:624` |
| Audit event constants | ⛔ **DO NOT EXIST** — inline string literals, six-plus divergent `audit()` helpers | `machineauth:195`, `nodes:2730`, `agenttemplates:910`, `sso/audit.go:15`, `devices:1552`, `tenancy:520`, `agentaccess:779` |
| SSRF guard / IP predicate / redirect policy | ⛔ **DO NOT EXIST** — zero non-test hits for `DialContext\|LookupIP\|CheckRedirect\|IsPrivate\|IsLoopback\|169.254` in `apps/api` | — |
| Retry / outbox / backoff / dead-letter | ⛔ **DOES NOT EXIST** — every background task is "reconcile again next tick" | `main.go:499-521,537-555` |
| General rate limiter / debounce | ⛔ **DOES NOT EXIST** — the one throttle carries a do-not-reuse notice | `http/rekeythrottle.go:11-18` |

⛔ **THE ONE THAT MATTERS MOST: a webhook URL is the first user-supplied URL this control plane will ever
dial.** Every outbound request today targets a constructed or hardcoded host — Microsoft SSO *builds*
`login.microsoftonline.com/<tenant>/v2.0` (`sso/microsoft.go:26`) rather than storing a URL, and
`sso_configs` has no URL column at all. There is no guard to extend; F11 builds the primitive.

---

## Decide-items

### D1 — Destinations in v1 · **LOCKED: all eight, three formatter families**
Slack, Microsoft Teams, PagerDuty, Opsgenie, Discord, Google Chat, generic JSON webhook, email.

Lean because they collapse into **three** payload shapers, not eight:
- **Slack-compatible JSON** — Slack, Discord, Google Chat, generic webhook (also covers Mattermost)
- **Adaptive Card** — Teams
- **Events API** — PagerDuty Events v2, Opsgenie Alerts (both take a routing key + dedup key)

Email reuses `mail.Mailer` and shapes nothing new.

### D2 — PagerDuty/Opsgenie incident lifecycle · **DEFERRED to F11.1, trigger-only in v1**
Both APIs model an incident that opens and later *resolves*. Auto-resolve means alerting must track
open-incident state per (destination, dedup key) and emit a resolve when the condition clears — a state
machine, and the single largest thing in this story.

v1 sends **trigger only**, with a stable `dedup_key` so the provider coalesces repeats rather than paging
twice. Operators resolve in PagerDuty. **Named trigger for F11.1:** the first customer running on-call
rotation off Tunnex alerts.

⚠ Recorded as a real cost, not a shrug: an un-resolved incident is noise, and noise trains people to
ignore pages. The dedup key is what keeps v1 honest — one open incident per condition, not one per tick.

### D3 — Event catalogue · **LOCKED: F11 owns its own constants; the audit log is NOT refactored**
The audit log cannot be the event source as it stands. Action strings are inline literals across seven
packages with six-plus divergent `audit()` helpers, so subscribing by string match means a renamed
literal **silently stops alerting** — a failure with no symptom, which is the worst kind here.

Rejected: build a central audit-event registry first. Correct, and a seven-package refactor F11 does not
own. That is a story of its own.

Locked instead: `internal/alerts` declares its **own** typed catalogue (`alerts.EventKey`), and producers
call `alerts.Publish(...)` **beside** the existing `audit()` call, not through it. Additive, no existing
code path changes, and the catalogue is a closed Go enum so a rename is a compile error.

⚠ THE HONEST COST: two writes at each producer site, and a producer someone forgets to wire emits
nothing. Mitigated by a census test — every `EventKey` must have at least one `Publish` call site — which
is the same shape as the standing who-reads-this probe.

### D4 — Subscription grain · **LOCKED: per destination**
Each destination selects its own event set: this Slack channel gets infrastructure health, that PagerDuty
service gets security only, email gets licence expiry. Schema is one join row per (destination, event).

Rejected: one org-wide event selection applied to all destinations. Barely less schema, and it makes the
common real case — paging on-call for outages while posting config changes to a chat channel —
impossible.

### D5 — SSRF policy · **LOCKED: deny private ranges by default, explicit per-destination opt-out**
The guard is a purpose-built `http.Client`:
- **resolve-then-dial** — resolve the host, check the resolved IPs, then dial the **IP** so DNS rebinding
  cannot swap a public answer for `169.254.169.254` between check and connect
- deny loopback, link-local (incl. `169.254.0.0/16` and `fd00::/8`), private RFC1918/RFC4193, CGNAT,
  unspecified and multicast
- **no redirects** (`CheckRedirect` refuses) — a 302 is otherwise a guard bypass
- hard timeout, response body cap, `https` only except where the opt-out allows
- an explicit `allow_private` boolean per destination, settable only by an owner and audited

Rejected: block everything private with no exception. Breaks a legitimate self-hosted Mattermost or
internal webhook receiver on a private LAN, which is a real deployment shape for this product.

Rejected: trust the admin. Anyone with the new permission could make the control plane port-scan its own
network and read the cloud metadata endpoint.

⚠ The style precedent is `cliauth.ValidateLoopbackRedirect` (`cliauth/service.go:92-108`), which pins IP
literals and states *"never a hostname — 'localhost' is DNS-spoofable"*. Same reasoning, inverted.

### D6 — Delivery semantics · **LOCKED: durable outbox, leader-gated ticker, no queue infrastructure**
No retry substrate exists. Lean answer: one `alert_deliveries` table as an outbox (`attempts`,
`next_attempt_at`, `last_error`, terminal `failed` state) drained by a ticker on the existing `mayTick()`
leader gate — the same pattern as the flow-log retention sweep (`main.go:499-521`).

At-least-once with exponential backoff and a bounded attempt count, then dead-letter to `failed` where the
UI can see it.

**Retry bound disposition — LOCKED:** one initial attempt plus four retries (five attempts total), with
delays of **1 minute, 2 minutes, 4 minutes, and 8 minutes**. The fifth failed attempt is terminal
`failed`; it is retained with its append-only attempt history for the delivery UI. This is intentionally
fixed for F11 rather than a new per-org tuning surface: alerting needs a predictable, bounded recovery
path before it needs delivery-policy administration.

Claimed rows use a one-minute worker lease. A later leader requeues only a `delivering` row whose claim
has exceeded that lease, preserving at-least-once delivery after a process crash without a queue service.

Rejected: Redis/NATS/river queue. New infrastructure for a workload measured in messages per hour.

Rejected: fire-and-forget from the request goroutine. A webhook that is down during a deploy would lose
exactly the alerts about that deploy.

### D7 — Storm suppression · **LOCKED: per-condition cooldown, NOT a general rate limiter**
A flapping gateway must not send 300 messages. Each event carries a `dedup_key`
(org + event + subject); a destination will not re-send the same key inside a cooldown window, and the
suppressed count is reported on the next send.

⛔ **THIS IS NOT THE GENERAL RATE-LIMITING GAP AND MUST NOT BE MISTAKEN FOR IT.** PLAN.md registers "no
general rate limiting" as owed for login, enrolment and the agent channel. This is per-condition
alert-send debounce, scoped to `internal/alerts`, and carries the same do-not-reuse notice as
`rekeythrottle.go:11-18`. Reaching for it as the general mechanism is the drift that notice exists to stop.

Precedent for the shape: health already debounces (`desyncDebounce` T=2R, `policyhealth.go:20-21`) so a
transient mismatch never reads as `silent_desync`. Alerts inherit that — they fire on the **projected**
kind, so debounce happens once, upstream, and not twice.

### D8 — Edition gating · **LOCKED: open to every edition, org opt-in, default OFF**
Being told your own infrastructure is down is table stakes, not an upsell. No `licence.Feat*` constant is
added.

Follows the unlock-then-opt-in law exactly: `organizations.alerting_enabled boolean NOT NULL DEFAULT
false`, matching `ovpn_enabled` / `agent_jit_access_enabled`, with a dedicated setter, an
`org.alerting_enabled` audit row, and the field on the org payload.

### D9 — RBAC · **LOCKED: new permission `alerting:manage`, never reused**
House rule is a permission named per capability. Granted to owner and admin; **`allow_private` (D5) is
owner-only**, because it widens what the server will dial.

Reading the delivery log needs no new permission beyond `alerting:manage` — it contains destination names
and failure reasons, which is administrative, not tenant data.

### D10 — Secret storage · **LOCKED: mirror `sso_configs` (`bytea` + fingerprint)**
Webhook URLs and routing keys are credentials — a Slack incoming-webhook URL *is* the auth token. Sealed
with `crypto.Sealer`, stored `bytea`, with a `secret_fingerprint` so the UI can prove the stored value is
the one that was pasted without ever returning it (`0014_sso_secret_fingerprint.up.sql`).

⚠ Noted inconsistency, deliberately not fixed here: `Seal` returns a `string`; four tables store it in
`bytea` and cast, one (`0046_ovpn_server_certs`) uses `text` and actually matches the signature. The
majority is `bytea` and F11 follows the majority for consistency. **Registered:** unify the column type,
owned by whoever touches `crypto.Sealer` next.

⛔ The URL is **never** returned by the API, only its host and fingerprint. A read-back webhook URL is a
credential exfiltration path through a read-only permission.

### D11 — Producer thresholds · **LOCKED: bounded defaults approved by founder**
F11 needs concrete condition boundaries; without them an alert producer either pages on a normal retry or
never fires at all. The following fixed v1 boundaries are intentionally not a per-org tuning surface:

- **`agent.offline`**: three minutes of gateway-reported absence for one managed agent. A silent gateway is
  not attributed to the agent, so no agent-offline event is emitted while the gateway reporter itself is stale.
- **`agent.denial_spike`**: twenty denied decisions in a rolling five-minute window for one agent.
- **`agent.access_expiring`**: fifteen minutes before an approved JIT agent-access request expires.
- **`agent.rotation_failed`**: only a terminal credential or WireGuard rotation failure/deadline expiry; retry
  noise is not an alert.

These values were approved for the F11 walk on 2026-08-20. A future alert-policy story may expose tuning;
F11 keeps them fixed so the event contract and cooldown semantics remain predictable.

---

## Configurability — what an owner actually controls

Every item is owner-settable; nothing is hardcoded policy.

| Control | Grain | Default |
| --- | --- | --- |
| Alerting on/off | org | **off** (unlock-then-opt-in) |
| Destinations | many per org | none |
| Which events go where | **per destination** (D4) | none selected |
| Minimum severity | per destination | `warning` |
| Cooldown window | per destination | 15 min |
| Quiet hours | per destination | none |
| Allow private-IP targets | per destination, **owner-only** | **off** (D5) |
| Test send | per destination, any time | — |

---

## Slice plan

Status vocabulary: `paper` · `todo` · `in progress` · `done` · `deferred`.

| # · Slice | Status | UI changes | Backend changes |
| --- | --- | --- | --- |
| **1 · Commit-one paper** | **paper — this document** | none | none |
| **2 · Schema, RBAC, event catalogue** | in progress | none (deliberately — the seam ships before any surface) | Migration: `alert_destinations` (sealed URL + fingerprint, kind, `allow_private`, cooldown, severity floor), `alert_subscriptions` (destination × event key), `alert_deliveries` (outbox), `organizations.alerting_enabled`. sqlc queries. `internal/alerts`: `EventKey` closed enum, `Event`, `Publish()` writing to a no-op sink. `rbac.PermAlertingManage` + grant table + `make generate-rbac` mirror. Census test: every `EventKey` has a producer |
| **3 · SSRF-guarded HTTP client** | todo | none | `internal/alerts/safedial`: resolve-then-dial, IP-range denylist, `CheckRedirect` refusal, timeout, body cap, `allow_private` escape hatch. **Red tests are the deliverable**: `169.254.169.254`, a DNS-rebinding stub, a 302 to a private host, a slow-loris body — each must be refused |
| **4 · Outbox + dispatcher** | todo | none | `alerts.Dispatcher` drained by a ticker on `mayTick()` (`main.go:624`); exponential backoff, bounded attempts, dead-letter to `failed`; per-condition cooldown + suppressed-count (D7). One transport (generic JSON) to prove the path end to end |
| **5 · Transports: Slack family** | todo | none | Slack-compatible shaper reused by Slack, Discord, Google Chat, generic webhook. Message text derived once from `Event`, not per provider |
| **6 · Transports: Teams, PagerDuty, Opsgenie, email** | todo | none | Adaptive Card shaper (Teams); Events-API shaper with `dedup_key`, trigger-only (D2); email via existing `mail.Mailer`, degrading honestly on `ErrNotConfigured` (`mail/mail.go:143-155`) |
| **7 · Producers: infrastructure health** | todo | none | `alerts.Publish` on `PolicyDegradedKind` **transitions** (not on every tick) — hooked where `PolicyHealthForNodes` already projects (`nodes/service.go:2390`) and beside `hub_set.promotion` / `hub_set.failback` (`nodes/failover.go`). Licence and capacity thresholds |
| **8 · Producers: security & access** | todo | none | `alerts.Publish` beside existing `audit()` calls for device revoke, JIT request/approve, MFA-enforce change, SSO/directory-sync config change, deprovision sweep. Additive only — no existing audit call changes (D3) |
| **9 · UI: destinations, subscriptions, test-send, delivery log** | todo | New **Alerting** section in the org-settings rail. Rows via the existing `SettingRow` / `SettingDialogRow` / `Switch` vocabulary: master `Switch`; destination list; add/edit dialog (kind, URL/routing key, severity floor, cooldown, quiet hours, owner-only `allow_private`); **per-destination event picker**; **Test** button with the real result; delivery log showing failures and the dead-lettered | Handlers for destinations CRUD, subscriptions, test-send, delivery list. OpenAPI first (`openapi/openapi.yaml`), then `make generate`. URL never returned — host + fingerprint only (D10) |

Slices 2–8 ship no UI on purpose: the seam, the guard and the delivery path are provable by tests before
there is a surface to mislead anyone with.

---

## Verification

- `make generate-check` (OpenAPI → Go/TS/RBAC/sqlc drift), `make migrate`, `make test-editions`,
  `make build-editions`, web `typecheck && test && build`.
- **Slice 3 is red-first.** The SSRF tests must fail against an unguarded client and pass against the
  guard. A green suite over a client that was never pointed at `169.254.169.254` proves nothing.
- **Wire proof:** a real Slack incoming webhook and a real PagerDuty routing key on the local stack; force
  a gateway into `site_link_down` and observe the message. Per ledger convention unit tests **substitute
  for** but never **satisfy** a wire proof.
- Test-send is the operator-facing proof, and it must report the true failure (DNS, refused by guard,
  4xx from provider) rather than a generic "could not send".

## Non-goals / registered

- **Auto-resolve for PagerDuty/Opsgenie** — D2, deferred to F11.1 on a named trigger.
- **Central audit-event registry** — D3, its own story.
- **General rate limiting** — still owed (PLAN.md); D7 is not it.
- **Sealed-column type unification** — D10, owned by the next `crypto.Sealer` change.
- **Alert templating / custom message bodies** — deliberately out; a fixed shape per event keeps the
  producer census meaningful.
- **Per-user (rather than per-org) subscriptions** — out; this is org infrastructure alerting.
