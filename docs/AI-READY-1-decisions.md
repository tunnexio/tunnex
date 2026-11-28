# AI-READY-1: AI Gateway pre-launch readiness

Status: decided and built on 2026-11-28, on top of AI-CATALOG-1 (PR #146).

Five items the founder asked for before launch: operator-set model prices with
an explicit unknown-price policy, a catalog refresh step in every release,
budget alerts, the real client address behind the Helm edge, and a per-request
log that never stores prompt content.

## Migration and merge order

One migration, `0259_ai_gateway_readiness`.

- 0256 (RBAC-1) is merged. 0257 is on the base branch (PR #146). 0258 is
  reserved by the unmerged static-keys branch (`story/ai-static-keys-1`).
- Merge order: PR #146 (0257), then the static-keys branch (0258), then this
  branch (0259). golang-migrate does not apply a lower-numbered migration to
  a database already at a higher version, so 0259 must not reach `main` before
  0258. If static keys slips, renumber this migration instead.
- 0258 also rewrites the four alert `event_key` CHECK constraints to add
  `ai_workload.static_key_expiring`. 0259 rewrites the same constraints, so
  its lists include that key (and its down migration restores the 0258 list).
  On a database without 0258, allowing one extra value is harmless. Without
  this, merging both would silently drop the static-key alert.
- The static-keys branch's own per-key daily threshold is not covered by the
  budget alerts here; add it when both are merged (one more subject kind).

## 1. Model prices the operator can set

### Problem

Cost admission (`enforceCostBindings`) refuses `ai_price_unavailable` when the
bundled catalog has no exact price. Live provider catalogs now offer models the
pinned catalog lacks (for example `gemini/gemini-3.5-flash`), so any user
group, workload or agent group with a daily limit cannot use them, and usage
shows them as uncosted.

### Where cost comes from

Usage cost is not computed in the control plane. The private engine (Bifrost,
pinned) prices each request from its datasheet (`bifrost-pricing.json`, derived
from the same LiteLLM pin) and writes it to its own log store. Usage, the
dashboard and cost admission all read that native ledger
(`/api/logs/stats`, with `missing_cost_only` for uncosted requests).

### Decision: push the override into the engine, scoped per provider key

An override applied only in the control plane does not work. The first call
would be admitted with the operator's price, the engine would log it uncosted,
and admission refuses any subject whose observed usage today has an uncosted
request (`ai_gateway_unavailable`, fail closed). One call would block that
subject until midnight UTC. So the override must reach the engine's ledger.

The pinned engine supports pricing overrides
(`/api/governance/pricing-overrides`), including override-only pricing for a
model that is not in its catalog. Scopes include `global`, `provider_key` and
`virtual_key`; there is no organization scope.

- Never `global`: one engine serves every organization, so a global override
  would reprice other tenants.
- Scope `provider_key`, one engine override per organization provider
  connection whose provider matches the model. Each connection has its own
  engine key ID, so this is isolated per organization and naturally bounded.
  Match type `exact`, pattern = the engine's native model name (the part after
  `provider/`), which is the name the engine matches for overrides.
- The engine assigns override IDs. Tunnex finds its own by a deterministic
  name, `tnx-price-<sha256(connection key id + model)[:24]>`, and reconciles:
  create the missing, update the changed, delete Tunnex-named overrides that
  are no longer wanted. Overrides not named by Tunnex are never touched.
- The control plane table is the source of truth, with `revision` and
  `applied_revision`, like assignments. Saving writes the row, then reconciles
  that organization and provider at once; the leader also reconciles every
  five minutes (new connections, engine data loss). Read-back confirms each
  override before `applied_revision` moves.
- Admission uses an override only when `applied_revision = revision`. Until
  then it keeps the bundled price (or the unknown-price policy). The control
  plane and the engine therefore never price the same call differently.
- Requests before the override applied stay uncosted in the engine; that is
  history, not repriced.

### Shape

- Per organization, per canonical model (`provider/model`): input and output
  USD per token. Output is required for chat and completion models, optional
  for embedding.
- Per-image and per-second prices are not added. Cost admission applies only
  to chat, completion and embedding today (other modes are refused with
  `ai_price_unavailable` under a limit), so they would have no effect.
- Values are finite, at least 0 and at most 0.01 USD per token (USD 10,000 per
  million). An explicit 0 is allowed (a free or self-hosted model) and is
  audited like any other value; it means the model costs nothing against a
  limit.
- At most 500 overrides per organization.
- Who: `ai_provider:manage` sets and removes; `ai_provider:view` or
  `ai_gateway:view` reads. Human administrators only.
- Every change writes an audit entry (`ai_model_price.changed` /
  `ai_model_price.removed`) with model, prices and revision.
- Expected revision on change and removal; a mismatch is 409.
- Tests: validation, admission prefers an applied override, ignores an
  unapplied one, engine reconcile (create/update/delete, foreign overrides
  untouched, never global scope), audit, permissions.

### API

- `GET /ai-gateway/model-prices?model=…` (repeatable, at most 200): every
  override of the organization, plus the effective price of each requested
  model with its source (`override`, `catalog` or `unknown`).
- `PUT /ai-gateway/model-prices`: `{model, input_cost_per_token,
  output_cost_per_token, expected_revision}`.
- `DELETE /ai-gateway/model-prices?model=…&expected_revision=…`.

### Unknown-price policy

An organization setting for subjects with a daily limit:

- **Block (default)**: today's behaviour. A model without an exact price is
  refused with `ai_price_unavailable`; uncosted usage fails closed.
- **Allow and alert**: a model without a price is admitted. Admission then
  also tolerates uncosted requests in today's observed usage and compares only
  the costed spend with the limit (otherwise the first allowed call would block
  the subject for the day, as above). The first such call per subject and model
  per UTC day raises the `ai.price_unknown` alert. The limit does not cover
  those calls; the console says so.
- Who: `ai_gateway:manage` (it sits in AI Gateway settings). Audited
  (`ai_gateway.cost_settings_changed`), with an expected revision.
- Subjects without a limit are unaffected either way.

### Console

- Models & endpoints: a Price column (input / output per million tokens, as
  people read prices), "Price unknown" badge, and "Set price" / "Edit price" /
  "Remove price" for `ai_provider:manage`. A custom price shows "Custom".
- AI Gateway settings: "Models without a price" with Block (default) and
  Allow and alert, plus request log retention (item 5).

## 2. Catalog refresh in every release

- `scripts/ai-model-catalog.mjs --refresh <commit|main>` resolves the commit
  through the GitHub API (date from the commit), downloads the source and
  license at that exact commit, computes hashes and counts, prints old → new
  counts and the added and removed models, rewrites `source.pin.json` and the
  README's pinned lines, regenerates every artifact, then runs the same
  verification as `--check`.
- The schema, provider-coverage and completeness guards are unchanged. One
  guard is added for refresh only: the reference count may not fall by more
  than 10% (an upstream file that lost providers would otherwise become the new
  pin).
- `make ai-catalog-refresh` (optional `LITELLM_COMMIT=…`, default `main`) runs
  the refresh and the generator tests. `make ai-catalog-check` runs the CI
  check.
- The release checklist (`docs/upgrade-release-signing-checklist.md`) gains a
  "Refresh the AI model catalog" step before tagging, with review notes.
- The refresh was run to LiteLLM `main` on this branch (see the commit).

## 3. Budget alerts

- One event key, `ai.budget_threshold`, at 50% (info), 80% (warning) and
  100% (critical) of a daily limit. Subjects: user groups (0257), workloads
  (`daily_usd_threshold`) and agent groups
  (`ai_gateway_team_policies.daily_cost_limit`).
- At most once per subject, threshold and UTC day: a durable marks table
  (`ai_gateway_alert_marks`), `INSERT … ON CONFLICT DO NOTHING RETURNING`;
  the event is published only by the insert that created the mark. Outbox
  cooldowns are time-based, so they are not relied on for the day boundary.
  Marks older than two days are pruned by the same job.
- Evaluation: a leader-only job every five minutes reads today's observed
  spend for each limited subject (the same native ledger and attribution as
  admission). At most 500 subjects per pass; the rest wait for the next pass.
  A failed usage read skips that subject (no alert, no mark). Alerts can
  therefore arrive up to five minutes after the spend.
- Delivery-only events (no `Resource`), like the MCP approval alert, so the
  alert centre never holds an occurrence that nobody resolves.
- Fields: subject kind, id and name, threshold percent, limit, observed spend,
  UTC day. Never keys or prompts.
- `ai.price_unknown` (warning) is the unknown-price alert from item 1, deduped
  through the same marks table (subject + model + day).
- Console: both keys under a new "AI Gateway" group in alert subscriptions.

## 4. Helm edge forwards the real client address

- The edge sets `X-Real-IP` from its own peer. Behind a load balancer or
  ingress controller the API therefore saw that peer, not the client.
- New value `edge.realClientAddressFrom` (CIDRs, default empty). When set,
  nginx's realip module takes the client address from `X-Forwarded-For` only
  when the direct peer is in that list (`set_real_ip_from`,
  `real_ip_recursive on`, so every trusted hop is skipped and the first
  untrusted address is the client). Empty = today's behaviour exactly.
- The existing scheme trust (`geo … $tunnex_ingress_trusted`) now keys on
  `$realip_remote_addr`, the direct peer, so taking the client address never
  widens who may report the scheme.
- `X-Real-IP` (both server-level and terminal location) is the resolved
  address; `True-Client-IP` stays cleared. The API keeps trusting only the
  edge pods (`TUNNEX_TRUSTED_PROXIES`), unchanged.
- Values are validated with the same pattern as `trustedIngressCIDRs`; an
  all-address range (`0.0.0.0/0`, `::/0`) is refused.
- PROXY protocol on the Helm edge is not added: a `proxy_protocol` listener on
  8080 breaks the kubelet probes and in-cluster callers. Terminate PROXY at the
  ingress controller or load balancer, which then sends `X-Forwarded-For`.
  Documented in the values file.
- Tests: the chart contract test renders both cases and runs the pinned nginx
  image: forged `X-Forwarded-For` from an untrusted peer is ignored, a trusted
  peer's chain gives the client address.

## 5. Per-request log

### What is stored

Time, organization, subject kind (user, agent, workload) and id, the group
that admitted it (user group or agent group, when known), workload instance,
model, mode, ingress (`public`, `vpn`, `agent`, `workload`), HTTP status,
outcome (`ok`, `refused`, `error`), refusal code (internal code such as
`ai_daily_threshold_reached`; never a message), latency, prompt and
completion tokens, cost or uncosted, and the request id.

Never prompts, completions, request or response bodies, headers, keys or
tokens. Docs say so.

### Where the numbers come from

- Status, latency, subject, model and refusal code come from the control plane
  request. A recorder is placed in the request context by the inference entry
  points (user, VPN, agent, workload); every authorize callback receives a
  context derived from it, so the recorder sees the grant or the refusal code
  without changing the adapter. A response-writer wrapper (with `Unwrap`, as
  the adapter requires) records the status. The record is written in a
  `defer` that also covers an aborted stream.
- Tokens and cost come from the engine's own ledger, not from parsing
  responses, so the log agrees with usage. The adapter's upstream request
  carries `X-Request-Id: <uuid>`; the pinned engine uses that header as its log
  entry ID. A leader-only enricher reads `GET /api/logs/{id}` for rows still
  pending after a few seconds and stores tokens and cost (`costed`), or
  `uncosted` when the engine has no price, or `unavailable` after an hour.
  Matching by key, model and time would be ambiguous with concurrent requests,
  so it is not used.
- No `adapter.go` change. The header is set by wrapping the adapter's HTTP
  transport from a new file (`request_log.go`), which reads the id from the
  request context.

### Write path

- A bounded in-memory queue (4096) and one batch writer per API process
  (up to 200 rows or one second per batch). A full queue drops the record and
  counts it (`RequestLog.Dropped()`; the writer logs `ai_request_log_dropped`
  with the running total whenever it grows). Inference never waits on the
  database for the log.
- Refusals before an organization is known (missing or invalid bearer) are not
  logged; there is no tenant to attribute them to.
- Video jobs are not logged in this story (separate job handler and engine
  calls); `/v1/videos` paths pass through untraced.
- The enricher checks leadership cheaply every five seconds without the
  database confirmation the deletion jobs use: its updates are idempotent
  (`WHERE cost_state='pending'`), so a brief overlap after a leader change
  only repeats a read. Pruning confirms leadership like other retention jobs.

### Where the hooks are (no `adapter.go` change)

- `request_log.go`: `RequestLog.Begin` (trace, status writer, deferred record),
  `TraceAuthorize`, `Adapter.ConfigureRequestLog` (wraps the adapter's HTTP
  transport to add `X-Request-Id`; the log is kept beside the adapter in a
  package map, so the adapter type is unchanged).
- Entry points: `aiInferenceMiddleware` (agent), `workloadMiddleware`
  (workload), `aiUserInferenceMiddleware` (public user) and
  `AgentChannel.serveVPNChat` (VPN); `cmd/server/main.go` wraps the token
  authorizer with `TraceAuthorize`.
- Group attribution: one `noteRequestGroup` line in `resolveUserModel`
  (user group) and in the agent resolver (agent group).

### Retention, API, console

- Retention per organization, 1 to 365 days, default 30 (same style as MCP
  activity retention), set in AI Gateway settings with the unknown-price
  policy. A leader-only job deletes in bounded batches every 15 minutes.
- `GET /ai-gateway/requests` with `from`, `to`, `subject_kind`, `subject_id`,
  `model`, `outcome`, `limit` (max 200) and an opaque cursor, newest first.
  Readable with `ai_provider:view` or `ai_gateway:view` (the usage
  permission). Names are resolved at read time.
- Console: Usage & cost gets a "Requests" view with filters (subject, model,
  outcome, time range) and "Load more".

## Not changed

- Adapter request validation, timeouts and its concurrency limiter (another
  branch owns them).
- Engine image, pins and the Bifrost build.
- Usage semantics: still an observed estimate, not an invoice or a cap.
