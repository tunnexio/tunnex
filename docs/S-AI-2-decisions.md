# AI-2: team and model reconciliation

Status: LOCKED and locally implemented after user approval on 2026-09-07.
Qualification: [AI ledger](AI-2-5-validation-20260907.md); remote CI remains pending.

## User disposition

Approved: reuse existing Agent Groups, one explicit AI team per agent. Agent
overrides may only narrow that team's exact allowed models. Multiple-membership
intersection rejected for this release: ordinary group memberships remain
unchanged, but only the explicit AI assignment grants AI access. Community and
honest soft thresholds remain approved.

## Implementation contract

- A team policy belongs to an active existing Agent Group. Assignment requires
  an existing same-tenant agent-group membership; removal/archive immediately
  denies new inference. One current assignment per agent, independently enabled.
- Team policy supports the qualified OpenRouter provider,1–32 exact model names
  (full `openrouter/…` identifiers),1–8 configured native provider key IDs, and an
  optional positive daily USD soft threshold up to100000. Empty model override
  inherits; a nonempty override must be a subset. Provider keys never enter CP.
- Optimistic expected_revision on all policy/assignment writes; initial revision0.
  Writes record desired state and audit, then reconciliation attempts to apply.
  Responses expose desired/applied revisions and pending/applied/error/disabled
  status. Stale or incomplete policy fails closed for new requests.
- Native key identity is stable per org/device/team, retained across edits and
  moves back to a prior team. A team move disables the old native key, then uses
  the target team's stable key. Retained binding rows are attribution metadata,
  not a usage ledger. History remains with the request's team, never relabelled.
- Each org is bounded to64 retained native bindings for this initial deployment,
  making native usage queries bounded. Refuse creation beyond the cap; never
  silently purge history/reset spend to make room. Each assignment is current
  once even if historical bindings remain. This limit is visible in setup docs.
- Reconcile under device lock and team-policy shared lock, using the same DB
  transaction. An org row lock serializes binding-cap allocation. Policy writes
  only lock their policy row; no inverse device/org lock order. Native readback
  verifies stored and in-memory scopes before applied revisions commit.
- Canonical runtime authorization already locks the device. Resolve reads policy
  and binding using its supplied transaction. No second pooled DB connection.
- Daily threshold admission reads Bifrost's native scoped stats since00:00UTC.
  This compares existing native observations; it introduces no competing ledger
  or reservation. Missing stats refuse when cost policy applies. Every monetary
  admission revalidates exact model pricing; unknown prices refuse. Async native
  logging, concurrent/accepted work and billing differences may overshoot.
- Usage API accepts only org-scoped team/agent IDs; native IDs are selected by CP.
  Maximum range31days, default current UTC day. Zero bindings return explicit0
  without asking the engine for all-tenant logs. Usage is observed/estimated, not
  an invoice; missing cost remains visible.
- Reconcile on management writes and via bounded periodic retry worker; no grant
  waits for an unbounded job. Manual reconcile operation makes recovery visible.
  Network/DB errors are sanitized. No provider credentials in responses/audit.

## Constraints already established

- Tunnex owns desired policy; Bifrost executes exact provider/model scopes using
  server-only virtual keys. No caller aliases, fallback destinations or arbitrary
  provider endpoint settings.
- Preserve stable native accounting identity across policy edits. Do not recreate
  a key/budget on every revision or reset counters while tightening models.
- Persist desired/applied revisions separately. A failed or partial engine update
  must not mark policy applied. Compare both persisted and in-memory native scope
  before admitting new requests.
- Serialize reconciliation with authoritative database state. Credentials' resolver
  uses the supplied transaction and must not borrow another pooled connection.
- Scope usage lookups from authoritative org/agent/native IDs, never caller-supplied
  engine identifiers. Empty native ID lists must never become all-tenant queries.
- Preserve request-time team attribution across assignment changes; current-team
  rollups must not relabel historical usage. Qualify the native metadata path
  before publishing historical team totals. No second competing spend ledger.
- Monetary thresholds are **soft**, as explicitly approved. Verify exact model
  pricing before monetary-policy admission; unknown/ambiguous prices refuse.
- Qualified topology is one CP admission process and one engine. Do not advertise
  shared-budget HA or a strict maximum invoice.

Next action: submit the committed candidate for exact-head remote validation.
