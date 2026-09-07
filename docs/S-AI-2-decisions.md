# AI-2: team and model reconciliation

Status: proposed contract; product implementation blocked only on the explicit
team-composition decision below. AI-1 credential/transport contracts are committed.

## Required user disposition

Recommendation: reuse existing Agent Groups, assign one explicit AI team per
agent, and allow per-agent model overrides only to narrow the team's models.
Alternative: intersect policies from multiple memberships. The user has approved
Community availability and honest soft usage thresholds but has not yet answered
this independent assignment question. No default has been silently selected.

This decision affects authorization, policy-edit effects, usage attribution and
which customer controls are needed. The repository's mid-build-fork rule requires
a disposition before dependent schema/API/service implementation.

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

Next action: receive the team-composition disposition, freeze its OpenAPI and
persistence contract, then divide reconciliation, scoped usage and dashboard
work between independent agents.
