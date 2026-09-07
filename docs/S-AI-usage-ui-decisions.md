# AI usage dashboard refinement

Status: implementation requested by user on 2026-09-07; local visual review pending.

## Locked scope

- Replace the text-only usage section with a usage-first dashboard inspired by
  the supplied LiteLLM screenshot and its public `usage.tsx` source. Implement
  Tunnex components; no copied LiteLLM implementation or new UI dependency.
- Usage and configuration are separate local tabs on the existing AI gateway
  page. Keep every existing policy/assignment action reachable in configuration.
- Show estimated spend, requests, successful/failed requests, tokens, average
  estimated cost, UTC daily bars, model spend and historical team/agent rankings.
  Display uncosted requests and tiny costs honestly. Estimates are not invoices;
  thresholds remain soft. No synthetic activity in the live dashboard.
- Extend the existing authenticated usage GET with optional `dashboard=true`
  and an additive optional `dashboard` response. Existing totals clients remain
  compatible. OpenAPI remains authoritative. No migration or second ledger.
- Use only native scoped aggregate statistics/histograms/rankings. Every call
  receives CP-selected retained native key IDs and the same bounded time range.
  Empty bindings produce explicit empty data without an engine call. Native key
  IDs and provider secrets never appear in public responses.
- Preserve request-time team attribution using retained bindings. Map native
  virtual-key rankings to authoritative CP team/device IDs and names. Reject
  out-of-scope/duplicate/invalid native results rather than showing partial totals.
- Maximum range remains 31 days and bindings remain capped at 64. Retrieve each
  histogram once for the whole window; fold epoch-aligned buckets into UTC days.
  Native range boundaries are inclusive; do not issue adjacent per-day queries.
  Native aggregation calls are bounded and use a shared timeout.
- Missing engine data is unavailable, never zero. Independent native reads can
  observe async accounting at different instants; no atomic billing claim.
- No cloud actions, provider spending, merge or release. Leave local preview up.

## Review disposition

- P2 selected page-two agent disappearing after refresh: fix as part of this
  refinement by clearing a selection no longer present after authoritative
  inventory reload; editor must disappear with it. Regression before fix.

## Acceptance

Scoped native adapter refusal tests, tenant/attribution integration tests, both
API editions, generated drift check, web filter/stale-result/error/chart tests,
and actual local CP browser inspection. Visual approval remains pending.

## Configuration visual refinement

User additionally requested the configuration view follow the LiteLLM-inspired
theme on 2026-09-07. Apply the usage dashboard's visual language to organization
status, team policy and agent access: compact selectors, clear section/status
hierarchy, balanced responsive forms and consistent controls. This is a scoped
presentation change; preserve API payloads, optimistic revisions, permissions,
default-OFF behavior, membership checks and every existing action. Shared settings
outside this view retain their presentation. Local browser review follows.
