# F07 — Truthful agent audit attribution box-walk

Status: **DRAFT / NOT YET RUN**. This walk runs once after the full F07 source
slice, review and exact-head local gates are complete. Unit/integration tests are
SUBSTITUTES, never live-wire satisfaction.

## Safe scope

- Use only the authorized AWS DEV control plane and the separate Ubuntu DEV
  agent VM.
- Use uniquely named disposable F07 agent, policy rule, destination and reporter
  resources. Do not reuse or mutate F01–F06 proof identities.
- Record exact content/image/schema/backup provenance before mutation.
- Never record cookies, bootstrap/runtime credentials, WireGuard private keys,
  raw configurations, token hashes or signing keys in chat or artifacts.
- Arm the existing flow-log collector only for the disposable reporter and
  restore its prior state during cleanup.

## Acceptance checklist

- [ ] Exact F07 API/web/node content is deployed healthy; migration 0096 is clean
      and the rollback bundle verifies.
- [ ] Instrument-first check proves the flow collector is reporting; an empty
      feed is never interpreted before this check.
- [ ] A zero-grant managed agent produces a real default-deny event attributed
      to its canonical agent ID from the applied subject map, not an address
      lookup.
- [ ] The deny event preserves gateway, applied policy hash/version, agent
      configuration revision, observed route tuple, decision and
      `no_matching_grant`; no human/workflow trigger is rendered.
- [ ] One disposable grant applies and a real allowed flow preserves the exact
      rule ID, route tuple, `allow` and `matched_grant`.
- [ ] `src_agent_id` filters on the server across keyset pages and composes with
      `denies_only`; unrelated/foreign IDs reveal no event or identity oracle.
- [ ] Released Access Events renders the agent selector and factual event-detail
      timeline. Deleted/current labels are explicit and absent facts say “Not
      recorded”.
- [ ] Rapid organization switching clears the prior agent, rows, filter and open
      detail before any late response can commit.
- [ ] Disposable PostgreSQL proves empty 96→95 down, 95→96 up-again, and
      attributed-row rollback refusal with event/field preservation.
- [ ] Cleanup removes only F07 disposable resources and restores collector
      configuration; unrelated data-plane/control-plane state remains healthy.

## Required redacted artifacts

- `walk-artifacts/F07/<run>/provenance.md`
- `walk-artifacts/F07/<run>/instrument-and-deny.md`
- `walk-artifacts/F07/<run>/allow-and-filter.md`
- `walk-artifacts/F07/<run>/released-route.md`
- `walk-artifacts/F07/<run>/rollback-and-cleanup.md`
