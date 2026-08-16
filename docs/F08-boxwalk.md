# F08 — Read-only Test Access box-walk

Status: **CORE LIVE WALK PASS / MEMBER-SESSION LEG SUBSTITUTED**.

Use exact committed F08 API/web content on AWS DEV, the existing healthy DEV
gateway when unchanged, and one uniquely named disposable managed agent. Run
the reusable walk harness for provenance/preflight/cleanup checks. Never record
cookies, bootstrap/runtime credentials, private keys, raw configurations or
token hashes.

## Acceptance

- [x] Harness preflight proves exact source/component scope, rollback readiness,
      schema and healthy shared services before mutation.
- [x] One fresh active agent reaches desired/applied revision parity through the
      existing gateway; baseline database/runtime/policy hashes are recorded.
- [x] A no-grant tuple returns `denied` with `no_matching_grant` and no writes.
- [x] Adding one disposable grant through the existing policy UI/API makes the
      same tuple return `allowed` with exact rule, gateway, policy hash/version
      and configuration revision; no data-plane probe is sent.
- [x] Expired grant, stale runtime, offline gateway, missing route, hostname DNS
      and suspended/revoked cases each render the exact fail/inconclusive step.
- [ ] Owner/scoped manager can view; unrelated member receives uniform forbidden
      and released DOM absence.
      Owner live proof passed. Exact-current API/DOM tests substitute for the
      unrelated-member leg until `next staffed AWS DEV member-session walk`.
- [x] Rapid DEMO -> demo2 -> DEMO and fast input changes clear/ignore stale
      results before late responses commit.
- [x] Repeated evaluator calls leave all durable row hashes, desired/applied
      revisions, policy hash and gateway/runtime state byte-equivalent.
- [x] Cleanup removes only F08 disposable agent/rule/resource and managed VM
      paths; harness cleanup-check and shared service health pass.

## Required redacted artifacts

- `walk-artifacts/F08/<run>/provenance.md`
- `walk-artifacts/F08/<run>/deny-allow.md`
- `walk-artifacts/F08/<run>/blocker-matrix.md`
- `walk-artifacts/F08/<run>/released-route.md`
- `walk-artifacts/F08/<run>/no-write-and-cleanup.md`
