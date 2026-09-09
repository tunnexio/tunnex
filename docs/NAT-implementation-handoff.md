# NAT implementation: consolidated pickup

As of 2026-09-09. Discover local repositories/worktrees; do not depend on paths
or cached credentials from a previous laptop. Verify live Git and remote refs.

## Current re-entry override

Latest continuation supersedes the historical paragraphs below. Server product
is consolidated at `0b1dd15`, followed by hosted-latency reduction `46b19d4`;
client product is committed at `55f4267` in its separate repository. Read
`NAT-consolidated-aws-20260909.md` FIRST for current artifact hashes, schema141,
rollback override, isolated hosted ownership PASS and combined recovery FAIL.
Both worktrees are consolidated; do not assume runtime changes remain dirty.
Latest full client suite318 passes. Corrected Mac helper is installed and Down.
Next narrow issue is loaded CP request latency during recovery, not another broad
NAT review or repeated historical proof. No merge/release readiness is claimed.

### Historical UI/backend checkpoint

Latest local UI continuation: Settings → Network relay card includes inline
coturn setup/verification/rotation guidance, no new navigation. Uses the generated
profile type. A failed or ambiguous save clears secret input and requires an
authoritative reload before another write; no stale-revision blind retry.
Focused tests cover read-only controls, secret omission/clearing, confirmed
removal, conflicts/network errors and cross-org response isolation.
Server web typecheck/build and full 112-file/1303-test suite pass; one additional
late-save/org-switch test was added afterward, with the final focused suite
passing 11/11 tests. This does not
resolve the separate client repository's missing renderer census fixtures.
No AWS or installed-client update. Gateway readiness telemetry and customer
deployment packaging are still missing; inline help is not a coturn installer.

The original backend-only checkpoint below is historical. Server evidence tip
before this update is `3826c37` on `codex/nat1-session-contract`. Read
`docs/NAT-product-aws-20260909.md` for completed, scoped live evidence and
`docs/NAT-runtime-integration-progress-20260909.md` for the integration state.
API/profile, node runtime, Settings and generated-contract changes remain dirty;
do not overwrite, discard or assume the evidence commits contain product code.

Client branch `codex/nat0-desktop-proof` has the managed relay integration and
Windows split-backend wiring in its worktree. Read its
`docs/NAT-1-managed-connect-progress-20260909.md` current pickup section.
Windows decision `f9eecd3` precedes the wiring; Windows native acceptance is
still pending. Full-tunnel relay remains explicitly refused.

Latest node-only correction: classify a selected pair containing peer-reflexive
or unknown candidates as unknown unless either side is explicitly relay. This
matches desktop diagnostics. All 25 candidate-type pairs are covered; package
race tests and vet pass. No packet-forwarding logic, installed component or
cloud configuration changed for that correction.

Not merge-ready: customer deployment/readiness, remaining platform/routing/
lifecycle qualification, full final gates and independent review remain owed.
Do not rerun previously proven unchanged Mac scenarios just because the older
paragraphs below call them unimplemented. No release or merge approval implied.

## Current candidate

Repository `tunnexio/tunnex`, branch `codex/nat1-session-contract`.
Product/test content `2afd25278a2b81fd770cfc076cd90d9f39337cbd`, based on remote
main `26a36afc9be657af94127c474e173783c91318c3`. Subsequent commits are AWS
runner/evidence/documentation, not additional NAT functionality.

Built: authorized short-lived credential primitive; migration 139; bounded
transactional signaling store; owner create/read/publish/close OpenAPI endpoints;
dedicated permission; generated Go/CLI/TS/RBAC; tests. Default off. No UI yet.
Read `S-NAT-1-decisions.md` and `NAT-1-aws-20260909.md` before changing code.
Local both-edition focused tests/race/vet/build and generation check passed.
AWS native both-edition DB/router tests, migrations and server startup passed.
Independent review, full final gates and exact-head CI are not complete.

## Preserve proven work separately

- `tunnexio/tunnex`, `codex/nat0-transport-proof`, checkpoint `0e867dc`:
  `docs/NAT-execution-plan.md`, decisions and actual CP policy evidence.
- `tunnexio/tunnex-client`, `codex/nat0-desktop-proof`, checkpoint `092f7cd`:
  native Pion/coturn helper/kernel proof; live-tested source `c9edf1c`.
- `tunnexio/tunnex-web`: future customer instructions, not client/product code.

Do not merge experimental fixture code into production wholesale. Reuse the
proved adapter design; keep client code in its own repository. These refs are
local checkpoints, not a claim that they were pushed or are available remotely.

## Next narrow implementation

Gateway mTLS signaling via existing AgentChannel authentication, then relay
profile and credential delivery with transactional rate limits. Lock numerical
forwarding lease/CP-loss and peer restriction rules before transport integration.
Follow with node/client consumers and minimal existing-screen UI:
Settings → Network card, Gateway → Overview readiness, desktop path badge.
No new dashboard, wizard, fleet management or unrelated epic.

The AWS run proves the implemented backend slice, NOT full NAT end-to-end.
NAT-0 already proves feasibility; do not restart discovery. Product-level live
packet proof waits for the missing CP/gateway/client integration. Existing
signed install/release requirements are not satisfied by SCP.

AWS sandbox account 735391218823, ap-south-1. Dedicated test host
`i-0d320abd28be9eaa9` reused, temporary SSH ingress removed and stop requested.
CP/old DB stayed stopped. No new EC2/RDS required for this slice; disks/fixtures
retained. Recheck identity/state before any mutation and never assume old IPs.

No merge/release approval carries forward. Preserve all unrelated dirty work,
stashes, infrastructure and identities. Update this handoff with each real
acceptance result and one next action; never report implementation as complete
because the prototype or this backend slice is green.
