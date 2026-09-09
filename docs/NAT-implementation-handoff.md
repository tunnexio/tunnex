# NAT implementation: consolidated pickup

As of 2026-09-09. Discover local repositories/worktrees; do not depend on paths
or cached credentials from a previous laptop. Verify live Git and remote refs.

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
