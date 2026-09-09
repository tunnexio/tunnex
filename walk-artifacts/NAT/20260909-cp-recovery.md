# Native relay recovery after CP latency reduction

Result: **PASS for this bounded scenario**, 2026-09-09, approximately
11:53–11:55 UTC. Not full NAT epic, GUI, platform, release or merge acceptance.

## Exact candidate

- Server product: `cddcd57`; client: `55f4267763d5ba906a187e0a120067b0fb910256`.
- Linux enterprise API SHA256:
  `30cc04168b5ae60e79a8e3b82ef2eb899b704577a79b104c11f3109343dc0860`.
- Gateway executable SHA256:
  `f7b1c01640e7ca9695c9dce10215794858ba2dd499b4715d9e9977b6d7303b1e`.
- Installed signed Mac helper SHA256:
  `ea1baaabad730b8df9d43194606083051652cb32449dae83f3aab40db682230f`.
- AWS ap-south-1; explicit Compose project `tunnex-byodb-neon-20260906b`.
- Running API image `tunnex-nat-product-api:readset-20260909`, image ID
  `sha256:23765dbd0ba8c678d8ea0c477315fa733709d179c94146db9e5d0015f54201a8`.

## Live sequence

Electron-hosted driver uses the built production tunnel controller, managed-owner
coordinator and installed native helper. It is not a GUI click-through or public
release test. Direct UDP remained blocked.

1. Generation26 create201, candidate publish200, mailbox read200.
2. Helper reported **relay**; private HTTP returned the expected proof body.
3. Restart only the dedicated TURN container once.
4. Client classified `relay_negotiation_changed` and invoked managed recovery.
   No manual Connect, helper restart or route/PF repair.
5. Fresh generation27 create201, publish200; helper reported **relay** and
   private HTTP recovered within the driver's bounded180s post-restart window.
   Recovery was not instantaneous.
6. Driver exited0. Both closes returned204; helper Down and temporary credential
   revocation confirmed. No bearer, key or configuration is stored here.

Redacted terminal evidence:

```text
CP session generation 26
Measured helper path: relay
Native allowed HTTP PASS; connection 1
Interrupting verified dedicated TURN container once
Terminal recovery classification: relay_negotiation_changed
Managed recovery received: relay_negotiation_changed
CP session generation 27
Measured helper path: relay
Native allowed HTTP PASS; connection 2
PASS: native Relay path and HTTP recovered after real TURN restart
Cleanup: native tunnel down; temporary bearer revoked
exit=0
```

## Limits and retained failures

Pool16 alone failed generation25 publish; the first three-lock batch failed
creation. Those failures remain in `docs/NAT-cp-pool-latency-20260909.md`.
Expanded read-set candidate passed. Hosted isolated timing saved about0.6s per
operation; this is not a high-load, arbitrary-latency or availability guarantee.

Focused both-edition/race tests, isolated local DB invariants, hosted configured
relay timing and two bounded reviews passed. Full exact-final gates/CI, broader
platform/packaging qualifications, PR and fresh merge approval remain owed.
Running API/node hashes were verified after the walk; gateway/TURN running and
CP HTTPS health status=ok. Mac helper remains Down after cleanup. Sandbox private
pool diagnostics are explicitly enabled (product default off). Rollback artifacts
retained; no infrastructure deleted. No push, PR, merge or release performed.
