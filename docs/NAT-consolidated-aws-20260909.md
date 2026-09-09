# Consolidated NAT candidate: AWS qualification in progress

Server content commit `0b1dd1554221e9c00cd610c2c14a7f5048b14cc3`;
client content commit `55f4267763d5ba906a187e0a120067b0fb910256`.
No release, push, merge, or exact-head CI completion is claimed.

Account 735391218823/ap-south-1 and exact CP/gateway instance identities verified.
Only the dedicated `tunnex-byodb-neon-20260906b` API and
`nat-product-gateway-20260909a` were replaced; no infrastructure deleted.

## Deployment and regression evidence

- CP migrated through 141, dirty=false. Candidate API initially healthy;
  HTTPS health returned status=ok. Codegen drift check passed locally.
- Candidate Linux enterprise test executable ran against the actual hosted
  walk database inside AWS CP. Credential tests and device/owner/org quota
  concurrency tests passed. Durable mailbox creation exceeded its unchanged
  five-second transaction deadline on two isolated attempts. NOT a pass.
- Rolled gateway back to retained executable. API rollback initially failed its
  startup migration against the newer schema. Retained additive 141 tables and
  restarted the former API with an explicit `TUNNEX_AUTO_MIGRATE=false` rollback
  override; HTTPS health then returned status=ok. No schema downgrade/data deletion.
  Current rollback requires `compose-rollback141.yaml` in addition to the existing
  base and lockfix files. Do not omit that override when restarting this old API.
- Investigating excess full-topology reads: gateway selection loaded DNS,
  subnets, device pool and Kubernetes inventory unnecessarily. Shared hub-member
  reader extraction keeps existing HA derivation and five-second deadline.
  Local connectivity/node race suites pass; hosted regression is still pending.

## Mac helper artifact correction

First install attempt mistakenly packaged a Go library archive instead of the
helper command. launchd could not execute it. Corrected build explicitly targets
`./cmd/tunnex-helper`; verified Mach-O arm64 executable and native caller auth.
User reran the installer. Helper now responds Down. Installer validates format,
version, hashes and post-bootstrap service status; original working binary remains
at `/private/tmp/tunnex-helper-finish-rollback.HCfznf/previous` on this laptop.
Installed signed executable SHA256:
`ea1baaabad730b8df9d43194606083051652cb32449dae83f3aab40db682230f`.
No new-helper end-to-end pass yet. No private keys, tokens or credentials recorded.

## Subsequent client/helper wire PASS (server rollback retained)

Corrected helper plus built client 55f4267, native production controller/owner
queue driver, old API/node rollback builds: generation22 negotiated measured
Relay path and allowed HTTP200 with expected body. Restarted only the dedicated
TURN container once. `relay_negotiation_changed` triggered automatic fresh
generation23; measured Relay and HTTP succeeded again. Exit0; helper Down and
temporary credential revoked. This qualifies this native controller/helper path,
not full Electron IPC/GUI, candidate API, or HA re-home to another gateway.
An earlier attempt failed `relay_gateway_timeout` because the gateway had exited
when started during CP rollback downtime. After CP health, explicit gateway
start reached `agent_ready`; only the subsequent successful attempt counts.

Hosted full-mailbox test was NOT isolated: a CP controller modified synthetic HA
state and created append-only audit records, preventing fixture hard deletion.
The one remaining test org is 28a7494f-0fe9-48c7-9220-c78a74ca1aa3. Preserve audit
records; soft-disable this synthetic org, do not bypass append-only protections.
An isolated database `nat_finish_20260909` on the same hosted service is being
prepared for a focused HA/ownership regression. The main walk DB is not a valid
target for standalone service fixture tests while its controllers are running.

## Isolated hosted HA/ownership PASS

Fresh `nat_finish_20260909` database migrated to 141, dirty=false. Focused
`TestGatewayMoveOwnershipPostgres` ran inside AWS against that database and
passed in 28.83s (fixture setup plus multiple independently deadline-bounded
operations). Same-owner HA recovery, old/new-owner stale-session read/publish/
close denial and fresh new-owner/active-gateway binding all passed. No background
CP controllers target this DB; fixture teardown succeeded. This is a real hosted
database contract proof, not an actual two-gateway encrypted data-plane failover.

Latency reduction content commit `46b19d437bcff3424d204cb955b8c663a828ba4f`;
Linux API SHA256 `9efd3508c47f635aee135453d2d515ac546e8775429d73cd292b57f3e2fd023c`.
Both-edition local connectivity race tests, nodes race suites, API builds/vet,
bounded independent read-set review pass. Final client main-process suite is
318/318 passing; helper race suite passes. Five-second DB transaction and
30-second forwarding deadlines are unchanged. Newly combined live run pending.

The stranded synthetic org above was soft-disabled (one row), not hard-deleted;
its audit history remains intact and the soft deletion is recoverable.

## Combined candidate wire: initial success, recovery FAIL

Verified running API hash matches 46b19d4 and gateway executable hash is
`f7b1c01640e7ca9695c9dce10215794858ba2dd499b4715d9e9977b6d7303b1e`.
With client55f4267 and corrected installed helper, generation24 negotiated Relay
and the driver's allowed HTTP passed. The actual dedicated TURN restart then
failed bounded automatic recovery: `relay_transport_lost` requested fresh Connect,
but that attempt timed out. Driver exited1, brought helper Down and revoked its
temporary bearer. Two ad-hoc curl probes overlapped the disruption and timed out;
they are not a denied-policy proof.

During this failure ordinary CP requests also degraded: `/nodes` HTTP500 at its
30-second deadline, `/auth/me` approximately8.4s, `/devices` approximately14.9s.
Gateway ownership-delivery polling reported repeated context deadlines. A later
DB snapshot showed four idle client-read backends and only the diagnostic query
active: no observed lock wait at that instant. This does not establish the cause
of the earlier slowdown. Do not claim an ICE root cause, fixed loaded CP latency,
or combined final-build acceptance from the isolated database PASS.

Stop adding transport patches based on this failure. Restore the known working
API/node pair and investigate request/pool/DB round-trip timing under concurrent
CP workload before another candidate deployment. Do not extend authorization
deadlines or repeat the entire historical walk. The failure is reproducible only
as recorded; the new source is committed, not release-ready.

Final safe state verified: rollback API HTTPS health returned status=ok; old node
restarted after CP health and logged `agent_ready` at 2026-09-09T11:11:01Z.
Corrected Mac helper remains installed, Down. Both product worktrees are clean.
No code pushed, PR opened, merge or release performed. The isolated hosted test
database and rollback artifacts remain available; no customer credentials or
audit records were removed. Candidate images are retained but not active.
