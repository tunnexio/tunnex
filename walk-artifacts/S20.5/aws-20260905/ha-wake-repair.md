# HA wake/authority repair — 2026-09-06

Status: wake-only standby repair PASS; sustained post-takeover renewal FAIL.
All faulted deployments restored. This is the targeted
acceptance path, not a restart of the historical eleven-leg checklist.

Decision: [acknowledged-base reuse and pending delivery cursor](../../../docs/S20.5-ha-acknowledged-base-reuse-decisions.md).

## Reproduction and bounded correction

The exact pre-fix API source `bb9ef15` reproduces renewal starvation in both
editions with a deterministic real-PostgreSQL runtime/authority/lease test.
Three cursor-only wake changes increase authority rows from 6 to 9, 12 and 15,
while the serving expiry never advances. The silent standby had already ACKed
the initial arm and ordinary base. A paired MTU/content-change control correctly
keeps renewal blocked until the final member's exact acknowledgement.

The fix reuses only the latest acknowledged ordinary delivery when canonical
content, classifications and generations are unchanged. It preserves its
immutable receipt tuple. Pending delivery responses may echo the original
earlier cursor only for exact principal/full-hash matches; future versions and
changed bytes still refuse. Scheduler capture now precedes compilation.
There is no node production, protocol, migration, lease-duration or grant change.

## Targeted verification

- New regression is RED before the repair and GREEN after it, both editions.
- Directly affected API node tests: 21 top-level tests plus subtests in each
  edition, PASS (open 14.901s, enterprise 14.648s). Includes seven independent
  store cases: immutable accepted replay, hash/classification/generation changes,
  unACKed cursor change, no historical receipt reuse, and strict transition replay.
- Existing bootstrap/expiry, ACK locking/read failures, canonical and principal
  checks remain passing. Test databases are independently owned and cleaned by
  their fixture; final task database schema is 136, clean.
- HTTP exact pending tuple, receipt, current cursor resumption and negative
  identity/hash/future/zero cases PASS in both editions.
- Node cursor-pin tests PASS: strict tuple checking remains, an earlier cursor
  conservatively retains an unrelated released fence, and the current cursor
  restores its prior projection. No inference of unfence or receipt relabelling.
- Canonical `make build-editions` PASS, both API editions.
- Independent bounded source review found no concrete P1/P2 in this production
  diff. This does not substitute for final story review or live acceptance.

Affected node API logs SHA256:

- open: `418d5dd92e43fd6e9a4c3d3e84c65d4cbae0cc666efe00a1fb1dd0c952707123`
- enterprise: `56babf3fb3969176ee76f5c61305a04df275cf496f0e9c8b291efb0b63b4ef44`

Logs remain task-local; no credentials, kubeconfig, certificates or private keys
are included. Earlier exact `48f96b0` CI is fully green but is not final-HA CI.

## Live pre-retest observation

Read-only account verification returned AWS account `735391218823`, principal
`aws-cli`, region `ap-south-1`; main remained `0f3d9b0`. All three existing
gateways were Ready on node digest `147a81bd…`; the old API was healthy on
`0c33825f…`. Fresh laptop IP/DNS probes initially timed out, then both recovered
without intervention. This is intermittent traffic, not a healthy baseline claim.
No machines, charts, client settings or cloud resources were changed for setup.

Next: publish/deploy only the reviewed API candidate, then baseline and bounded
standby/owner fault/recovery probes with original identities preserved.

## API-only publication and deployment

Product source: `e6a56a41282e5368cb99e7adb4281db4887eb72f`, built from its
clean detached worktree with the committed Dockerfile, enterprise tag,
linux/amd64 and OCI source-revision label. Private ECR tag
`tunnex-s205-aws-20260905a/api:ha-e6a56a41282e` resolves to
`sha256:c733301c9423154ae6523a4a3d509ba7f3d9e28468b9a36d0bfd5331ddcb424d`.
The CP pulled this exact digest; image inspection confirmed amd64 and the
exact source label. Effective Compose comparison verified the API image was
the only configuration change, without exposing private configuration.

At 03:52:17 UTC the already-authorized retained licensed CP was updated with
`up -d --no-deps --pull never api`; replacement API started at 03:52:27.466 UTC.
No gateway, chart, database service, client setting or machine was recreated.
Existing candidate metadata remains C7; this is a truthfully mixed-component
sandbox repair, not a newly signed unified release. Node production remains
`dc70c9b` / digest `147a81bd…`.

Full node ownershiplease race suite PASS (2.769s) and both independent bounded
reviewers found no P1/P2 in the API correction. Exact-source
[CI run 34009930693](https://github.com/tunnexio/tunnex/actions/runs/34009930693)
is running in parallel; its result is not yet claimed green. AWS fault proof
and final story review remain pending.

## Post-deploy baseline

03:53:01.701–03:53:29.374 UTC: six fresh rounds, **12/12 HTTP responses**
with the expected marker through private IP and normal split-DNS FQDN.
No curl host override or client DNS/routing modification. A3 remained active,
generation 3, fenced HA; all gateway deployments Ready 1/1, unchanged images.
API health was verified healthy. Baseline JSONL SHA256:
`85693e80e9dbf33adc4a6d820f6b71e0becdb4c5bc886b53c76a6def4f8acc3e`.

At 03:53:53.333 UTC B2 was scaled from one replica to zero after fresh checks
confirmed A3 owner/generation and all deployments Ready. This is intentionally
a standby-absence regression, not reverse active-failover evidence. The probe
has a restoration path; results will be recorded after restoration.

## Standby absence/return — PASS

B2 was restored at 03:55:52.300 UTC, after **118.967 seconds absent**. During
absence 22 paired rounds passed (44/44 requests); during return 18 paired
rounds passed (36/36), ending 03:57:27.244. A3 remained owner/generation 3
throughout. The separate pre-fault pair also passed. All deployments returned
Ready 1/1 and the manager stayed Ready 3/3.

Read-only durable evidence at 03:55:17 UTC shows A3 serving lease epochs
261–264 advancing expiry through 03:54:30, 03:55:00, 03:55:30 and 03:56:00,
while both nodes' latest base-authority revision remained 420. Renewal no
longer needed a fresh unchanged-base standby ACK. B2's new pod started at
03:55:58 UTC, Ready with **zero restarts**; the earlier startup-500 recurrence
was not observed. The original A3/B2/edge PVC UIDs remain unchanged.

Standby JSONL SHA256:
`b121fbd7c2addf7a3d38492abe40106dd06a768074258348c01aba386685e34d`.
This establishes bounded standby absence and return, not unbounded outage
continuity or generic startup recovery. Active-owner fault proof is next.

## Active-owner fault — takeover observed, sustained renewal FAIL

A3 was freshly verified as the active owner/generation 3 with all deployments
Ready and healthy pre-fault traffic, then scaled to zero at 03:57:40.098 UTC.
B2 became owner/generation 4 by 03:58:39.949. Both IP and FQDN first recovered
at 03:59:03.983, **83.885 seconds after the fault**. This is automatic recovery,
not seamless failover.

The longer hold exposed a distinct remaining failure: requests failed again
at 04:00:09.631 while B2 remained owner and A3 was absent. Read-only database
evidence at 04:00:49 shows B2's sole serving epoch 270 was issued 03:58:44.735
and expired 04:00:00, with no subsequent serving renewal. B2 ACKed its new
generation-4 ordinary authority revision 421/hash `9b9d4f89a9ca…`. A3's desired
base genuinely changed from `1c3a627d2662…` to `d48deef6326c…`; its revisions
421–425 remained unACKed while it was absent. The existing all-member barrier
therefore still prevents the new owner's continuing renewal after a handoff.
This is not another unchanged-content cursor case and cannot be declared fixed
by the acknowledged-base replay correction.

A3 was restored by the fault script at 04:01:34.054. Traffic recovered by
04:01:53.252. Automatic failback to A3/generation 5 was observed by 04:02:45.118,
with another interruption during that transition; both paths recovered by
04:03:08.847 and remained successful through 04:03:31.023. Final readback at
04:03:32 confirms every deployment Ready 1/1. No remedial rollout restart,
SCP product patch, host/CNI/Secret/PVC edit or client repair was performed.

There were 19 fault-stage and six return-stage paired rounds with at least one
failed request. The sampler's completed process is not an acceptance result:
the **sustained active-owner test is FAIL** despite initial recovery and final
healthy state. No PR or merge is justified as completed proof yet.

Active JSONL SHA256:
`491a2d1a463d506f35841fe84893e5851507c80097469384c4ac57c0bfc0ade5`.
Next correction must explicitly model the already-fenced-out previous owner
versus continuing current-owner renewal, retaining exact current authority,
completed handoff/expiry proof and future candidate admission. Do not remove
the general changed-base ACK barrier merely to pass this test.

## Second correction — immutable API deployed, live retest pending

Source `fa6d851b8f3343e74f3f0244c618c22413378fce` adds proof-gated retired-owner
renewal in a single transaction with all resulting leases; future candidate
admission still requires the latest exact ordinary-base ACK. See the
[decision and local red/green controls](../../../docs/S20.5-ha-retired-owner-renewal-decisions.md).

Built from a clean detached source and published only to the verified private
AWS account `735391218823`, region `ap-south-1`, immutable API repository
`tunnex-s205-aws-20260905a/api`, tag `renewal-fa6d851b8f33`.
Manifest digest:
`sha256:ab718b31a7d0abe7b34602cd1fa1205adf0f7bebb2a9d39ea75ba61c57c3fe0d`.
AMD64 manifest:
`sha256:e1347d12ec56f32fdc536e81be5691dca92d7fb7f4da19405969d9640dbd016e`.
The CP image's OCI revision matches the exact source SHA. Private effective
Compose comparison confirmed that only the API image changed. The existing
licensed CP's API started at **04:35:23.823674141 UTC**, running and healthy.
Gateway/client images, identities, PVCs and other CP services were not changed.

The prior source `e6a56a4` CI run 34009930693 completed successfully. Exact
second-source CI [34011797134](https://github.com/tunnexio/tunnex/actions/runs/34011797134)
has been started; it is not yet reported green. Retain the passing standby
evidence above; repeat baseline and the failed sustained active-owner sequence.
Deployment is not itself acceptance. No PR, final checkpoint or merge yet.

## Second correction — targeted active renewal proof PASS with measured outages

Baseline passed **12/12** IP/FQDN requests (04:35:43.778–04:36:11.534 UTC),
all three gateways Ready, A3 owner/generation 5. Baseline JSONL SHA256:
`e24cb7bf3dcf1c46c4603a762ae132c205f27665f9d6af12286c3ad4e9fa2837`.

A3 was scaled down at **04:36:26.205**, after fresh owner/readiness/traffic
guards. B2 took over generation 6. Both paths recovered at **04:37:50.349**,
**84.144 seconds** after the fault. All **42/42** requests from that recovery
through 04:39:42.144 passed while A3 stayed absent. There was no repeat outage
after takeover; the sustained healthy observation lasted 111.795 seconds.
A3 was restored at **04:39:43.505**, after **197.300 seconds** absent.

Read-only CP evidence confirms actual continuing renewal, not just HTTP recovery:

| B2 generation-6 lease epoch | Issued UTC | Expires UTC |
| --- | --- | --- |
| 342 (initial takeover) | 04:37:15.495897 | 04:38:30 |
| 343 | 04:37:44.088595 | 04:38:30 |
| 344 | 04:38:04.088250 | 04:39:00 |
| 345 | 04:38:34.088766 | 04:39:30 |
| 346 | 04:39:04.088216 | 04:40:00 |

At 04:38:26 A3's genuinely changed base revision 429/hash `d48deef6326c…`
was unACKed; B2's revision 423/hash `9b9d4f89a9ca…` was ACKed. The generation-6
handoff was complete with prepared/serving ACKs and CAS audit. The retired A3
serving epoch 341 expired 04:37:30. No expiry or ACK was manually changed.

Returned A3 pod `tunnex-s205-a3-tunnex-gateway-5486fb9c8d-btg4l` started
04:39:43, Ready with **zero restarts**. All original A3/B2/edge PVC UIDs were
unchanged. A3 genuinely ACKed revision 432 before automatic failback. A3 became
owner/generation 7 by 04:40:52.517. Failback caused a separate interruption:
first failed pair 04:40:43.173, full IP/FQDN recovery 04:41:33.353 (50.180 seconds
between those samples). This is **not seamless failover/failback**.

The active sampler recorded nine failed fault-stage pairs before takeover
recovery and six failed return-stage pairs during failback. Its exit was **1**:
the fixed return window ended with only two healthy pairs, below its three-pair
final stability check. Do not relabel that process exit as green. Without any
intervening mutation, a read-only continuation at 04:41:43.452–04:42:11.049
passed **12/12** additional IP/FQDN requests with A3/generation 7 and all gateways
Ready. The combined observation completes the bounded final-stability proof;
there was no repeated fault, remedial restart, or host/client repair.

Active JSONL SHA256:
`85a71eb9d636ed306a99c7decda1ab0eb4064a3975677daea50ab347a10660dc`.
Final stability continuation JSONL SHA256:
`f0960d2b215f8627c9cdc2640856d612d4900247f6dc9b33d19e2376625a4120`.
The earlier sustained-renewal failure is fixed on this live API candidate.
This permits the requested draft PR, not exhaustive walk completion or merge
clearance. Historical review holds, final-head CI and fresh merge approval remain.
