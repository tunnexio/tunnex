# AWS transit SNAT correction — local qualification

Product source: `dc70c9bc847925f43d19bff59306ebb63ef5c7ec`.
Decision records precede product code in `648c7b0` and `ade26c3`.
Private candidate version: `0.0.1-walk.1.shadc70c9bc847925f43d19bff59306ebb6`.

## Reviewed correction

Journal schema 4 adds a distinct AWS source-tunnel + ingress/egress `wg0`
return receipt and finite authority scope. Schema 3 stays destination-only;
schemas 1/2 stay IP-MASQ-only. Active epochs never migrate in place.
The startup observer accepts the new finite scope. An explicit ordered walk
sequence avoids accidental hash-lexical manager downgrades while preserving
full source provenance and the existing 50-character version boundary.

Self-review and independent reviews found no concrete P1/P2 findings in the
final product slices. Independent review also covered the final startup
fixture correction and its real-store two-advancing-proof regression.
This is slice review, not final story-end multi-finder completion.

## Local results

- Real candidate packaging contract suite PASS with Go 1.25.13 / Helm 3.18.4:
  default deterministic packages, ordered sequences 1/10/999, full provenance,
  four charts and CLI, and invalid sequence/version refusal.
- Linux host-posture package PASS, including old-schema byte preservation,
  schema-4 cleanup, historical cleanup refusal and baseline leftover detection.
- Linux k8snetprep package and scoped fake-runner race suite PASS, including
  partial insertion, duplicates, restart cleanup and expired authority.
- Native host-posture race PASS. Native Darwin `cmd/agent` build is unsupported
  by existing Linux data-plane symbols; that failed invocation is not a pass.
- Real Linux startup tests PASS, including schema-4 correlated two-proof
  admission and continued proof freshness across a slow startup.
- CLI/operator/helper/helper-crosscompile targets PASS on detached `1da06bf`;
  their component trees are unchanged by this correction. These are not
  inherited exact-final whole-story gate results.
- Initial full node/race invocations exposed an outdated test-only schema
  threshold: the fixture mapped schema 3 to IP-MASQ after the current schema
  advanced to 4. Corrected to preserve 1/2, 3 and 4 independently; full target
  rerun PASS (`cmd/agent` 100.203s and every node package green), and final
  Linux startup race PASS (11.761s) after correction.

## Real Linux packet witness (not AWS acceptance)

`TestAWSTransitKernelPackets` PASS with the actual C7 node image's nft/iptables
tools (iptables-nft-save 1.8.10) in a disposable privileged Docker container,
no network attachment or host network, and a nested isolated network/mount
namespace. A veth called `wg0` models ingress/egress; it does not substitute for
WireGuard cryptographic identity, live AWS CNI or the desktop client.

The production reconciler, native JSON parser and explicit compat readback
were exercised, not hand-written replacement exemption commands:

1. Destination-only legacy scope reproduces failed client-to-Service traffic.
2. New scope preserves source `10.99.0.2` to `100.96.0.3`; receiver source
   filtering makes a successful ping proof of the received source.
3. Reverse initiated Service-to-client traffic retains the Service source.
4. Same-pool source entering on `pod0` still receives AWS SNAT.
5. Client traffic leaving on non-WG egress still receives AWS SNAT.
6. An independent forwarding DROP remains effective with the exemption.
7. Production withdrawal restores source NAT; receiver accepts only SNAT source.

Each ping is a fresh process/flow. No conntrack flush is used. Exact foreign
rules/chain fingerprints, excluding only recognized owned returns and changing
counters, remain unchanged across reconcile and withdrawal.

Test-harness corrections before PASS: namespace sysctls needed a disposable
privileged container; the first fingerprint assertion incorrectly included
expected owned mutations; xt rule deletion matching was replaced with a
source-filtering deny inserted below the one SNAT-source accept. None of these
changed AWS, weakened product parsing, or repaired live networking.

## Live boundary / next transition

AWS identity freshly verified as account `735391218823`, principal
`arn:aws:iam::735391218823:user/aws-cli`, ap-south-1. Exact EKS cluster
`tunnex-s205-aws-20260905a` ACTIVE, VPC `vpc-05cbd22769f527e55`.
Existing A3/B2/edge pods remain Running with zero restarts and unchanged IDs.
No AWS mutation was used for this local proof.

Native transition: retain original PVC/PV and consumed claim identities;
uninstall B2/A3/edge through CLI, explicitly wait for restored old epochs and
idle manager/no owned artifacts, then reuse-install edge/A3/B2 with the new
published manager and gateway candidate. First install upgrades manager through
the native provenance path, subsequent installs reuse it. Verify new epoch =
old + 1, schema 4, unchanged node/WG identities and PVCs. No journal, Secret,
PVC, CNI or Helm-history edits. This entails a deliberate sandbox gateway
outage and is retained reuse evidence, not a fresh empty-cluster baseline.

Live IP/FQDN and HA legs remain pending. NLB remains SKIPPED. No PR, merge,
release, exact-final CI or story-complete claim is made here.

## Publication and pre-transition checkpoint

All six linux/amd64 images and four charts were built from clean detached
`dc70c9b`, published to the existing immutable private ECR prefix after exact
account/repository checks, and their image digests verified. Every image has
the full source revision label. All four privately pulled chart archives
compare byte-for-byte with local bundles. No public artifact was published.

Node/manager image:
`sha256:147a81bdfb1818a2a168a5b7f29ead9f28d1ce6a0fe1cf6bc72480962e5d70fc`.
Native CLI reports the exact candidate version. The packet witness was also
rerun in this new node image and PASS (3.26s), not only the old C7 tool image.
GitHub reports zero check runs for the product SHA; not exact-SHA CI green.

Before transition, A3/B2/edge each have active schema-3 epoch 2, one owner,
and a committed owned `wg0`. Native status confirms manager revision 3,
healthy 3/3 and original C5 image. Original retained identities:

| Role | PVC UID | Lifecycle claim |
| --- | --- | --- |
| A3 | `355a26b0-022d-4710-b10c-85fae3375418` | `f6fb3425-bfef-483e-b879-2faefb341917` |
| B2 | `8eb91d90-453a-4412-b18c-8e28d587caae` | `3fb061eb-63c9-486c-8590-a57a86801f64` |
| edge | `78f384ac-4ef7-447f-ac60-77ef44a43089` | `a8654d15-6140-4d08-a164-94a3c786f4bd` |

All remain Bound to original matching PVs; failed A/A2/B fixtures are untouched.

## Old epoch withdrawal

All three CP lifecycle claims were read-only verified `consumed` into their
original A3/B2/edge node IDs before removal. Native CLI uninstalls succeeded
in B2, A3, edge order, retaining each original PVC. No purge-state was invoked.

All three managers subsequently proved schema 3 / epoch 2 / `restored`, no
owners, idle heartbeats and revoked CNI authority. Host readback showed no
`wg0` or posture-aliased link, and no Tunnex-commented nft rules. Heartbeat
sequences at this check were A3 2197, edge 2195, B2 2198. The old manager
remained healthy; no manual restoration was necessary. Gateway outage is
intentional during this retained-reuse/new-epoch transition.

## Native schema-4 edge reuse

Edge plan PASS, selecting manager `upgrade`, retained PVC and original endpoint.
Native install ran 02:07:34.251–02:08:30.023 UTC, exit 0. Manager revision 4 is
deployed with honest `tunnex-zero-touch/v1` description and the new digest;
all three manager pods are Ready. Edge now has active schema 4 / epoch 3 and
a matching granted `ip_masq_and_aws_transit` capability. Its original WG public
key is unchanged. Live AWS chain readback shows both destination and exact
source + `iifname wg0` + `oifname wg0` returns before unchanged foreign rules.
No manual networking mutation occurred.

A3/B2 reuse plans both PASS and select manager `reuse`, not another upgrade.
Their independent retained-state installations started concurrently only after
that manager rollout completed; exact original PVCs, host selectors and public
NodePort endpoints were checked. End-to-end traffic is not yet marked PASS.

## Client wire restored

A3 native reuse install PASS 02:10:02.690–02:10:49.704 UTC; B2 PASS
02:10:03.332–02:10:49.785 UTC. Both have active schema-4 epoch 3 and their
original WG public keys. All three gateway deployments are 1/1 Ready.

Unmodified local client route remains `100.96.0.0/24 → utun6`. Its normal
split-DNS resolver maps `s205-aws-eks.s205.internal.tunnex.app` to `100.96.0.2`.
No resolver/hosts/client-profile edit was made.

From 02:11:47.987 through 02:13:02.362 UTC, eight fresh IP and eight fresh
FQDN HTTP requests all returned `S20.5_PRIVATE_SERVICE_OK` (16/16, zero
failures). HA status stayed A3 active, `fenced_ha`, generation 1, epoch 0,
revision 181 across more than two 30-second lease periods. Full redacted
per-request timing receipts remain in the task-local `baseline.jsonl`.

CP node list reports fresh last-seen times and original node IDs but retains
the original C5 `agent_version` field despite actual new image digests. Do not
use that stale field as final-candidate provenance; investigate separately.
The new image/revision, live schema-4 rules and retained public keys are the
verified runtime evidence. This observation does not invalidate the measured
client traffic, but it is not a clean final provenance/UI result.

## HA first direction

After all three deployments were 1/1 Ready and continuous requests succeeded,
the exact A3 scale subresource changed `1 → 0` at 02:14:53 UTC. No template,
Service, PVC, pool, fence or role changed manually. Edge and B2 stayed up.

First failed request sample: 02:14:57.934. CP automatically reported B2 as
active at the 02:15:40.868 sample, promotion generation 2. Both IP and FQDN
requests first recovered at 02:16:16.553, and the next sample also passed.
Observed scale-to-first-success is about 83.6 seconds; the scheduler/lease
convergence outage is recorded, not represented as seamless failover.
No intervention occurred between scale-down and automatic client recovery.
A3 restoration and reverse-direction proof remain next.

## Member return, reverse-test correction and current blockers

A3 was restored to one replica at 02:16:50 UTC. Its returning container exited
once at 02:17:01.456 after startup desired-state HTTP 500; CP attributed this
to `Kubernetes ownership base authority does not match the exact desired base`.
Kubernetes restarted it automatically, and it became Ready with its original
identity. Requests were interrupted again from samples 02:17:00.963 through
02:17:22.380, recovering at 02:17:29.510 while B2 was still reported active.
No remedial restart or host repair was performed.

A3 automatically became active again, generation 3, by 02:18:22.425. B2 was
then mistakenly scaled to zero at 02:18:48 before that readback was used as
a mutation guard. This removed a standby, not the active connector: **it is
NOT reverse-direction failover proof**. B2 was restored at 02:19:32; its
original identity became Ready without a container restart. Requests were
interrupted from 02:19:33.077 through 02:20:22.933, recovering at 02:20:30.051
while A3 remained active, generation 3. Both connectors are restored to one
replica. Any next fault must condition mutation on fresh expected-owner,
readiness and working IP/FQDN checks, not merely print them first.

Fresh post-trial readback confirms A3/B2/edge each 1/1 Ready on the published
node digest and both local IP/FQDN requests return the expected marker.
Automatic first-direction recovery is demonstrated, but returning-member
interruptions and startup HTTP 500 are unresolved. Leg 9 is not complete.
No general startup-retry feature or named lifecycle deferral is implemented.

### Read-only durable-ledger correlation

Exact org/pool-filtered SELECTs in a read-only CP database transaction establish
a serving-lease gap, not just a temporal association with a returning pod:

| Receipt | Created (UTC) | ACK (UTC) | Expiry (UTC) |
| --- | --- | --- | --- |
| A3 serving, generation 3, epoch 110 | 02:18:32.014676 | 02:18:33.598102 | 02:19:30 |
| A3 base authority 275 | 02:19:27.009116 | 02:19:52.883331 | 02:25:00 |
| B2 base authority 274 | 02:19:27.009116 | 02:19:43.500674 | 02:25:00 |
| B2 base authority 275 | 02:19:57.008779 | 02:20:22.886426 | 02:25:00 |
| A3 base authority 276 | 02:20:02.005308 | 02:20:06.337171 | 02:30:00 |
| A3 serving, generation 3, epoch 111 | 02:20:27.016545 | 02:20:27.545678 | 02:21:00 |

There was no intervening serving delivery. A3 remained owner; its authority
expired **before** B2 restoration at 02:19:32. Therefore calling this purely a
return-triggered outage would be inaccurate: standby absence/pending full-base
ACKs already coincided with blocked renewal. Both members' base versions
advanced while their individual base hashes stayed unchanged across these
rows. The next serving delivery followed the last required ACK, and client
traffic recovered at 02:20:30.051.

Source `reconcileFencedPools` deliberately requires scope-complete exact
full-base ACK acceptance before renewing any serving/prepared lease. This
correlates the conservative renewal barrier with the observed gap; changing
that barrier requires a fencing-safety decision, not a shorter polling interval
or an unchecked retry. No deployment overrides the agent reconcile interval.

## Exact product-source local gates

At clean `dc70c9bc847925f43d19bff59306ebb63ef5c7ec`, generation, both-edition
builds, five non-packaging chart contracts, web typecheck/1,377 tests/build
and client typecheck/292 tests/build pass. The client's first disposable
Linux harness lacked Git; installing Git and mounting existing Git metadata
read-only corrected the harness and the full client rerun passed. This is
not native macOS/Windows CI or live CRD matrix acceptance.

Migration passed at schema 136. `make test-editions` remains RED: open passed,
enterprise failed in runtime credential promotion and bootstrap fixture
cleanup. Ranked findings held separately from the transit fix:

1. P1: unordered candidate promotion/current demotion can violate the immediate
   one-current credential index; authentication returns unauthorized.
2. P2: fixed bootstrap fixture hash collides after ignored cleanup failure;
   immutable audit records prevent the fixture's hard organization delete.
3. P2: runtime fixture closes its pool before registered cleanup, ignoring
   deletion errors and leaking test organizations.

Affected source is unchanged from main baseline `0f3d9b0`; that comparison is
not a full baseline test run. No index, audit trigger or assertion was relaxed,
and no fixture deletion or lucky-green retry was used. Redacted diagnosis and
logs are retained in the task-local API gate directory. Exact-SHA required CI,
the remaining lifecycle legs and story-end review still block acceptance.
