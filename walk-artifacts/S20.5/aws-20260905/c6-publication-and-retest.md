# C6 publication and AWS retest

User explicitly approved publishing six images (including enterprise API),
four Helm charts, and deploying replacement source
`2c8445f94ca73b98b556215437e5b7943aada4f6` on 2026-09-06 IST.

Verified principal `arn:aws:iam::735391218823:user/aws-cli`, account
`735391218823`, region `ap-south-1`; EKS task cluster ACTIVE in
`vpc-05cbd22769f527e55`. Root checkout remains clean and unchanged.

Clean detached build source: `/private/tmp/tunnex-s205-c6.CmPue8/source`.
Candidate version: `0.0.0-walk.sha2c8445f94ca73b98b556215437e5b794`.
Six linux/amd64 builds succeeded, maximum concurrency two. Two initial local
build attempts failed before compilation/upload because the isolated Docker
authentication directory lacked the build plugin/context; corrected only the
local build environment. Native CLI and embedded node/operator versions match.
Operator's network-disabled probe exited for deliberately absent CP URL.

All six images were pushed to the existing immutable repositories under
`735391218823.dkr.ecr.ap-south-1.amazonaws.com/tunnex-s205-aws-20260905a`;
remote image digests matched local build IDs. All four charts were published,
then privately pulled and byte-compared successfully with the candidate bundle.
Private build/publication logs and manifest reside outside Git in the build
directory. No credentials, certificate bodies, or keys were emitted.

Dashboard device move: connector A3 → `tunnex-s205-edge`; UI reported
**1 moved, 0 require configuration re-import**, with A3's homed count zero.
No gateway was revoked. This is placement evidence, not fresh VPN proof.

Before CP rollout, effective configuration comparison proved only API/web/nginx
image references and the three API candidate metadata values differ. Caddy,
old node-agent, Postgres, Redis, volumes and all other settings are unchanged.
The Scale license was valid; CP health returned 200. The C6 override was
installed as a new file; original deployment environment and C5 override remain.

CP rollout completed around 23:47 UTC: API `071d3428fe3a`, web
`3e88e60ef606`, nginx `8911c64f208b` healthy. Caddy `64e95d0b321e`, old
node-agent `80259b6ef9e4`, Postgres `59a305613856` and Redis `d819881e8ef9`
were unchanged. Subsequent health 200 and valid Scale license confirmed.

Native A3 upgrade started next. Its replacement reused the stored identity
and passed the two-heartbeat CNI admission, but startup GET returned HTTP 500
and it entered CrashLoopBackOff. The existing authority revision 153 was
created 23:40:01 and expires 23:50:00; no expiry/authority state was modified.
The command remains within its native five-minute atomic upgrade window at
this entry. B2 and edge upgrades are paused pending its outcome. This is not
a passed upgrade or HA leg; no remedial restart was used.

Fresh HA results remain pending. No PR or merge;
NLB remains skipped, not passed. Historical C5 traffic is not C6 acceptance.

## A3 recovery and fresh exact authority acknowledgments

Native A3 upgrade ran 23:48:01.050–23:50:20.344 UTC, **exit 0**. After
revision 153 expired naturally, startup recovered without another mutation.
The same A3 node/PVC returned Ready on C6. This records the transient crash
honestly; it is not a claim of uninterrupted access or instant recovery.

New authority revision 154 was created 23:50:02.013187. A3 acknowledged it
at 23:50:09.589253 and B2 at 23:50:26.055473. This is the first recorded
pair of exact acknowledgments since the duplicated-peer blocker. A3 kernel
readback now shows one edge peer retaining ordinary `172.31.0.0/16` after
the pool fence, with no desktop peer left on A3. The peer correction is
therefore supported by fresh wire evidence; complete fenced HA and client
recovery are still separate pending proofs. B2 native upgrade started next.

## Remaining C6 upgrades and next live refusal

B2 native upgrade completed 23:50:39.550–23:51:18.226 UTC, exit 0;
edge completed 23:52:05.511–23:52:43.199 UTC, exit 0. Host-posture normal
Helm upgrade completed at revision 2 (23:53:55 UTC start), exit 0. No
credential replacement, PVC edits, or remedial rollout restarts were used.

At 23:52:02.703512393 UTC A3 rejected the ownership serving overlay because
the actual nft listing used `dnat ip to jhash ...`, whereas the emitter and
receipt parser expected `dnat to jhash ...`. Both Nginx backends remain
present (`10.240.10.149:8080`, `10.240.10.98:8080`). Automatic compensation
withdrew the incomplete overlay; fenced HA remains **BLOCKED**, not passed.
The bounded correction is papered in
`docs/S20.5-nft-dnat-readback-correction.md`. C6 is not the corrected candidate.

Fresh readback after all upgrades: A3/B2/edge each Running and Ready 1/1;
host-posture desired/current/ready/up-to-date/available all 3. A3 retained
its four startup restarts; B2 and edge had zero. Readiness does not satisfy HA.

Local correction verification: typed-printer regression failed before the
change, then package race tests passed. An opt-in Linux test applied and listed
single/two-backend rules in a fresh network namespace; nft 1.0.9 printed
`dnat ip to` and both original digests validated. This is local proof only.
Independent review raised **P2 (HOLD)**: that kernel test uses hardcoded rules
in an inet table, whereas production uses the actual emitter in an ip table
and different listing options. Repair the test to exercise the production
path after disposition; do not treat the current probe as full path coverage.

P2 disposition approved and folded on 2026-09-06. The corrected isolated test
uses resolvedVIP → dnatRule and RequestedK8sDNATReceipts, `table ip tunnex`,
and plain `nft list table ip tunnex`. It passed: single-target output used
`dnat to`, while the two-target map used `dnat ip to`, both matching their
requested digests. Egress race rerun passed. Full `make test-node` passed
for the product correction before this test-only fold; no AWS HA acceptance
is inferred from these local results.
