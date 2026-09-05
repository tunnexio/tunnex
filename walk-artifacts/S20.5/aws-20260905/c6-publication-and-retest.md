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
