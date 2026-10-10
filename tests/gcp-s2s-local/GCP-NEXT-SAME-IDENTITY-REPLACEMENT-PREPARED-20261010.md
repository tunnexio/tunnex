# Next same-identity GCP node replacement preparation

Source-only checklist; no source freeze, build, stop, creation or deployment performed. Root source dca77bf5 is an intermediate candidate while renewed shared-batch review remains pending. Do not substitute it for the final clean reviewed commit.

Historical source pointers, inspected read-only:

- `/private/tmp/gcp-cloud-replacement-4143d866-20261010/replace-phased.remote.py`, SHA256 fe71fc0e97a3f8a64e44917bfc4f1bdd669ceddeacaf58ee1b1b4bc25f3e75d3.
- `/private/tmp/gcp-cloud-replacement-4143d866-20261010/continue-phased.remote.py`, SHA256 24e574bfac42b2690fee8309fee6dcda75b039d242dd0cc627f0511a88847eed.

These templates are provenance, not reusable execution artifacts. They bind obsolete dc81/ccde identity and historical stop hashes. Both invoke `CREATE` without defining it in the inspected file: next rendered source must contain the exact reviewed create argv, with no runtime injection. Their assertions also prohibit optimized Python; do not run them with `-O`.

## Bind final immutable source and image

1. After shared review, capture clean root full commit/tree, all intended shared fixes and focused checks. Build from a detached clean source snapshot using tracked `deploy/docker/node.Dockerfile`, pinned native dependencies and exact VERSION/OCI revision label. Target linux/amd64 for the owned cloud VM; no heavy parallel build during lab proof. Record Dockerfile/source/dependency/build-command hashes, image ID and exported archive SHA. Independently inspect image binary, native tools and revision label before transfer. The image source label must be measured, never populated from an expected constant.
2. New replacement manifest must bind OLD CID5f77c5857fa78b0533eb4fddc46cc4a0e9c69369d8e7987ee068b88ec7ba8c2f, OLD image347bcb66318aa1b8ef1e949c6f57e28506e56a1497f2f4ae15b9ab74b8fed4c6, OLD revision4143d866ab97386411ff1ac4705aaa0e4579bcf6, boot9617762e-19db-4a21-bdee-909dfb31e501 and namespace net:[4026531840]. Final new full source/image/archive/reader/verifier hashes remain unset until actual qualification. Require a fresh unique name/evidence directory and absent name collision.
3. Preserve state `/var/lib/tunnex-gcp-s2s-cloud-20261010` and existing private env `/var/lib/tunnex-gcp-s2s-launch-20261010/node-wgctrl.env`. Retain old container; no join-token issuance, enrollment, cert/key/environment copy to host logs or journal rewriting. Pin existing identity file inode/device/size/mtime privately, and env content digest without printing contents. Exact launch argv must retain reviewed host-network, no restart policy, stop timeout45, wgctrl backend, loopback health/control endpoints, state mount, bounded privileges/capabilities and owned label. Verify actual old launch shape rather than assuming it.

## Fresh normal preflight and stop

4. Freeze ordinary API actors. Capture complete semantic resources/policies and both connection/config desired states. Preserve the current 13 resources/12 policies and disabled CAS QA connection; compare exact authoritative IDs/bodies, ignoring only documented read-time projections. No new grants/resolvers/FQDN edits during replacement. Count alone is insufficient. Snapshot actual journal owner/version/sequence and immutable entries privately; output selected lineage hashes only.
5. Fresh preflight must bind boot/ns/process, assigned70.2/32 ens4, exact owned local70/24 proto242 route, complete routes/links, nft ruleset and managed process/SAD metadata without raw XFRM keys. Preserve full foreign topology. Actual complete guard readback requires exported production verifier and current expected guard; empty permits demonstrate refusal, not positive readiness.
6. Stop ONLY exact old CID once using normal docker stop45 with command deadline50. Record actual exit/OOM/running/readback outcomes in an exclusive private partial receipt. Do not automatically continue if stop fails or after ambiguous output. No generic nft/iptables flush, host reboot or link/route deletion.
7. Handle ordinary WG teardown narrowly: pre-capture exact owned wg0 link/routes and full source-owned ip/ip6 tunnex tables. The old historical allowance for one wg route and20 specific objects cannot be reused blindly. A removed object is permitted only if its complete pre-stop definition and the final source's normal teardown establish ownership; all foreign routes/tables must remain equal. Unexpected missing/additional objects refuse. This is deployment observation, not a new cleanup/restoration/absence receipt. Never alter the journal to make comparison pass.

## Create, start and independently qualify

8. Recheck stopped exit0/OOMfalse, immutable identity/env/journal lineage, retained topology and freshly verified complete permanent guard with empty permitsets. Guard ownership changes require a fresh bounded capture, not comparison relaxation. Preserve fresh evidence; no manual lease/receipt/gate modifications. Host-network shares the existing namespace and does not supply a namespace-empty Docker restoration proof.
9. Create the exact reviewed new container once; capture returned full64hex CID, then inspect actual image/revision/argv/state/envmount/labels before normal start. Use the returned CID for all later reads; never invent new CID from a proposed name. Exclusive receipts prevent same-path replay, not semantic duplicate creation.
10. Verify genuine health, enrolled same NodeID, wg0/native qualification, current capabilities/eligibility, actual accepted delivery/config, fresh managed SA/cardinality/route and complete guard. Preserve current API baseline exactly. HA and Classic readiness are independent; SA presence or health alone is insufficient. Re-run only changed-source acceptance cases after relevant positive authority gates, retaining all prior failures. No replacement helper fabricates runtime proof or claims production readiness from container start.

Final executable phases must be independently reviewed after final hashes are known. This checklist adds no new approval requirement to the already authorized owned lab scope; it prevents stale source/evidence replay.
