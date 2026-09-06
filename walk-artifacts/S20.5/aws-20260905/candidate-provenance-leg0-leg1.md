# S20.5 — candidate provenance and accepted Legs 0–1

2026-09-05 AWS continuation. Exact candidate source: `d2c9cba653d400e2dab3d7b038796efeee1f028c`.
Candidate version: `0.0.0-walk.shad2c9cba653d400e2dab3d7b038796efe`.

The executing root operator accepted **Leg 0 PASS and Leg 1 PASS: 2/11** after
the readbacks below. This record does not update any existing ledger row or
count. The first ordinary gateway-A install was running at this checkpoint;
**no Leg 2 result, enrolled agent-version readback, client connection, HA result,
cleanup/recovery result, complete gate result, or customer release is claimed.**
This AWS evidence does not establish AKS qualification.

## Immutable candidate and native CLI companion

[candidate-manifest.json](candidate-manifest.json) is the original packager
manifest copied byte-for-byte, SHA-256
`8b4ce669d5781799387f9b2ab47c235d6008e8c5e418859d4112569daf2986c8`. Its full source SHA remains the provenance authority; the
32-hex abbreviation in the candidate version is not a substitute.

[candidate-cli-chart-provenance.json](candidate-cli-chart-provenance.json)
separately binds the exact full source, candidate version, and original-manifest
checksum to the native macOS CLI and all four registry receipts. The original
manifest and bundle were not edited to add the native CLI.

| CLI artifact | Platform | SHA-256 |
|---|---|---|
| tunnex-linux-amd64 | Linux amd64; static ELF | `3a05f7e3dffd27d02215ead95df9b2d28853d85b9e431976287e09059a898aa4` |
| tunnex-darwin-arm64 | macOS arm64; Mach-O | `bcaf3bbf324635ad451bb99a1344105dc385108620e554de06de72f1d6a94758` |

Both actual executable `version` commands returned the exact candidate version
with exit0. The native binary used an independent `git archive` of the same
committed `apps/cli` source and the same version linker input. The Linux binary
was executed in a read-only, network-disabled container. Go1.25.13 and
Helm3.18.4 were used. Both packaging boundaries checked clean, unchanged source;
the six-entry original bundle checksum ledger passed after publication.

The original manifest binds all six runtime image digest references. Their
published identities, enterprise API build, and retained licensed CP deployment
are recorded in [candidate-deployment-evidence.md](candidate-deployment-evidence.md).
That earlier checkpoint's chart-publication-pending statement is superseded
only by the completed receipts below. Node/operator embed the candidate version;
API/web/nginx/migrate Dockerfiles do not consume VERSION. The node's exact
VERSION build input and embedded binary literal were verified, but the required
post-enrollment CP `agent_version` readback remains a Leg2 obligation.

## Four private OCI charts: exact-byte proof

The user explicitly approved the four chart uploads after the prior safety
refusal. Fresh STS proved account735391218823 and principal
`arn:aws:iam::735391218823:user/aws-cli`. The exact four task repositories were
IMMUTABLE and the candidate tags were absent. No alternate transfer bypassed
the earlier approval boundary.

Each chart was packaged twice and compared byte-for-byte before publication.
Every push, ordinary authenticated Helm OCI pull into a fresh private directory,
AWS digest/type readback, and archive `cmp` exited0. Each rehashed pulled archive
matched the original manifest, including chart version and appVersion.

| Chart | Original/pulled archive SHA-256 | ECR OCI manifest digest |
|---|---|---|
| tunnex-host-posture | `3d11408b21074c1e209543a9a4f9bbaf18e988d0a9cc3957be30e1c4ccc4705c` | `sha256:d1d64234ed9de1d5f227561f46e71beb5bff14b43d14fb5983dc07e80c8a7daa` |
| tunnex-gateway | `68ea7191ddfdd3d34f44ad5eadc4bc55c8884d3fef7aec5f1a24078d2746f5b9` | `sha256:0d2a81601af16510ecdad4c007e62ecddd841bee4bd250690791d8c5bd51f1c7` |
| tunnex-operator-crds | `221eaa3c47d1879d4f5ae62bf37daea84d3403002f06fc08e3f65ac08bfaa4ee` | `sha256:758118b7a2072d1918a82f63ed0a936c90227d3bf41e9c46cba6ef12cc4ea1b4` |
| tunnex-operator | `8fc34cf042fac607a406eb4dbeac6daca0f80455565ef78582abf70819361ea4` | `sha256:2e43e96b6c4f62b98459672bb96a3e5a4a24e6b207da0ce7f215d5590ed5c4ed` |

Every OCI reference is under
`oci://735391218823.dkr.ecr.ap-south-1.amazonaws.com/tunnex-s205-aws-20260905a/`.
AWS reported `application/vnd.oci.image.manifest.v1+json` with Helm artifact
type `application/vnd.cncf.helm.config.v1+json` for all four. Registry manifest
digests and chart archive hashes are distinct and are not interchanged.
No credential/config file content or private runtime path is committed here.

## Leg 0 — clean baseline accepted

The executing operator verified the exact three task workers, all with
successful SSM command exit0:

- `i-0afe3c3ecd00d1411`
- `i-0f6bb7eca4b726637`
- `i-03c1fb3619712c8d3`

SSM receipt `91f1a597-329c-40ae-9584-031e775fbd27`, at
`2026-09-05T13:42:07Z`, proved both
`/var/lib/tunnex/host-posture/v1` and final `wg0` absent on every worker.
Follow-up receipt `cf65a39a-71a2-4bc4-b0ad-89cfd55b6cab`,
`2026-09-05T13:42:57.965Z` through `13:42:58.005Z`, reported only loopback,
Ethernet and native veth interfaces; the WireGuard-link filter was empty on
all three. Thus no old final/staged WireGuard link or node-local journal was
present before first installation. These were metadata-only host reads:
no host write, repair, journal content, or state credential was involved.

The namespace/CP absence readbacks in Leg1 below completed the gateway-state
baseline. The root operator accepted Leg0 only after both host receipts arrived,
not from packaging, controller readiness or CP health alone.

## Leg 1 — ordinary read-only plan accepted

The root operator executed the exact native CLI's ordinary `k8s plan` for
`tunnex-s205-a` from `2026-09-05T13:38:16.872Z` to
`2026-09-05T13:38:26.532Z`, exit0. The command used the verified private OCI
chart versions and the digest-pinned candidate node image, not a manual Helm
install or local chart workaround.

[gateway-a-plan.stdout.txt](gateway-a-plan.stdout.txt) preserves the token-blind
canonical JSON rendering and printed digest byte-for-byte; file SHA-256:
`8fde398abe2ba6f360f4deaef08e28fb3df01fb2ef6a883c9a54a227c290d4f8`.

- Plan digest: `sha256:c65005db643e347ab28fde1ac32465521394a8eb8dad2cc281025d32430435e9`.
- Stable install intent: `sha256:8a02d4e8f4b40ed8f65cf2e1499c61ea1b1f15ee62b080d09713d8a544009625`.

The plan digest was independently recomputed over the compact canonical JSON
and matched. Secret-value scans found no credential, bearer/JWT, private key,
AWS access key, or certificate body in the retained plan. Lifecycle UUIDs,
bootstrap object names and token-transport prose are nonsecret planned metadata;
they are not a minted claim, token or Kubernetes object.

After the plan, the executing operator read the exact
`tunnex-s205-aws-20260905a` namespace: only the pre-existing default
`kube-root-ca.crt` ConfigMap remained, with no Secret, PVC, Deployment or
Service. The CP nodes GET reported total1 existing node and `walkNodes: []`
for names prefixed `tunnex-s205-`. No gateway was enrolled by the plan.
The selected host manager action, namespace/Secret/PVC creation and enrollment
operations in the JSON are planned work only, not completed operations.

The plan binds the existing Scale CP API
`https://cp.13.206.39.40.sslip.io`, agent endpoint
`https://cp.13.206.39.40.sslip.io:8443`, organization
`01a06bff-c3b0-7951-aee6-b41b2f7306ec`, task context/namespace, gateway A's exact
hostname selector, explicit gp3 StorageClass and all13 reviewed AWS annotations.
The schema/host posture evidence for actual installation remains pending.
