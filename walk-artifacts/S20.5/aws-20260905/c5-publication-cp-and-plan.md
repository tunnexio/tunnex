# S20.5 C5 candidate — private publication, licensed CP and A2 plan

Checkpoint: **C5 publication and fresh A2 read-only plan verified; A2 installation
is not graded here.** The ordinary native-CLI install was running after the plan;
this record makes no Leg 2, upgrade, rollback, uninstall-guard or overall walk
acceptance claim. Earlier `d2c9cba` evidence and its failed installation remain
unchanged. All timestamps below are UTC on 2026-09-05.

## Exact candidate and public evidence boundary

- Product source: `61ecc5fec4e5a971faaf9b1c65ccdc7b3b4cd8c1`, built from a clean,
  unchanged detached checkout.
- Candidate version: `0.0.0-walk.sha61ecc5fec4e5a971faaf9b1c65ccdc7b`.
- Original package-manifest SHA-256:
  `65fb29b7feb05d6f5bf3a800121996b20d0176dd30e289add2da330fcb636500`.
- Linux/amd64 CLI SHA-256:
  `ee0de4e0a5541f1d393f9461fd3e2cb2f3f724317889357cd5eb131b071c9623`.
- Native Darwin/arm64 CLI SHA-256:
  `fadaf6d023f76b57583d001c6a54a064c46f062c3e238d1218bf9aac072dbf5f`.
  The companion receipt binds this additional binary to the full source SHA,
  exact candidate version and original manifest hash; the original Linux bundle
  was not rewritten. Both actual CLI binaries printed the exact version above.
- Go `1.25.13`; Helm `v3.18.4+gd80839c`. Each chart was packaged twice by
  the unmodified candidate script and compared byte-for-byte. All six bundle
  checksum entries passed again after publication.
- The frozen C5 node source passed all 14 packages normally and under race
  detection. These are local gates, not live packet or lifecycle acceptance.

Publication resumed only after the user's standalone approval explicitly named
the six Tunnex images, including enterprise API, and four Helm charts for
`61ecc5f` in private ECR account `735391218823`, region `ap-south-1`, namespace
`tunnex-s205-aws-20260905a`. Earlier blocked attempts did not create push
processes and remain historical private receipts. Fresh STS matched
`arn:aws:iam::735391218823:user/aws-cli`; all ten exact repository ARNs/URIs
and immutable-tag settings were checked, and all new candidate tags were absent
before publication. Builds and pushes were limited to two concurrent operations.

This artifact contains only non-secret identifiers, digests and token-blind
plan metadata. No credentials, certificate/private-key bodies, license payload,
private local paths or token values are included.

## Six immutable images — publication verified

Repository prefix for every row:
`735391218823.dkr.ecr.ap-south-1.amazonaws.com/tunnex-s205-aws-20260905a/`.
Append the image name and `@` plus digest to obtain the pinned reference.
All images are Linux/amd64; ECR-returned OCI index digests equal the inspected
local build IDs and the original candidate manifest.

| Image | Published digest |
|---|---|
| `api` | `sha256:ba6c70d3eb2b6d37f0018670b56dcaeb0720c9046e77698a8273358abe8633e6` |
| `web` | `sha256:53cbde3dbbbb78ca32958e4fb0ee691accc95ebec7bb1aec37449f7a85a52718` |
| `nginx` | `sha256:c8e0f845db5f4ccc1954a5cea3fca155d65cfd9315afa8c31f60436c1efd800f` |
| `migrate` | `sha256:69792a05945f9c31022612dd51c4625e16eb0d1b0323c03fce6af11430af1879` |
| `node-agent` | `sha256:1189a15a2b78bf029cedd14d09a7de2daa37457ff61cd66506589009fe7708a3` |
| `operator` | `sha256:40df19e05cc7dfca0bcfe2acb026a0a52af80ff0511ecc7ce6734f97c16054ff` |

API was built with `TUNNEX_BUILD_TAGS=enterprise`. Only node-agent and operator
Dockerfiles consume the version argument; no embedded-version claim is made for
API, web, nginx or migrate. The shipped node executable contained the exact C5
version and its image provided nft `1.0.9` and explicit
`iptables-nft-save 1.8.10 (nf_tables)`. The actual operator startup printed the
same version, then deliberately exited for absent control-plane configuration
in a credentialless, network-disabled probe.

Image-publication receipt SHA-256:
`99745eeb46bf77595a41e34c5fdd17b516740bab8e63399f05567263dc7439a9`.

## Four immutable charts — actual OCI pull-back proof

Each OCI reference uses the same repository prefix plus its chart name.
All chart versions and appVersions equal the candidate version. Every ordinary
authenticated OCI pull landed in a fresh private verification directory, and
`cmp` plus SHA-256 matched its untouched original archive. AWS readback
reported Helm artifact media type `application/vnd.cncf.helm.config.v1+json`.
Combined publication/readback/byte proof completed at `15:02:38Z`.

| Chart | Archive SHA-256 | OCI manifest digest |
|---|---|---|
| `tunnex-host-posture` | `747cb8b4c20a62355ce762337ed2c3b47065ce126351c14403ed7a054e400814` | `sha256:3030bf9d4fbda1607e30743bfd2c072e901b255ffcf13903523bcb64ec52e2a8` |
| `tunnex-gateway` | `740357c892c3348752e2f40a03aeb5309003fb3720397f34cd905d7fb39c65f0` | `sha256:100bbe73416ac29bbf03787631c0b3cbcf574abc98cc25299507350f717704d6` |
| `tunnex-operator-crds` | `7c62446aba47b21200bddf3b0bcf6968ac50ccf239482eec3cd79e75e06d1174` | `sha256:5b001e07d7aac57c18f864922078a694c4df45546a981e07553a48137ed15346` |
| `tunnex-operator` | `85db07a76efc222a6d1a81ecd5aeff2a0199b56d4c775d72bb9a1ef8b986032f` | `sha256:9bd167fb9e8c0389e441bacbdb3a35a094509beb8faaf02105a86bc540431b09` |

Chart-publication receipt SHA-256:
`8188240c837c7493b4afbdf063f0e54b3eafa03c8a268d40f534268130d02506`.
Native-CLI companion receipt SHA-256:
`3985d3a494418ee63488685b790528437c883934ba5e48aa9a431d47270f9234`.

## Existing licensed control plane — scoped ordinary update

The retained Scale control plane was updated using the committed candidate
Compose override, not a signed/public release or a new control-plane host.
Override source:
[deploy/aws-s205-existing-cp-candidate.yml](../../../deploy/aws-s205-existing-cp-candidate.yml),
commit `ef0b36be1d9885e75bfb995dac77fb5bcc3bc264`; exact file SHA-256:
`909e4e0693a1659e738e46fb1ab195708b6c5c2c7c38e602f71a8c40cefbe117`.

Only API, web and nginx were recreated with their pinned candidate image
references above. Root's post-update readback recorded:

| Service | Observed container ID (12-character prefix) | Result |
|---|---|---|
| API | `4c70c9367701` | New C5 API digest reference |
| Web | `e133d31e12ca` | New C5 web digest reference |
| Nginx | `0d87991946cd` | New C5 nginx digest reference |
| Caddy | `64e95d0b321e` | Existing container unchanged |
| Existing node | `80259b6ef9e4` | Existing container unchanged |
| PostgreSQL | `59a305613856` | Existing container unchanged |
| Redis | `d819881e8ef9` | Existing container unchanged |

Health returned HTTP `200`. License readback remained **Scale**, valid, with
expiry `2029-07-22`; no license body or credential is published. Unchanged
database-container identity is not a claim that application data never changed.
This CP update is separate from Kubernetes gateway-install acceptance.

## A2 plan refusal and explicit idle-fixture reset

The first C5 native plan ran `15:03:42.193Z → 15:03:51.823Z`, exit `1`.
It refused the existing cluster-wide host-posture chart because private
prerelease hash ordering treats the old `shad2c9cba…` version as newer than
`sha61ecc5f…`. The exact refusal was a shared-manager downgrade refusal;
private hash ordering is not Git ancestry. No A2 objects were written.

Root then explicitly retired **only the idle old host-posture test fixture**
through ordinary Helm uninstall of `tunnex-host-posture` in `tunnex-system`.
Before removal, root recorded a cluster-wide census with zero owner-labelled
Pods and controllers, plus successful read-only SSM receipt
`f9bfdbe6-5b5e-4f2d-9c25-6ba0186141f9` at `15:16:25Z`:

| Worker IPv4 | Heartbeat / owners | Journal | WireGuard |
|---|---|---|---|
| `10.240.10.88` | idle / null | absent | wg0 absent |
| `10.240.10.121` | idle / null | absent | wg0 absent |
| `10.240.10.204` | idle / null | restored | wg0 absent |

The readback inspected only bounded public status/journal metadata and interface
presence. HostPath state and retained PVCs were not deleted.

**There is no automatic uninstall guard demonstrated here.** The chart's NOTES
provide guidance; they do not enforce this readback. This was an explicitly
authorized **pre-walk fixture reset**, not product-guard, shared-manager upgrade,
rollback, failed-candidate recovery or final cleanup proof. It does not erase
the first refusal or the earlier failed `d2c9cba` installation.

## Fresh A2 read-only plan after fixture reset

The exact C5 native CLI then ran `15:18:27.140Z → 15:18:36.830Z`, exit `0`.
Root's post-plan readback found no A2 objects. The target remained the new
release/node `tunnex-s205-a2` on worker
`ip-10-240-10-88.ap-south-1.compute.internal`, using the two exact private OCI
charts, C5 node digest, retained gp3 storage and explicit reviewed NLB inputs.

- Plan digest, independently recomputed from compact parsed JSON:
  `sha256:36e222105aec99c8a99ae67fd58918c98b72a1014b14aadf3f82afa0e6b46ce7`.
- Stable install-intent digest:
  `sha256:ab741b4d45070a7b28193f65a9c809228f2a269ba9abc75ec0d14ea30dc249f1`.
- Exact original printed-plan SHA-256:
  `2ec6b7ed9930cbb2cba906d5f73ab0ce8541f51642a1f0d35af5bb343bb6ebe4`.

The following is the token-blind printed plan, inspected and secret-scanned
before inclusion. Its operation list describes intended install work; it is
not a record that those mutations happened during `plan`.

```text
{
  "schema_version": 1,
  "action": "install",
  "install_intent_digest": "sha256:ab741b4d45070a7b28193f65a9c809228f2a269ba9abc75ec0d14ea30dc249f1",
  "kubernetes": {
    "context": "tunnex-s205-aws-20260905a",
    "namespace": "tunnex-s205-aws-20260905a",
    "release": "tunnex-s205-a2"
  },
  "organization": {
    "id": "01a06bff-c3b0-7951-aee6-b41b2f7306ec",
    "name": "Tunnex AWS Engineering Demo"
  },
  "control_plane": {
    "api_url": "https://cp.13.206.39.40.sslip.io",
    "agent_url": "https://cp.13.206.39.40.sslip.io:8443",
    "server_name": "tunnex-control"
  },
  "host_posture": {
    "action": "install",
    "release": "tunnex-host-posture",
    "namespace": "tunnex-system",
    "daemon_set": "tunnex-host-posture",
    "chart": "oci://735391218823.dkr.ecr.ap-south-1.amazonaws.com/tunnex-s205-aws-20260905a/tunnex-host-posture",
    "chart_name": "tunnex-host-posture",
    "version": "0.0.0-walk.sha61ecc5fec4e5a971faaf9b1c65ccdc7b",
    "app_version": "0.0.0-walk.sha61ecc5fec4e5a971faaf9b1c65ccdc7b",
    "artifact_sha256": "sha256:747cb8b4c20a62355ce762337ed2c3b47065ce126351c14403ed7a054e400814",
    "contract": "tunnex-host-posture/v1",
    "image": "735391218823.dkr.ecr.ap-south-1.amazonaws.com/tunnex-s205-aws-20260905a/node-agent@sha256:1189a15a2b78bf029cedd14d09a7de2daa37457ff61cd66506589009fe7708a3"
  },
  "gateway": {
    "node_name": "tunnex-s205-a2",
    "mode": "enroll",
    "service_type": "LoadBalancer",
    "endpoint": "discover from Service status.loadBalancer.ingress",
    "wireguard_port": 51820,
    "service_annotations": {
      "service.beta.kubernetes.io/aws-load-balancer-attributes": "load_balancing.cross_zone.enabled=true",
      "service.beta.kubernetes.io/aws-load-balancer-healthcheck-path": "/readyz",
      "service.beta.kubernetes.io/aws-load-balancer-healthcheck-port": "9091",
      "service.beta.kubernetes.io/aws-load-balancer-healthcheck-protocol": "HTTP",
      "service.beta.kubernetes.io/aws-load-balancer-healthcheck-success-codes": "200",
      "service.beta.kubernetes.io/aws-load-balancer-ip-address-type": "ipv4",
      "service.beta.kubernetes.io/aws-load-balancer-manage-backend-security-group-rules": "false",
      "service.beta.kubernetes.io/aws-load-balancer-name": "tunnex-s205-a2",
      "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "ip",
      "service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing",
      "service.beta.kubernetes.io/aws-load-balancer-security-groups": "sg-01a26ee7e12ca2297",
      "service.beta.kubernetes.io/aws-load-balancer-subnets": "subnet-01be85cea381cc1ae,subnet-006997cf153f6259e",
      "service.beta.kubernetes.io/aws-load-balancer-type": "external"
    },
    "node_selector": {
      "kubernetes.io/hostname": "ip-10-240-10-88.ap-south-1.compute.internal"
    },
    "bootstrap_secret": "tunnex-s205-a2-bootstrap",
    "bootstrap_state": "new create-only lifecycle anchor and Secret",
    "token_transport": "token-blind anchor before control-plane mint; Secret stdin only; value redacted",
    "image": "735391218823.dkr.ecr.ap-south-1.amazonaws.com/tunnex-s205-aws-20260905a/node-agent@sha256:1189a15a2b78bf029cedd14d09a7de2daa37457ff61cd66506589009fe7708a3",
    "lifecycle": {
      "anchor_name": "tunnex-s205-a2-lifecycle",
      "claim": "e0d23d50-8562-4115-a659-a931d1825218",
      "request_id": "217e084f-42db-41b9-83e8-0626272c1ff0",
      "expected_generation": 0,
      "generation": 0,
      "state": "pending"
    }
  },
  "chart": {
    "name": "tunnex-gateway",
    "reference": "oci://735391218823.dkr.ecr.ap-south-1.amazonaws.com/tunnex-s205-aws-20260905a/tunnex-gateway",
    "version": "0.0.0-walk.sha61ecc5fec4e5a971faaf9b1c65ccdc7b",
    "app_version": "0.0.0-walk.sha61ecc5fec4e5a971faaf9b1c65ccdc7b",
    "artifact_sha256": "sha256:740357c892c3348752e2f40a03aeb5309003fb3720397f34cd905d7fb39c65f0",
    "rollout_revision": "derived from stable install intent digest"
  },
  "storage": {
    "claim": "tunnex-s205-a2-tunnex-gateway-state",
    "state": "create new retained claim",
    "class": "tunnex-s205-gp3",
    "provisioner": "ebs.csi.aws.com",
    "binding_mode": "WaitForFirstConsumer",
    "retention": "retain on uninstall"
  },
  "operations": [
    "install exact cluster-wide host posture manager before gateway enrollment",
    "recheck release/Secret/claim/anchor fingerprint",
    "create namespace only if absent",
    "create token-blind lifecycle anchor",
    "mint or redeliver exact claim token",
    "stream create-only immutable bootstrap Secret to kubectl stdin",
    "acknowledge Secret CAS",
    "persist stable install intent and opaque operation UUID in the lifecycle anchor",
    "Begin exact control-plane install operation before gateway Helm mutation",
    "CAS-mirror installing epoch and server-bounded hard deadline in the lifecycle anchor",
    "run Helm atomic install under the approved timeout with bounded control-plane heartbeats",
    "cancel Helm on abort, lost epoch, or hard deadline",
    "verify exact consumed claim, release/workload readiness, and persistent provenance",
    "Complete exact install epoch before deleting bootstrap recovery metadata",
    "verify Deployment readiness",
    "verify Service endpoint",
    "verify exact enrolled lifecycle identity",
    "delete consumed bootstrap Secret and lifecycle anchor"
  ]
}
Plan digest: sha256:36e222105aec99c8a99ae67fd58918c98b72a1014b14aadf3f82afa0e6b46ce7
```

At this checkpoint, the subsequent ordinary native install was in progress.
**Leg 2 is not marked passed, and no overall ledger count is advanced here.**
