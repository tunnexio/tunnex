# S20.5 — supported gateway A abort and unused-worker baseline

2026-09-05. This follows the [failed first install](gateway-a-first-install-failure.md).
After the root operator described the exact abort effects, the user explicitly
approved proceeding without another confirmation. Authority was limited to
gateway A's failed lifecycle identity and its owned bootstrap Secret/anchor;
PVC/PV/EBS and host-posture were to remain. No purge or broad cleanup was used.

## Exact supported abort

Before execution, the native abort implementation, fenced-operation helpers,
canonical hook cleanup and owner-bound Secret deletion were read. The relevant
source was unchanged from `d2c9cba653d400e2dab3d7b038796efeee1f028c`.
The existing native macOS CLI SHA-256 was verified as
`bcaf3bbf324635ad451bb99a1344105dc385108620e554de06de72f1d6a94758`.
The ordinary saved CLI credential was used privately; no token or credential
content is included here.

Fresh guards proved account `735391218823`, principal
`arn:aws:iam::735391218823:user/aws-cli`, region `ap-south-1`, ACTIVE cluster
`tunnex-s205-aws-20260905a`, VPC `vpc-05cbd22769f527e55` and its exact OIDC
issuer. Live metadata, not a constructed identifier, supplied the claim and
typed confirmation:

| Field | Verified value |
|---|---|
| Context / namespace | `tunnex-s205-aws-20260905a` |
| Release / node name | `tunnex-s205-a` |
| Organization | `01a06bff-c3b0-7951-aee6-b41b2f7306ec` |
| Lifecycle claim | `3156a7f5-0dfb-4dc8-abc4-2f04f25b2e90` |
| Anchor UID | `3b8cacd9-7642-414d-9786-a3eb27ab4599` |
| Prior claim state / generation | `consumed` / 1 |

Executed only the native `k8s abort-install` with those explicit scope flags,
`--confirm "ABORT 3156a7f5-0dfb-4dc8-abc4-2f04f25b2e90"` and `--timeout 2m`.
It ran from `2026-09-05T14:23:47.220Z` through `14:24:07.663Z`, **exit 0**,
stderr empty. Its final message confirmed that the partial install was aborted
and any retained PVC was not deleted. Private stdout/stderr and the nonsecret
execution receipt remain outside Git; only selected fields are recorded here.

## Independent result and retention readbacks

Ordinary authenticated lifecycle GET returned HTTP 200, exact claim above,
state `aborted`, generation 1, node `tunnex-s205-a`, and node ID
`01a071d1-5c35-7f57-9e17-779413287075`. Both `aborted_at` and the shortened
`expires_at` were `2026-09-05T14:24:05.276966Z`. The supported nodes listing
independently returned that exact node with status **revoked**.

Post-abort Kubernetes/AWS reads proved:

- Bootstrap Secret `tunnex-s205-a-bootstrap` and lifecycle ConfigMap
  `tunnex-s205-a-lifecycle` are absent. They were removed by the supported CLI,
  not raw kubectl mutation; the old token/identity is permanently invalidated.
- The exact gateway Helm release remains absent, with no task gateway Pod,
  Deployment, Service or Job present.
- PVC `tunnex-s205-a-tunnex-gateway-state` remains Bound to unchanged PV
  `pvc-8a8a39dd-527b-487d-a93a-162610102b81`, UID
  `4bee8ae4-c008-4c86-857d-3c1a8bb96ead`, reclaim policy Retain.
- Encrypted volume `vol-091ad45df24c5186b` remains available with no attachment.
  No identity filesystem or private journal contents were read.
- Host-posture DaemonSet remains 3 desired / 3 ready / 3 available. It was not
  uninstalled or restarted by the abort task.

A metadata read initially encountered this agent's sandbox DNS restriction;
retry through its permitted network channel succeeded without repeating the
abort. A per-node GET probe returned 405, so the supported nodes listing was
used for the revocation readback. Neither diagnostic changed cloud state.

## Proposed A2 worker: pre-install metadata baseline

The root operator proposed a new release/node `tunnex-s205-a2` on the previously
unused worker `i-0f6bb7eca4b726637`, private IP `10.240.10.88`, keeping failed A's
PVC separate. Fresh instance/VPC/SSM guards proved the exact running task
worker, Online in SSM. No A2 installation or new identity was invoked here.

Read-only SSM receipt `f811dd50-efc9-4adf-8511-8d9e81929ac2`,
`2026-09-05T14:32:14.103Z`, returned Success / exit 0:

- Public nonsecret heartbeat: state `idle`, owners `null`, sequence 1416,
  observed at `2026-09-05T14:32:13.925145813Z`.
- Node name `ip-10-240-10-88.ap-south-1.compute.internal`; manager UID
  `4bffdbd8-1866-4eba-b08c-5872675dba6d` matched the live Running manager pod.
- Private `journal.json` path absent; only existence metadata was tested.
- WireGuard text-filter output empty; direct wg0 lookup explicitly reported
  that the device does not exist. The AL2023 filtered JSON still emits empty
  objects, not `[]`; it is not misrepresented as a standalone absence proof.

The first SSM request was rejected before execution because its comment
exceeded 100 characters; shortening only the comment allowed the same read-only
checks to run. No temporary Pod, host write or journal-content read occurred.

This is an idle, journal-free unused-worker observation, not a claim that a
new kernel restoration occurred or that the final candidate is running there.
The planned fixed runtime candidate is bound to source
`61ecc5fec4e5a971faaf9b1c65ccdc7b3b4cd8c1`; the baseline manager still runs the
previous candidate. Final provenance, ordinary plan/install and live acceptance
must be re-established. Do not relabel or remount failed A's revoked identity
as A2. No full cleanup/recovery leg, new gateway pass, PR or public release is
claimed by this bounded abort and baseline record.
