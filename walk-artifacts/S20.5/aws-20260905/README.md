# S20.5 AWS walk — live session ledger, 2026-09-05

**Current acceptance (2026-09-06):** [targeted AWS repair](../../../docs/S20.5-aws-targeted-acceptance.md)
supersedes the old eleven-leg completion denominator. Working installation,
retained identity and IP/FQDN evidence is retained; the active HA failure gets
the focused regression/re-test. Unrun broader qualification remains explicit,
not a blocker automatically attached to every unrelated fix. The historical
2/11 and latest-build 0/11 reports are no longer the progress model.

Current checkpoint (2026-09-06): **API `fa6d851` is deployed to the retained
licensed CP, including credential/health, HA wake and atomic retired-owner renewal repairs.
`dc70c9b` node/manager remains installed on all three workers; no gateway or
chart reinstall was needed. New baseline private-IP/FQDN proof passes 12/12.
Standby absence/return passed 80/80 on the preceding API correction. The repaired
active-owner sequence now proves sustained renewal: 42/42 requests after takeover
while the old owner remained absent, then 12/12 final stability requests after
automatic failback. Measured takeover/failback outages remain explicit. Exact-product
CI is running with native macOS/Windows already green. This is not yet merge-ready.
NLB remains explicitly SKIPPED.** See [current HA repair evidence](ha-wake-repair.md).
The mixed-component candidate is not a unified final release. No PR or merge
exists yet. Earlier counts below are historical, not current acceptance.

Historical status: **three-worker EKS ready; retained CP uses its verified valid Scale
license; six immutable candidate images and four chart OCI pull proofs complete.
Legs 0 and 1 passed for candidate `d2c9cba`; Leg 2 failed on runtime CNI startup
admission. The scoped LBC discovery-permission correction is deployed, but
fresh reconciliation is not yet proven. C5 (`61ecc5f`) passed local node gates
and independent review; its approved six images and four charts are published,
and the licensed CP runs its pinned images. A2 passed runtime CNI admission,
but its install timed out on the missing A2 NLB name in fixture IAM. That narrow
permission is corrected; a native retry safely refused the consumed claim.
The separate B native install reached an AWS account-level CreateLoadBalancer
`OperationNotPermitted` refusal (contact AWS Support), not IAM denial.
User explicitly skipped NLB qualification. Native NodePort replacements A3/B2
both installed successfully, 1/1 Ready, zero restarts, exact C5 agent versions;
bootstrap metadata is removed. Direct-A3 private-service VIP/FQDN client traffic
passed. A separate entry gateway installed on the existing third worker, but
switching to that primary exposed a base-authority mismatch and fresh traffic
timed out. HA and the remaining lifecycle proofs are pending.
Historical fully evidenced progress: 2/11; no final-candidate
or overall walk acceptance.**
No PR exists for `codex/s205-aws-reentry`; no merge or public release occurred.

Latest detailed evidence:

- [HA wake repair, immutable API deployment and targeted retest](ha-wake-repair.md).
- [Credential/health correction and full API gates](credential-health-gate-retest.md).
- [Transit correction, client IP/FQDN and partial HA proof](transit-snat-retest.md).
- [Candidate provenance, clean baseline and read-only plan](candidate-provenance-leg0-leg1.md).
- [First gateway failure and scoped controller correction](gateway-a-first-install-failure.md).
- [C5 publication, licensed CP, and fresh plan](c5-publication-cp-and-plan.md).
- [C5 live admission, A2 IAM correction, and retry refusal](c5-a2-runtime-and-iam.md).
- [User-approved NodePort transition and two successful installs](c5-nodeport-transition.md).
- [Dashboard service setup and real client traffic](c5-dashboard-service-and-client.md).
- [Third-worker entry gateway and live HA blocker](c5-edge-and-ha-blocker.md).

A new immutable candidate must re-earn the affected baseline, plan and live
installation proofs. Earlier image or gate results are not inherited as green.
The chronological entries below retain their original observed state.

## Authority and subject

- User selected AWS, required real infrastructure proof before PR, and allowed
  SCP. Any manual remedy remains labelled diagnostic until the affected leg is
  rerun from final immutable source.
- Paper-first AWS plan: commit `29e1c6d`,
  `docs/S20.5-aws-live-walk-plan.md`.
- Current immutable product candidate: `61ecc5fec4e5a971faaf9b1c65ccdc7b3b4cd8c1`.
- Last pushed checkpoint before this live-first preparation:
  `9b1797715ef8d5578d1afa73824ebe88963f947e`; that exact SHA had zero check runs,
  zero workflow runs, and zero legacy status contexts. This is not green CI.
- Current main integration baseline remains
  `0f3d9b0495aebd6c01dfd1c6791d1e54390a0c8d`.

This is a changing walk record, not the final PLAN pointer or a candidate
manifest. Each runtime artifact must later identify its actual clean source
SHA, digest, platform, and version; no existing test or image is assumed final.

## AWS identity and protected boundary

Fresh STS returned account `735391218823` and
`arn:aws:iam::735391218823:user/aws-cli`. All scoped infrastructure calls select
`ap-south-1` explicitly. Read-only inventory returned no EKS clusters, ECR
repositories, active CloudFormation stacks, ASGs, NAT gateways, or v2 load
balancers in this region.

The three running demo instances use 6 vCPU: CP `i-019a97f67dd40ce13`, gateway
`i-09e94cd620b7cde0e`, Nginx `i-0e2df49c1bbfecc73`. Their default VPC, attached
addresses, DNS, data, and settings are protected. No resource was classified
as unused from its name alone, and no stop/delete/resize was performed.

## Live event 1 — quota request

Before mutation, STS account and exact principal were checked again. The
Standard On-Demand quota `ec2/L-1216C47A` was 8, and request history was empty.
The request to increase it to 16 returned:

- ID: `eef0e19d97de4d1eb2f5cf48bfcc8c85Jfm3yUt9`.
- Created: `2026-09-05T15:19:10.557+05:30`.
- Status at return: `PENDING`.
- Support case ID at return: none.

A later read at `2026-09-05T15:22:16.847+05:30` reports `CASE_OPENED`, support
case `178860193200026`. A separate quota read still returned 8. Neither case
creation nor the request is counted as an increase.

This is a submitted request, not an approved increase. The initial one-worker
diagnostic fits the existing quota (6 existing + 2 new). No larger node group,
control-plane host, or update surge is allowed without rechecking quota and
actual running/pending usage. No existing infra was stopped to obtain capacity.

## Pinned infrastructure inputs observed read-only

- Cluster name reserved in the plan: `tunnex-s205-aws-20260905a` (not yet created
  at this ledger entry).
- Kubernetes 1.35: AWS API reports STANDARD_SUPPORT until 2027-03-27.
- kubectl client: 1.34.1, darwin/arm64.
- Add-ons: VPC CNI `v1.22.4-eksbuild.3`, kube-proxy
  `v1.35.3-eksbuild.21`, CoreDNS `v1.13.2-eksbuild.21`.
- Public AWS SSM AL2023 release: `1.35.7-20260827`.
- AMI: `ami-03632a6f1684c0665`, Amazon owner `602401143452`, x86_64,
  available, root device `/dev/xvda`; image name
  `amazon-eks-node-al2023-x86_64-standard-1.35-v20260827`.
- Admin IPv4 was read from AWS's public check-IP endpoint for a `/32` API
  restriction. Its value is an operational parameter, not committed here.

No private kubeconfig, certificate body, access token, private key, machine
credential, or service-account credential is included in this record.

## Live event 2 — reviewed change set executed

Infrastructure source: `fc494ad5b725b1ec6cdba2da3d6c5988ceea7e10`,
`deploy/aws-s205-walk-bootstrap.yaml`, SHA-256
`d54c9a8e38fabb0a09c9d3a6406528c454953e3c33e6efffc0e2ad808499c107`.
AWS `validate-template` accepted it and required only `CAPABILITY_IAM`.
The complete template/plan received independent scope, IAM and dependency
review with no confirmed high/medium blocker. Local YAML/reference/dependency
checks passed; cfn-lint was unavailable. None of these substitutes establishes
actual bootstrap, CNI, or product readiness.

Before creation, STS account/principal, absent stack/cluster/launch-template,
running/pending instances, quota, administrator `/32`, Amazon-owned AMI and
the selected AZ offering were checked. The change set contained exactly 20
`Add` actions, no replacement, removal, import, or existing physical ID.

- Stack ARN:
  `arn:aws:cloudformation:ap-south-1:735391218823:stack/tunnex-s205-aws-20260905a/103234e0-a911-11f1-9224-02bb0dc3d5f3`.
- Change-set ARN:
  `arn:aws:cloudformation:ap-south-1:735391218823:changeSet/phase1-fc494ad/1fcc2a45-259d-409c-8191-1c804d2daeac`.
- Exact change set was executed after another STS check; the command succeeded.
- `OnStackFailure=DO_NOTHING`; stack reports `DisableRollback=true`. Partial
  resources are preserved if creation fails; cleanup still needs exact approval.

Observed at the first provisioning readback:

| Task resource | Exact identity | Observed state |
|---|---|---|
| VPC | `vpc-05cbd22769f527e55` | CREATE_COMPLETE |
| Public subnet A | `subnet-01be85cea381cc1ae` | CREATE_COMPLETE |
| Public subnet B | `subnet-006997cf153f6259e` | CREATE_COMPLETE |
| Internet gateway | `igw-05cb9d4554aa56ab0` | CREATE_COMPLETE |
| Route table | `rtb-0aefcbaed14f4e857` | CREATE_COMPLETE; both associations and internet route completed |
| Worker launch template | `lt-017dbe5122c8e360f` | CREATE_COMPLETE |
| Cluster role | `tunnex-s205-aws-20260905a-ClusterRole-MKKPdDrxluvq` | CREATE_COMPLETE |
| Worker role | `tunnex-s205-aws-20260905a-WorkerRole-I91s5022hRQ5` | CREATE_COMPLETE |
| EKS control plane | `tunnex-s205-aws-20260905a` | CREATE_IN_PROGRESS from 10:05:11.300 UTC |

No Tunnex control plane, gateway, private workload, or runtime image publication
has occurred at this event. The original root checkout remained clean and
unstaged. This is real infrastructure progress, not a completed product leg.

### DNS preflight for the later fresh CP

The account contains a public Route53 `tunnex.app` zone and a private
`internal.tunnex.app` zone. The proposed `cp.s205-walk.tunnex.app` record is
absent from the public Route53 zone, but public NS lookup points to Cloudflare,
not that zone's AWS delegation set. Therefore an AWS record write alone would
not prove public resolution. No DNS record or delegation was changed. Establish
an actually authoritative TLS/DNS path before deploying the later CP; do not
modify existing domain delegation to make the walk work.

## Live event 3 — eligible-worker correction and scoped recovery

The managed EKS control plane became ACTIVE, platform `eks.21`. A task-only
kubeconfig outside Git (mode 0600, separate context; default context unchanged)
successfully reached Kubernetes `v1.35.6-eks-bca9cf6`. The initial node and Pod
inventories were empty: API access is proven, worker or application readiness
is not. No credential or certificate contents were collected into evidence.

The initial managed worker failed to launch any EC2 instance. Its Auto Scaling
activities at 10:13, 10:15, 10:17, 10:21 and 10:29 UTC report
`InvalidParameterCombination`: `t3.medium` is not eligible under this account's
Free Tier restriction. This was not a vCPU-quota or Tunnex-runtime error. AWS
reported `c7i-flex.large` eligible and offered in the selected AZ; it preserves
2 vCPU, 4 GiB and x86_64. Eligibility is not a free-billing promise.

Paper `3fb5fe9` records the correction, updated cost, and recovery boundaries
before source commit `832595e05e62c980fde3ebdaf8a1f4966b1b6086`. The template
changes only the instance type and removes T3-only credit configuration. Local
YAML/scope assertions and AWS template validation passed. No product code,
custom bootstrap, CNI rule, account billing plan, or old demo was changed.

The user separately approved deletion/recreation of exactly the failed-empty
node group `tunnex-s205-aws-20260905a-worker-a` and its managed ASG
`eks-tunnex-s205-aws-20260905a-worker-a-30d03887-72cd-93c3-8bb5-dcc8253d7be1`.
Fresh STS, exact original node-group ARN, exact ASG, zero ASG instances and
zero task-tagged EC2 instances were verified before `delete-nodegroup`.
AWS accepted deletion and reported DELETING. Subsequent CloudTrail readback
timestamps `DeleteNodegroup` at `2026-09-05T10:34:47Z`.
The stack then reported CREATE_FAILED, naming only `DiagnosticNodegroup`;
successful resources were retained with rollback disabled. A subsequent
read still reported DELETING; deletion completion is not claimed here.

The same stack's update change set is
`arn:aws:cloudformation:ap-south-1:735391218823:changeSet/worker-eligible-832595e/edf055d4-7f53-4c5f-8a70-8fa36b5727d4`,
created at `2026-09-05T10:37:12.108Z`. Its initial coarse preview included
tag-driven conditional changes across successful resources, so execution was
held. The subsequent full property-value preview reports exactly three:

- `WorkerLaunchTemplate`: Modify, no replacement; only instance type and
  credit-specification removal.
- `DiagnosticNodegroup`: Modify/replacement for the failed resource, without
  a stable physical ID; this is the explicitly approved empty-worker scope.
- `CoreDNSAddon`: Add, as already planned after worker creation.

No change set has been executed at this event. Reverify original group/ASG
absence, account/principal, quota/usage, exact preview and preserved resources
before proceeding. The preview's node-group launch-template version is a
pre-execution observation, not proof of the version actually launched.

The user also explicitly approved publishing non-secret AWS identifiers and
the quota support-case number in this public repository's redacted evidence.
The branch was successfully pushed through `c02ab84` after that approval;
this permission does not authorize publication of any credentials or imply
approval of held product-design decisions. Root checkout remains clean.

## Live event 4 — clean managed worker and native network baseline

The original node group and exact approved managed ASG were both absent before
executing the update. Zero associated instances had ever launched. The same
CloudFormation definition can recreate the empty worker; no application data
was deleted. Fresh account/principal, exactly three protected running demo
instances, eligible instance type, quota 8, ACTIVE cluster and exact VPC/role
were checked again. The final full preview still contained only the three
actions in event 3, with no successful-resource replacement.

Execution explicitly used `--disable-rollback` and a stable request token.
CloudFormation timestamps:

- `10:49:47.697Z`: UPDATE_IN_PROGRESS.
- `10:49:49.693Z`: failed-only node-group resource deletion acknowledged.
- `10:49:53.488Z`: the same source launch template UPDATE_COMPLETE.
- `10:51:40.380Z`: recreated node group CREATE_COMPLETE.
- `10:51:52.919Z`: planned CoreDNS add-on CREATE_COMPLETE.
- `10:51:57.837Z`: stack UPDATE_COMPLETE, DisableRollback=true.

Actual source launch template `lt-017dbe5122c8e360f` version **2** contains
`c7i-flex.large`, with no credit specification. The recreated node group
actually references that source version, min/desired/max=1. Its new ARN is
`arn:aws:eks:ap-south-1:735391218823:nodegroup/tunnex-s205-aws-20260905a/tunnex-s205-aws-20260905a-worker-a/cad03898-38b9-cf0c-8b1a-e201c6c63cd2`.
EKS generated derived launch template `lt-03d69b07af53c0d50` version 1 for its
new ASG; this is distinct from source version 2, not version drift or a manual
patch. The observed EC2 worker is `i-0afe3c3ecd00d1411`, selected AMI
`ami-03632a6f1684c0665`, in the existing task subnet A. Successful cluster,
network, IAM, OIDC, access, CNI and kube-proxy physical IDs remain unchanged.

Kubernetes node `ip-10-240-10-204.ap-south-1.compute.internal`, UID
`abf3e90f-c3bd-4067-ade6-83a12e00f3e2`, reports Ready, two CPUs, amd64,
Amazon Linux 2023.12.20260817, kernel `6.12.100-125.179.amzn2023.x86_64`,
kubelet `v1.35.7-eks-cb19647`, containerd `2.2.5+unknown`. The aws-node Pod,
kube-proxy Pod and both CoreDNS Pods are Ready with zero restarts.

### Actual resolved system images

All registry paths below start `602401143452.dkr.ecr.ap-south-1.amazonaws.com/`.

| Image path / tag | Resolved digest |
|---|---|
| `amazon-k8s-cni:v1.22.4-eksbuild.3` | `sha256:7ba0bb50de053432467d1cc629dfc846de4e534f00b73828a1ff33fcee70c8e7` |
| `amazon/aws-network-policy-agent:v1.4.0-eksbuild.1` | `sha256:c8555b6f2aed6d795a1637e0fe7f1f47cca2465354438157bdc8d8a6beb61045` |
| `eks/kube-proxy:v1.35.3-eksbuild.21` | `sha256:5f610139b70e7d52f5b00bf9087a789585d21cbb880b5ab94e4209ba85fc3999` |
| `eks/coredns:v1.13.2-eksbuild.21` | `sha256:df7ee9e5fbcc524da9151b43906cc013cf2089c6a59b3c5c25dd65d2db51f54f` |

### One-shot native Pod proof

`native-network-probe.yaml` records the exact created diagnostic Pod. The
official BusyBox 1.37.0 Linux/amd64 manifest was resolved before use; returned
imageID matches the manifest's digest. Strict server dry-run passed, then only
the absent `default/s205-native-network-probe` was created. It is non-root,
unprivileged, read-only-root, with no host mounts or service-account token,
small explicit resource limits and a 120-second active deadline.

Pod UID `2fc6d85a-0d6a-4862-9f24-c694d409bb88`, IP `10.240.10.42`, ran on the
new worker and completed at `2026-09-05T10:57:40Z`, exit **0**, zero restarts:

```text
2026-09-05T10:57:39.911958231Z DNS server 172.20.0.10:53
2026-09-05T10:57:39.911984585Z kubernetes.default.svc.cluster.local -> 172.20.0.1
2026-09-05T10:57:39.912131267Z NATIVE_SERVICE_DNS_OK
2026-09-05T10:57:39.914839893Z NATIVE_EXTERNAL_DNS_OK
2026-09-05T10:57:40.039441731Z NATIVE_HTTP_EGRESS_OK
```

The first two lines above compact the actual multi-line DNS output; success
marker lines are exact. External lookup was `checkip.amazonaws.com`, followed
by anonymous HTTP port 80 GET to that AWS endpoint with response discarded to
`/dev/null`. This proves native Service DNS, external DNS and HTTP egress;
it does not prove TLS, a private workload, Tunnex routing, or a desktop VPN.
The completed Pod is retained as evidence; no cleanup was performed.

## Live event 5 — actual CNI incompatibility and HOLD

Strictly read-only observations in host-network `kube-system/aws-node-f9s9d`
show nftables 1.0.4 and iptables 1.8.8. `alternatives --display iptables`
reports manual selection of `/usr/sbin/iptables-nft`. Explicit nft/legacy
versions and save commands were used; no generic wrapper was invoked and
legacy-save had no `-t` argument. Legacy-save succeeded with empty output.
Full nft JSON and explicit nft-save show **no `IP-MASQ-AGENT` chain**.

Actual relevant iptables-nft-save excerpt (10:53:41 UTC):

```text
-A POSTROUTING -m comment --comment "kubernetes postrouting rules" -j KUBE-POSTROUTING
-A POSTROUTING -m comment --comment "AWS SNAT CHAIN" -j AWS-SNAT-CHAIN-0
-A AWS-SNAT-CHAIN-0 -d 10.240.0.0/16 -m comment --comment "AWS SNAT CHAIN" -j RETURN
-A AWS-SNAT-CHAIN-0 ! -o vlan+ -m comment --comment "AWS, SNAT" -m addrtype ! --dst-type LOCAL -j SNAT --to-source 10.240.10.204 --random-fully
-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
-A KUBE-POSTROUTING -j MARK --set-xmark 0x4000/0x0
-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE --random-fully
```

nft readback places the IPv4 nat POSTROUTING hook at priority 100, with the
two jumps in that order. `AWS-SNAT-CHAIN-0` handle 34 has VPC return handle 36
and terminal rule handle 37. Several compat expressions, including SNAT,
appear as `xt: null` in nft JSON: this is opacity, not absent behavior. Do not
round-trip foreign rules through that representation. AWS CNI EXTERNALSNAT is
false, RANDOMIZESNAT is prng, prefix delegation is false; kube-proxy config
mode is iptables. These are observations, not settings changed for Tunnex.

The CNI image lacks `/usr/sbin/ip` and `/usr/sbin/sysctl`; those invocations
failed and no tool was installed into it. An exact-instance, read-only SSM
command on the verified task worker then captured routes, links and sysctls:
command `7fb08624-dcbd-4286-854e-ec5403613cff`, Success/exit 0 at 10:56:42.773Z.
It showed no wg0/staging link; native ENI/veth links and AWS rules remain.
The main default route is via `10.240.10.1` on `enp39s0`, protocol dhcp,
metric 512; table 2 has the secondary ENI route. Before Tunnex, ip_forward=1,
all.rp_filter=0, default.rp_filter=2 and primary-ENI.rp_filter=2. No values
were written, and no route, link, CNI, Secret or PVC was repaired.

**Source-backed inference, not a running Tunnex failure log:** current
`k8snetprep` recognizes only the absent IP-MASQ seam. With an active tunnel and
valid interface posture it returns blocked/no_registered_adapter, and gateway
readiness requires that netprep be ready. The host-posture manager's baseline
can accept an absent seam; manager readiness must not be conflated with gateway
readiness. No Tunnex runtime has been deployed to claim either live result.

The adapter/cleanup-journal authority decision was surfaced as HOLD. The user
then explicitly renewed sandbox implementation approval; its bounded C1–C4
dispositions are in `docs/S20.5-aws-cni-compatibility-decision-proposal.md`.
Implementation and qualification remain outstanding. No fake chain,
SNAT-disable patch, foreign-rule rewrite, broad bypass, or readiness exemption
was applied. Quota remains 8 (increase CASE_OPENED); broader topology, CP
authoritative DNS/TLS, red API gates and earlier held decisions remain open.
Exact pushed `ac7d92e82eb88c167d356c02be0bfe14a8b230df` has zero check runs
and zero workflow runs. No PR was raised and no required exact-final CI passed.

## Live event 6 — user-directed demo retirement frees compute

The user explicitly directed retaining the CP and removing other non-walk
machines, then finalizing the compatibility fix. Exact targets were shown
before mutation and revalidated by account, VPC, instance role and root volume.
The first read-only guard contained a mistyped VPC and refused; no mutation
ran under that failed guard. The corrected exact guard preceded graceful stop.

Both old hosts stopped normally, and private encrypted snapshots completed
before their exact termination calls. AWS returned `terminated` for both:

| Removed instance | Role | Deleted root volume | Completed recovery snapshot |
|---|---|---|---|
| `i-09e94cd620b7cde0e` | old demo gateway | `vol-0b818564ba3ea911e` | `snap-0d249c993ab1cd583` (12 GiB) |
| `i-0e2df49c1bbfecc73` | old private Nginx | `vol-0a179ae250dd86e1c` | `snap-08af53773c7ee20fc` (8 GiB) |

The disks are recoverable through those retained snapshots; removed instance
identities cannot be restored. The old demo VPN/private-Nginx path intentionally
no longer serves traffic. CP `i-019a97f67dd40ce13` and task EKS worker
`i-0afe3c3ecd00d1411` were excluded and remain the intended running topology.
No default-VPC routes, DNS records, CP data, or shared security group was deleted.
Snapshot storage continues to bill; no public snapshot sharing was requested.

The retained CP's exact stale operator SSH `/32` rule was changed to the freshly
verified laptop `/32`; all other rules were preserved. Strict SSH then succeeded.
Ordinary trusted HTTPS health succeeds at `https://cp.13.206.39.40.sslip.io`.
Read-only CP evidence reports v0.1.20/source `1119bd93c728b47d47f9e8cc9ffd75db6b903d75`,
clean schema 129, approximately 2.9 GiB available RAM and 15 GiB free root space.
Candidate migrations will not be silently applied to that retained database.

Current quota remains 8. With the old hosts removed, CP plus one worker use 4
vCPU; worker B and a later same-AZ spare can fit within 8 without waiting for 16.
No additional worker, candidate CP stack, gateway, CSI driver, or load balancer
has been created by this event.

Local source qualification continues separately. The complete first node gate
passed every non-CNI package but failed the new CNI tests because their external
walk-artifact fixture path was unavailable in the normal module-only test mount.
Package-local immutable fixtures correct that harness dependency. Real runtime
tool evidence also exposed the 1.0.4 `xt:null` versus 1.0.9 exact typed `xt`
format difference; both encodings must be proven without accepting unknown
semantics. See `cni-real-tool-witness.md` and the `runtime-alpine-*` snapshots.
Neither correction is a live VPN pass; full rerun and candidate wire proof remain.

## Live event 7 — required capacity and finalized CNI candidate

Worker scaling source `430177d` added only a closed 1/2/3 count parameter.
Full property-level change set
`arn:aws:cloudformation:ap-south-1:735391218823:changeSet/walk-workers-three-430177d/b28cec57-b751-4546-a553-b7a4cd977607`
contained exactly one non-replacing `DiagnosticNodegroup` modification:
desired/max 1 to 3. Normalized before/after properties outside ScalingConfig
were identical, including launch-template version 2. Fresh identity and exact
two-instance inventory preceded execution. CloudFormation UPDATE_COMPLETE
and all three nodes Ready were read back without a host or CNI repair.

| Retained/new machine | Role | Private IP | Public IP |
|---|---|---|---|
| `i-019a97f67dd40ce13` | retained CP host | 172.31.39.125 | 13.206.39.40 |
| `i-0afe3c3ecd00d1411` | original task worker | 10.240.10.204 | 65.2.179.105 |
| `i-0f6bb7eca4b726637` | additional task worker | 10.240.10.88 | 13.234.118.111 |
| `i-03c1fb3619712c8d3` | additional task worker / relocation capacity | 10.240.10.121 | 13.206.207.103 |

All four are 2-vCPU/4-GiB c7i-flex.large. The workers are in the exact task
subnet/AZ and use the unchanged pinned AMI/kubelet. This consumes 8 vCPU;
there is no additional EC2 surge headroom. No gateway placement is implied.

After verifying that the old gateway EIP was unattached and belonged to the
removed gateway, released only `eipalloc-0f8de2bcddee7e221` / 13.126.17.194.
Its address cannot be guaranteed recoverable. The CP EIP remained attached;
the subsequent address inventory contained only that allocation. Both old
root-volume IDs were absent after termination; their encrypted snapshots remain.

CNI product content is committed and pushed at
`d2c9cba653d400e2dab3d7b038796efeee1f028c`. The complete rerun of
`make test-node` passed all 14 packages (cmd/agent 89.900s, k8snetprep 1.018s),
following the recorded failed fixture-path attempt. Host-posture Linux and
Darwin race suites, actual read-only-mount locking, gateway/host-posture chart
contracts and focused cross-reviews passed their respective scopes. No
concrete P1/P2 remained in the CNI/host-posture cross-review; this is not the
uncompleted whole-story review or all-gates approval. Exact pushed-SHA GitHub
lookup returned zero check runs and zero workflow runs, not green CI.

Six linux/amd64 runtime images built from a separate clean detached checkout
of that exact product SHA. API used the enterprise build tag; node/operator
embedded version equals `0.0.0-walk.shad2c9cba653d400e2dab3d7b038796efe`.
The ten planned private ECR repositories were created with immutable tags,
verified exact account/ARN/URI, and no other repositories were modified.
Image upload was then refused by the execution safety reviewer for missing
directly visible authorization of this exact code payload and destination.
No workaround or alternate transfer was used; read-only post-refusal checks
returned ImageNotFound for both attempted candidate tags. Remaining uploads
were not attempted. User confirmation of the exact private image publication
is required before proceeding with that refused operation.

Controller and isolated-CP templates are committed at `79c2425`, but neither
the controller stack nor the candidate CP has been deployed. Existing CP
services/IDs and schema 129 remained unchanged on readback. Its new candidate
directories were absent; no new candidate administrator credential exists.

## Live event 8 — authorized image publication, controllers and retained CP

Event 7 records the earlier refusal and pre-deployment state. The user then
explicitly authorized the six-image private ECR payload; all six uploads and
digest readbacks succeeded. The four Tunnex chart uploads initially remained
blocked for separate exact approval, without an alternate export or transfer.
The user has now explicitly approved those four uploads; publication is in
progress, with digest readback and pull proof still pending at this checkpoint.

The approved controller change set created exactly seven Add-only resources,
then the pinned LBC chart and named nondefault Retain StorageClass were
installed. CSI and LBC report ready; no gateway PVC, NLB or packet path has yet
been exercised. See [controller deployment evidence](controller-deployment-evidence.md).

The user separately approved upgrading the retained licensed dev CP. The
committed plan/override `6081525` preceded replacement of only API, web and
Nginx. The same public HTTPS origin is healthy, schema is 136/clean, and fresh
normal authentication with unchanged credentials verifies a valid Scale
license. Existing stores and the other four old container IDs were retained;
all five isolated-project containers were stopped, with their files/stores
retained. See [candidate publication and CP evidence](candidate-deployment-evidence.md).

These are prerequisites, not Leg 0 or any product-leg pass. There is still no
Tunnex gateway, NLB, PVC or client proof, no exact-final green CI, and no PR.

## Acceptance ledger

| Stage/leg | Result | Remaining proof |
|---|---|---|
| Account/region/inventory | READ-ONLY VERIFIED | Recheck before mutation |
| Quota increase | CASE_OPENED; quota still 8; minimal topology fits | No extra EC2 surge headroom; increase not required for the current four machines |
| Three-worker EKS infrastructure | UPDATE_COMPLETE; three nodes Ready | No product qualification implied |
| Native Pod networking | DNS and HTTP egress PASS | Repeat alongside actual Tunnex packet/fault/cleanup proofs |
| CNI mechanism | Source repair committed; full node gate PASS | Real Tunnex tunnel/controller proof pending |
| Candidate images | Six private ECR uploads and exact digest readbacks PASS | Four Tunnex chart uploads newly authorized/in progress; digest/pull proof pending; full Leg 0 still unrun |
| CSI/LBC prerequisites | Stack CREATE_COMPLETE; pinned controllers Ready; named nondefault Retain StorageClass created | First PVC/volume and UDP NLB reconciliation unrun |
| Retained licensed CP | Candidate API/web/Nginx deployed; schema 136 clean; trusted TLS health and Scale license verified | Gateway enrollment/control, HA opt-in and client packet proof unrun |
| 0. Candidate provenance/clean baseline | NOT RUN | Matching source/CLI/charts/images; no old ownership state |
| 1. Redacted plan/no writes | NOT RUN | CLI/CP/Kubernetes evidence |
| 2/3. A and B enrollment | NOT RUN | Host journal, CNI, readiness, identity and Secret consumption |
| 4. Desktop private FQDN/VIP | NOT RUN | Real local-client responses and HA opt-in |
| 5. Persistence/self-heal | NOT RUN | Pod relocation and exact fault/controller recovery |
| 6. Immutable upgrade/rollback | NOT RUN | History/digests/readiness/continuous traffic |
| 7. Retained reuse | NOT RUN | No remint; original identity |
| 7a. Interrupted/TTL/abort | NOT RUN | Real expiry and lifecycle-only recovery |
| 8. Operator/CRD matrix | NOT RUN | Full clean-cluster lookup/adoption/refusal cases |
| 9. A→B→A | NOT RUN | Automatic fenced ownership and measured client recovery |

The missing IP-MASQ-AGENT mechanism is now observed on the actual worker, not
merely a provider-name risk; Tunnex runtime qualification remains unrun.
Current local API gates remain RED and the
manager/startup design decisions remain HELD. Infrastructure creation alone
will not satisfy any product leg, and diagnostic SCP changes cannot establish
zero-touch acceptance. No cleanup or PR action is implied by this ledger.
