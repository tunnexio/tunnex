# S20.5 AWS walk — live session ledger, 2026-09-05

Status: **preflight and quota request only; no working-product proof yet.**
No PR exists for `codex/s205-aws-reentry`; no merge or public release occurred.

## Authority and subject

- User selected AWS, required real infrastructure proof before PR, and allowed
  SCP. Any manual remedy remains labelled diagnostic until the affected leg is
  rerun from final immutable source.
- Paper-first AWS plan: commit `29e1c6d`,
  `docs/S20.5-aws-live-walk-plan.md`.
- Last product repair: `18bd20af82d09c5a6bcec1d6f5d525bbf57550fa`.
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

## Acceptance ledger

| Stage/leg | Result | Remaining proof |
|---|---|---|
| Account/region/inventory | READ-ONLY VERIFIED | Recheck before mutation |
| Quota increase | PENDING | Actual approved quota; do not infer from request |
| One-worker EKS infrastructure | NOT RUN | Stack/node/CNI/native DNS/kernel readback |
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

The IP-MASQ-AGENT mechanism requirement is a known compatibility risk, not a
proven EKS failure or an exemption. Current local API gates remain RED and the
manager/startup design decisions remain HELD. Infrastructure creation alone
will not satisfy any product leg, and diagnostic SCP changes cannot establish
zero-touch acceptance. No cleanup or PR action is implied by this ledger.
