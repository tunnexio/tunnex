# S20.5 — controller prerequisite deployment evidence

2026-09-05. This is a redacted record of the approved controller deployment,
not a claim of gateway, storage-provisioning or packet qualification.
Account/principal: `735391218823` /
`arn:aws:iam::735391218823:user/aws-cli`; region `ap-south-1`.
Cluster `tunnex-s205-aws-20260905a` was ACTIVE on EKS 1.35.

## Guarded seven-resource creation

Fresh STS, cluster ARN/VPC/OIDC, both task subnets, worker security group,
approved current client /32 and exact change-set preview were independently
verified before execution. The administrative client address is intentionally
not committed. VPC is `vpc-05cbd22769f527e55`, worker SG
`sg-0a4645cf6d8de2c33`, subnets `subnet-01be85cea381cc1ae` and
`subnet-006997cf153f6259e`; OIDC issuer ID is
`EC9D7B319CCC0C36555DB40A392B5813`.

Executed only change set
`arn:aws:cloudformation:ap-south-1:735391218823:changeSet/controllers-first-install-79c2425/b5d3847c-7f66-4ba6-8552-7bb36ad8725a`
against stack
`arn:aws:cloudformation:ap-south-1:735391218823:stack/tunnex-s205-aws-20260905a-controllers/9d2d6560-a928-11f1-958f-02c874d07609`.
The preview was available and exactly seven Add-only resources, with no
replacement, import or deletion; its template matched the reviewed local
template apart from terminal whitespace.

| Logical resource | Type |
|---|---|
| EBSCSIAddon | AWS::EKS::Addon |
| EBSControllerRole | AWS::IAM::Role |
| ELBServiceLinkedRole | AWS::IAM::ServiceLinkedRole |
| LoadBalancerControllerRole | AWS::IAM::Role |
| NLBFrontendSecurityGroup | AWS::EC2::SecurityGroup |
| WorkerReadinessFromNLB | AWS::EC2::SecurityGroupIngress |
| WorkerWireGuardFromNLB | AWS::EC2::SecurityGroupIngress |

Execution began around 13:09 UTC with `--disable-rollback`; stack readback was
CREATE_COMPLETE at `2026-09-05T13:10:08.698Z`. All seven resources completed.
The ELB service-linked role was verified absent immediately before creation.
It is an account-wide AWS-owned service role with Retain deletion policy,
not a task-exclusive object; no cleanup authority is implied.

Verified outputs:

- EBS IRSA: `arn:aws:iam::735391218823:role/tunnex-s205-aws-20260905a-control-EBSControllerRole-cN7RBhUGeJT0`.
- LBC IRSA: `arn:aws:iam::735391218823:role/tunnex-s205-aws-20260905a-LoadBalancerControllerRol-YUliy4hHDzXM`.
- NLB frontend SG: `sg-01a26ee7e12ca2297` in the exact task VPC.

Role trusts read back the exact OIDC provider, STS audience and separate
`kube-system` service-account subjects (`ebs-csi-controller-sa` and
`aws-load-balancer-controller`). Frontend ingress is UDP 51820 only from the
approved client /32; egress is UDP 51820 and TCP 9091 only to the task worker
SG. Two stack-owned worker ingress rules allow those ports only from the
frontend SG. Original worker self-ingress remains for webhook connectivity.
The LBC role received no EC2 security-group write or IAM write permission.

## Pinned controller installation and readback

Exact-name absence checks preceded creation of the task workload namespace,
LBC Helm release and named StorageClass. Installed the locally verified
AWS LBC chart **1.14.1**, SHA-256
`5b9f5bf3d7295d0c61eda2a7aea8c7f3369d51eca406c3dc032b84eacc3893d3`,
with reviewed values, ordinary Helm install and `--wait --timeout 5m`.
Release `aws-load-balancer-controller` in `kube-system` reports deployed,
revision 1, deployment time `2026-09-05T13:14:21Z`.

LBC Deployment UID `dcf1ad05-cc1f-4557-995d-7ab1ca43c68d` reports
generation/observedGeneration 1/1 and replicas/ready/available 1/1/1. The
Running/Ready pod has zero restarts. Requested image is
`public.ecr.aws/eks/aws-load-balancer-controller:v2.14.1`; actual image ID is
`public.ecr.aws/eks/aws-load-balancer-controller@sha256:13abee6e31c2f25ee91f9ae91aabe4f5bcaf6a70eccd372b36835786d2e0813e`.
Live assertions verify the exact IRSA annotation, watch namespace
`tunnex-s205-aws-20260905a`, backend SG/rule management disabled, and
`AGAController:false` / `LBCapacityReservation:false`.

EBS CSI add-on reports ACTIVE `v1.65.0-eksbuild.1`, health issues `[]`.
Controller Deployment UID `5f7157a3-d580-41b9-992d-bb2ba5e376ae` is 1/1 ready;
the node DaemonSet is 3/3 ready/available. Plugin image is
`602401143452.dkr.ecr.ap-south-1.amazonaws.com/eks/aws-ebs-csi-driver:v1.65.0`;
live args contain the exact task cluster ID and approved Project/Session tags.

StorageClass `tunnex-s205-gp3`, UID `718d5c29-dec5-4c97-8929-1d828facaf30`,
readback: `ebs.csi.aws.com`, gp3, encrypted, ext4, WaitForFirstConsumer,
Retain, expansion allowed, no annotations (not default). No gateway PVC or
EBS data volume was created by this prerequisite task.

## Proof limits and retained state

No deployment error occurred and no permissions beyond the reviewed stack
were added. No manual CNI/host/application Secret/PVC repair or existing
resource cleanup occurred. Helm created its reviewed vendor-managed release
and certificate objects. The controller stack, controllers, namespace,
StorageClass and private runtime files remain; no deletion is authorized here.

A ready controller is not proof of successful NLB reconciliation or CSI
CreateVolume/AttachVolume. There is still no Tunnex gateway, UDP NLB, gateway
PVC or fresh packet flow. Product acceptance remains 0/11; this record does
not close Leg 0, held decisions, red API gates or exact-final CI requirements.
