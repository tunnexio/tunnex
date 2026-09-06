# BYODB AWS fresh-install walk — in progress

## Scope and authorization (2026-09-06)

The user explicitly confirmed that the prior AWS infrastructure was disposable
walk infrastructure and requested testing from zero, rather than preserving or
reusing its deployment state. No merge is authorized by this walk.

Verified AWS identity: account `735391218823`, IAM user `aws-cli`, region
`ap-south-1`. Core candidate is `da73afc201f956a9c2c71b88add9e2362f206deb`,
draft PR #59. Its executed PR checks passed; release-only jobs were skipped.

## Inventory and teardown

- Existing CP: `i-019a97f67dd40ce13`, `13.206.39.40`, default VPC
  `vpc-05d83034f7c1609a2`. Termination submitted after explicit clean-slate
  authorization; root `vol-0f80fa802fec160a1` has DeleteOnTermination enabled.
  Its data will not seed the new CP. No backup taken, as requested.
- Old cluster: `tunnex-s205-aws-20260905a`, dedicated VPC
  `vpc-05cbd22769f527e55`.
- Worker nodegroup: `tunnex-s205-aws-20260905a-worker-a`; instances
  `i-0f6bb7eca4b726637`, `i-03c1fb3619712c8d3`, `i-0afe3c3ecd00d1411`.
- Read-only Kubernetes inspection found three running gateways, two Nginx pods,
  and six bound retained PVCs. These were not incorrectly classified as unused.
  Retirement follows the user's explicit disposable-walk clarification.
- Standard on-demand vCPU quota: 8; initially occupied by four 2-vCPU instances.
- No RDS instances, NAT gateways, ELBv2 load balancers or VPC peerings found in
  this regional inventory. This is not an all-regions/account-wide cleanup claim.

Submitted nodegroup scaling change: min 0, desired 0, max 3; EKS update
`02d65a43-c556-3bcf-bc2b-17ecd5f2c766` reports Successful. Immediately following
that result EC2 still reported the three workers running: configuration acceptance
does not prove completed instance termination or freed quota.

CloudFormation deletion for `tunnex-s205-aws-20260905a-controllers` is verified
DELETE_COMPLETE. Base stack `tunnex-s205-aws-20260905a` deletion was subsequently
submitted. Workers currently report Terminating:Wait in their Auto Scaling group.

Deleted the three previously detached, explicitly scoped old gateway volumes:
`vol-091ad45df24c5186b`, `vol-06648cb77c469b8cd`, `vol-01ccd69956897d6ee`.
No snapshots were taken; this walk does not provide a recovery path for that data.
The three attached gateway volumes remain pending worker termination/detachment.
The existing Elastic IP is not released yet. Full infrastructure cleanup is pending.

## Required fresh proof

1. New CP VM and separate PostgreSQL 16 VM in the same VPC, empty database,
   fresh master key and verified TLS. Database ingress scoped to the CP only.
2. Runtime preflight, migration, login, restart, credential rotation, backup and
   restore. Record failure cases without secrets.
3. Private RDS PostgreSQL 16 if feasible; account free-tier eligibility is not
   established, so do not describe this leg as free.
4. User-provided Neon PostgreSQL 16 direct endpoint. Free-tier public TLS is a
   managed-provider interoperability test, not private-network proof.

The normal installer currently bootstraps a public GHCR verifier and a fixed
release signing key. An unmerged private candidate must not bypass verification
and be described as a successful signed installer test. Runtime proof and the
full signed-install/upgrade proof remain separate outstanding acceptance items.

No AWS BYODB runtime test has passed yet. Local proof is recorded separately.
No credentials, kubeconfigs, keys or certificates belong in this evidence file.
