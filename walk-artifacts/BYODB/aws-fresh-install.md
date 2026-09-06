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

The above was the initial teardown checkpoint. The live results below supersede
its pending runtime/cleanup status, not its remaining acceptance requirements.
No credentials, kubeconfigs, keys or certificates belong in this evidence file.

## Fresh AWS runtime proof — 2026-09-06

Old controller and base CloudFormation stacks both verified DELETE_COMPLETE.
All four old EC2 instances terminated; all six old gateway volumes deleted.
Old CP root volume deleted on termination; Elastic IP allocation
`eipalloc-0572e6c398180d1b8` released. No snapshots/backups of old walk data taken.
The final regional volume inventory contains only the two fresh VM roots. This
does not claim deletion of historical ECR repositories, every IAM role or default
VPC infrastructure.

New stack `tunnex-byodb-aws-20260906a` verified CREATE_COMPLETE:

| Component | Verified target |
| --- | --- |
| VPC | `vpc-00a41471ec7bce5d2` |
| CP | `i-0679744e281749144`, c7i-flex.large, `10.245.1.10`, public `43.205.96.138` |
| PostgreSQL VM | `i-0f8987f25fc8deffb`, t3.micro, `10.245.2.10`, **no public IP** |
| Public CP URL | `https://cp.43.205.96.138.sslip.io` |
| Compose project | `tunnex-byodb-aws-20260906a` |
| Compose network | `tunnex-byodb-aws-20260906a_default` |

Infrastructure template: `deploy/aws-byodb-walk.yaml`, validated by CloudFormation
and actually created. Ubuntu AMI `ami-0c0fd09cfe77b59dc` resolved from Canonical's
AWS public SSM parameter. CP Docker 29.1.3, Compose 2.40.3. DB port 5432 and SSH
allow the CP security group only. The private DB subnet uses the lab CP for outbound
package traffic; no paid NAT Gateway. This cost-saving lab NAT composition is not
a production HA recommendation. The certificate is a short-lived seven-day lab
certificate with the database private IP SAN; production certificate management
is not qualified by this fixture.

Candidate API/web/nginx built linux/amd64 using committed Dockerfiles and product
content `da73afc201f956a9c2c71b88add9e2362f206deb`. No product-file difference from
that SHA existed at build time. Images transferred over SSH and pinned by local
image identity in the CP environment, **not published/signed release artifacts**.
The unchanged canonical `deploy/tunnex.yml` ran api/web/nginx/redis/caddy with the
external profile; no bundled PostgreSQL or node-agent container was started.
Fresh named secrets volume, empty external database and new admin were used.

API image identity: `sha256:4d030a30368f6fe9724e86e10f9de153a6892e550840d14b3e8a44311a6a9252`.
Web: `sha256:ca8c49cded928bb130ca28894c1309bb7f8289c01db42fb00d725bbb79493b77`.
Nginx: `sha256:ed8c91ad706302d10e6e5618ee508c0a027825f1054d9ae16b86b5b3909fdd73`.

### Passed on real VMs

- Runtime `preflight --database-only`: private connectivity, verified TLS,
  authentication, writable PostgreSQL 16 and migration prerequisites.
- Automatic empty-database migration: `schema_migrations = 136|false`.
- `pg_stat_ssl` confirms API connections use TLSv1.3.
- Public HTTPS health returns 200 with normal certificate validation.
- Bootstrap login 200, forced password change 204, new-password login 200.
  Credentials saved outside Git in a mode-0600 file, never printed in evidence.
- `preflight --database-dump` and `--database-verify-archive` succeed.
- Restore into a second empty logical database (`tunnex_restore`) succeeds;
  restored migration state `136|false`. This proves database restoration, not a
  separately started restored CP or full key-bound upgrade recovery.
- PostgreSQL service restart followed by runtime preflight passes with API
  restart count still 0 and unchanged original start timestamp.
- Deliberate API restart, Compose health wait and fresh HTTPS login 200.
- Wrong password -> `database_auth_failed`; missing CA ->
  `database_config_invalid`; missing DNS -> `database_dns_failed`; disabled TLS ->
  `database_tls_required`. Each exits nonzero without disclosing the real DSN or
  password. No network-timeout fault injection claimed.

### Observed fixture issue

The initial custom bootstrap script applied umask 077 before creating the public
CA directory, unintentionally leaving it 0700. The unprivileged API could not read
the CA and preflight correctly refused. Explicit directory mode 0755 and public
CA mode 0644 fixed this fixture; private keys/password files remained restricted.
This was not an installer-generated directory or a product-code patch.

### Still pending

Private RDS and user-provided Neon; DB credential rotation on AWS; restored CP
startup with key binding; actual signed installer/upgrade end-to-end; final review
and exact-final-SHA gates. No merge or release has been performed. This walk must
not be presented as full installer, Kubernetes, HA failover or story acceptance.
