# Private RDS BYODB walk — 2026-09-06

Status: focused private RDS runtime proof passed; signed installer/upgrade and
full story acceptance remain pending.

User explicitly requested the RDS leg and live screenshots for it and the prior
VM leg. AWS identity verified: account `735391218823`, IAM user `aws-cli`, region
`ap-south-1`. The existing private PostgreSQL VM and its CP data are preserved.

Created stack `tunnex-byodb-rds-20260906a` using
`deploy/aws-byodb-rds-walk.yaml`: PostgreSQL 16.14, db.t4g.micro, 20 GiB encrypted
gp3, Single-AZ, PubliclyAccessible=false, rds.force_ssl=1. Two private subnets
meet the RDS subnet-group requirement; PostgreSQL ingress uses the existing
CP-only database security group. This is a paid disposable test, not a free-tier
claim. AWS manages the master password in Secrets Manager; it is never printed.

The application will use a separately created database-owner role, not the RDS
master role. Use the official AWS RDS CA bundle with sslmode=verify-full.
Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html

Prior VM UI screenshots are actual browser captures, not renderings of CLI output:
empty login, organization creation, and dashboard after creating BYODB VM Walk.
Website PR #40 commit `a231e5a` contains the images and contextual captions.
Website typecheck, tests and build passed under local Node 26.4.0. The initial
default Node 20 attempt failed Wrangler's runtime minimum and was rerun with the
installed supported-major runtime. No website production deployment performed.

## Verified live result

Stack CREATE_COMPLETE; RDS available and PubliclyAccessible=false. Endpoint
`tunnex-byodb-rds-20260906a.cram4qqss34l.ap-south-1.rds.amazonaws.com` resolved
from the CP runtime to private address `10.245.3.19`. PostgreSQL reports 16.14.
The CP remains at `https://cp.43.205.96.138.sslip.io` but now serves the separate
RDS-backed test installation.

Installation directory `/home/ubuntu/byodb-rds`; explicit Compose project/network
`tunnex-byodb-rds-20260906a` / `tunnex-byodb-rds-20260906a_default`.
Existing VM-backed project `tunnex-byodb-aws-20260906a` was stopped with its own
Compose file and project flag; its database, secrets and other volumes were NOT
removed. RDS used an empty database and freshly generated CP secrets. This is
not an in-place migration of the VM-backed organization.

The candidate API/web/nginx identities and canonical deployment file are unchanged
from the preceding VM proof (product content `da73afc`). No RDS-specific product
patch was needed. This remains a manually composed candidate runtime proof, not
a signed launcher run or release.

Passed:

- Runtime database-only preflight with the official RDS CA and verify-full.
- Automatic migration: `schema_migrations = 136|false`.
- Application database role `tunnex_app`: rolsuper=false, rolcreatedb=false,
  rolcreaterole=false. RDS master credentials are not the CP runtime credentials.
- SQL connection reports SSL=true, TLSv1.3; citext is installed.
- AWS parameter-group readback rds.force_ssl=1, attachment in-sync.
- HTTPS bootstrap login 200, password change 204, new-password login 200.
- Browser login, organization creation and dashboard for `BYODB RDS Walk`.
- External custom dump and archive-list validation via the API image pass.
  This does NOT claim a restore drill from the RDS dump.
- API restart, Compose health wait, database-only preflight and fresh HTTPS
  login 200 after restart.

The attempted SQL `SHOW rds.force_ssl` returned "unrecognized configuration
parameter". We corrected the evidence query to read the AWS parameter group;
the preceding SQL checks already returned migration/role/TLS evidence. No
product workaround or database security weakening was performed.

## Screenshots and limits

Website docs include six actual browser captures: three VM and three RDS
(empty sign-in form, organization onboarding, dashboard). All were visually
inspected; no password, token, connection URL or key is displayed. Captions
explicitly distinguish browser onboarding from database configuration and
candidate runtime proof from signed-release acceptance. The website build was
rerun successfully after adding the RDS section and images.

RDS remains running for inspection and is billable. No RDS failover, RDS restore,
database password rotation, signed upgrade or Neon result is claimed. No merge
or production website publish performed. Credentials remain outside Git in
protected files; the RDS CP has different login credentials from the VM CP.
