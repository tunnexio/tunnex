# Private RDS BYODB walk — 2026-09-06

Status: in progress; no RDS runtime acceptance claimed at this checkpoint.

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
