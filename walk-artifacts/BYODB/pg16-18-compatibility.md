# PG16–18 compatibility candidate — 2026-09-06

Status: positive matrix and Neon preflight passed; **not live-CP-qualified or
merge-ready**. Product delta remains uncommitted pending review dispositions.

Candidate API image: `tunnex-byodb-compat:20260906b`, locally built linux/amd64.
Image manifest-list digest:
`sha256:5aa034d5ed27cd30daebc4dcace425ee10dedfe7258c5f0cd78e75f5e4ff9ec7`.
This is an unmerged candidate, not a signed customer release.

## Passed

- Dedicated internal Docker network `tunnex-byodb-matrix-20260906b`; no default
  Compose resources used. Fresh PostgreSQL 16, 17 and 18 fixtures each passed
  verify-full TLS and required channel binding, migration up/down/up convergence,
  version-matched pg_dump, offline archive listing, and actual pg_restore into a
  separate database. Restored migration state: `136|f` for all three versions.
- Focused dbcheck, db and preflight tests passed in open and enterprise editions.
- New candidate transferred to the existing AWS CP host after account verification
  (`735391218823`). Direct Neon PG18.6 connection and new Tunnex preflight passed
  from that host, preserving verify-full and channel_binding=require. Native
  client reported TLS1.3. No credentials or endpoint identifiers recorded here.
- Local generate-check passed. Dedicated gate database migration reached 136 clean
  after correcting a missing test-environment DATABASE_URL; the initial invocation
  failed configuration and is not counted as a migration pass.

## Not completed

- Fresh isolated Neon Compose project was configured. Redis/web started, but API
  startup hit the RDS CP's existing host port 8443 binding before execution. No
  Neon CP migration/login/backup claim is made. RDS CP remains serving; nothing was
  deleted or switched. Resolving the planned cutover is deferred until review.
- Full exact-content gates/CI, signed installer/upgrade and Kubernetes mTLS proof
  remain prerequisites. Existing PG16 VM/RDS evidence does not satisfy these gaps.

## Independent review: ranked and HELD

1. **P1 — migration lock continuity.** New `pgxmigrate.WithInstance` with an empty
   config derives database name `tunnex`; legacy postgres.Open used URL path
   `/tunnex`. Upstream advisory-lock hashing does not normalize these strings.
   For public.schema_migrations the old/new keys are 128373238 and 3413422074.
   Mixed-version migrators can therefore run concurrently. Recommendation:
   preserve the legacy identity and add an old/new lock contention regression.
2. **P1 — required channel binding must fail closed.** Pinned pgx v5.9.2 checks
   required binding inside SCRAM but not all other authentication paths. Source
   review found trust/cleartext/MD5 paths missing this requirement. A bounded local
   negative diagnostic used the existing PG16 fixture's trusted loopback over TLS:
   candidate preflight with `DATABASE_URL` and sslmode=require/channel_binding=require
   passed, while the native psql client refused authentication without binding.
   This diagnostic intentionally used the non-external configuration path; it is
   not a verify-full external negative proof. Recommendation: enforce the driver
   boundary and add TLS trust/password/MD5 refusal tests plus SCRAM-PLUS positives.

No review finding has been folded. Positive tests alone do not close these issues.
The matrix script is opt-in and currently macOS-path-specific, not a Linux CI gate.
