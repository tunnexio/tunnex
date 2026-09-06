# Approved compatibility fixes — 2026-09-06

Product content tip: `f6b276f` (unmerged candidate).

Both held P1 findings were explicitly dispositioned by the user for fixes/tests.

- Migration adapter preserves the legacy decoded URL path in the advisory lock.
  Real PG16/17/18 tests hold the old driver's lock, observe the new migrator blocked
  on the same key, release it and verify convergence. Plain and escaped URL paths
  passed. The legacy test client omits its unsupported channel-binding option;
  the new client retains it. This exception exists only inside the test fixture.
- Shared connection configuration uses upstream pgx v5.10.0 RequireAuth=SCRAM when
  channel binding is required. Direct, stdlib migration and runtime-pool paths each
  refuse trust/password/MD5/SCRAM-without-PLUS over verified TLS, without sending a
  password/authentication response. All 12 negative cases passed in both editions.
  Race-enabled focused tests passed. Environment-only binding and URL precedence
  also passed, including native backup propagation.
- Independent post-fold reviews completed. A native-backup environment parity
  omission found during re-review was corrected within the approved binding fix;
  focused tests and narrow re-review passed. No remaining actionable finding was
  reported within the bounded folds; this is not an unrestricted product audit.

Final candidate image `tunnex-byodb-compat:20260906d` was built from this product
content before the commit (only documentation changes followed the build).
Fresh internal Docker matrix `tunnex-byodb-matrix-20260906d` passed PG16/17/18
verify-full/required binding, migration up/down/up, old/new lock contention,
matching-major dump, archive listing, and actual restore: schema `136|f` each.
Fixtures retained. Default Compose project untouched.

## Live Neon runtime proof

Live Neon preflight passed from verified AWS account 735391218823 using the fixed
connection mechanism. The existing CP host connected to direct Neon PostgreSQL
18.6 with verify-full and required channel binding. Fresh migration progressed
through all 136 migrations; API became healthy without a migration restart.

Cross-region migration took longer than Compose's dependency health window;
the initial `up` reported unhealthy before migration completed. After confirming
API health, proxy services were started using canonical Compose. This is a live
runtime proof, **not** an unattended/signed-installer success claim. Recommend
co-locating CP and DB; initial-startup wait behavior remains to be qualified.

Passed over public HTTPS: bootstrap login 200, mandatory password change 204,
fresh login 200, organization creation 201 and readback 200. Final candidate image
20260906d then recreated the API against the same Neon DB/secrets; health, fresh
login and organization readback passed again. Credentials stored only in protected
scratch files, never in this repository. No browser screenshot claimed here.

RDS-backed CP services were stopped for the test URL cutover; its database and
volumes remain intact. The URL now serves the fresh Neon organization. RDS remains
billable. Final repository gates/CI and signed installer/upgrade remain separate
requirements. No merge or public release performed.

Final-image Neon native PG18 dump and offline archive listing passed. The protected
dump was restored into a new isolated local PostgreSQL 18 database using matching
pg_restore with `--no-owner --no-privileges`. Restored migration state `136|f` and
the expected organization count `1` passed. This verifies database restore only,
not a second restored CP/master-key deployment. Restore ownership/grants must be
applied for the chosen target role; provider-specific roles were not recreated.
Dump/log files remain protected scratch artifacts and are not committed.

Installer behavioral contracts passed. Helm lint and BYODB chart contracts passed
using the existing Helm 3.16.4 container with Ruby installed in that disposable
container. Local host lacks Helm; initial host/container dependency failures are
not counted as passing runs. Full gate chain is still running at this checkpoint.
