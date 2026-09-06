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

Live Neon preflight passed from verified AWS account 735391218823 using the fixed
connection mechanism. Fresh CP migration is in progress; no live CP/login success
claimed at this checkpoint. Final repository gates/CI and signed installer/upgrade
remain separate, pending requirements. No merge or public release performed.
