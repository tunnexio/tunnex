# Local private PostgreSQL proof — 2026-09-06

Status: in-progress implementation proof, not a published-release or cloud walk.
Branch: `codex/byodb-private-postgresql`, baseline `a3c192a`; tested working-tree
API image `tunnex-byodb-dev:20260906a` (candidate changes not yet committed).

Final implementation checkpoint: product/CI content committed as `b3ab8cd`, draft
core PR #59. Companion website documentation: tunnex-web PR #40 (`5f03fea`).

## Isolation

- Dedicated Compose project `tunnex-byodb-proof-20260906a`.
- Docker network `tunnex-byodb-proof-20260906a_default`: `Internal=true`.
- PostgreSQL container has empty host port bindings (`{}`); private DNS alias only.
- Additional canonical installed-manifest project `tunnex-byodb-installed-20260906a`
  uses its own internal network and stores. Existing/default projects untouched.
- Scratch TLS material and fixture configuration live outside Git. No keys, URLs
  containing credentials, dumps, bootstrap passwords or private certificate files
  are evidence artifacts.

## Observed results

1. API-image `preflight --database-only` connected using `sslmode=verify-full`
   and a mounted CA, before a Tunnex schema existed: PASS.
2. CP startup applied schema through migration 136 and `/healthz` returned
   `status=ok`: PASS.
3. Wrong password: `database_auth_failed`, exit 1.
4. Missing CA trust: `database_tls_failed`, exit 1.
5. Missing private DNS name: `database_dns_failed`, exit 1.
6. `sslmode=disable` in external mode: `database_tls_required`, exit 1.
7. API-container custom-format dump and archive listing: PASS after fixing the
   discovered libpq PGDATABASE issue. PGDATABASE does not expand the URI here;
   explicit libpq environment fields now select the target without DSN argv.
8. Restore into a separate database: PASS, `schema_migrations` = `136|f`.
9. CP against restored DB with the original roots volume: healthy.
10. Fresh database owned by a role with NOSUPERUSER, NOCREATEDB and NOCREATEROLE:
    migration and CP startup healthy. No server-wide admin role was required.
11. Canonical installed manifest pointed initially at the already-initialized
    fixture DB with a different roots volume: correctly refused decrypting the
    existing agent CA. This was a fixture mismatch, not a reason to regenerate
    keys. The canonical fresh-install test was then given its own empty DB.
12. Canonical `deploy/tunnex.yml`, external profile and an empty dedicated database
    owned by the non-superuser role: preflight and CP healthy. Only API and Redis
    run in that installed project; there is no bundled Postgres service running.
13. Rotate the fixture DB owner's password, update the protected installed URL
    and recreate API using the final candidate image: preflight and CP healthy.
    This proves controlled rotation, not automatic secret hot-reload.
14. Restart the private PostgreSQL container without restarting the installed CP:
    database preflight passes and CP health remains OK after DB recovery. This
    proves restart recovery, not a multi-node PostgreSQL failover.

## Local gates

Passed: generate-check, migrate, test-editions, build-editions, test-node; targeted
dbcheck tests on real isolated PostgreSQL; installer full mocked-release/host flow
(including external mode and interactive bundled mode); standalone installer/Helm
contracts; upgrade helper/apply/runner contracts; signed-release contract and the
new release-source-ref regression. The release regression fails on a3c192a with
the same HTTP 422 class as main CI and passes on the fix.

Core web typecheck/tests/build passed (1,281 tests); website typecheck/tests/build
passed (214 tests). Final exact-SHA hosted CI and story-end review are not replaced
by these local results. A final core-web rerun after frozen-lockfile dependency
installation is tracked separately in the session.

## Still owed

Signed public installer/release-path execution, Kubernetes runtime mTLS proof,
multi-node database failover, exact-head CI and story-end review.
Local containers do not establish all-provider qualification. No cloud resources
were mutated and no registry artifacts published. Test resources are retained;
cleanup is not performed as part of this evidence record.
