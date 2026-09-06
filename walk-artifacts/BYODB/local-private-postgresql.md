# Local private PostgreSQL proof — 2026-09-06

Status: in-progress implementation proof, not a published-release or cloud walk.
Branch: `codex/byodb-private-postgresql`, baseline `a3c192a`; tested working-tree
API image `tunnex-byodb-dev:20260906a` (candidate changes not yet committed).

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

## Still owed

Final-content recheck, signed public installer/release-path execution, Kubernetes
runtime mTLS proof, credential rotation/reconnect and database failover/recovery.
Local containers do not establish all-provider qualification. No cloud resources
were mutated and no registry artifacts published. Test resources are retained;
cleanup is not performed as part of this evidence record.
