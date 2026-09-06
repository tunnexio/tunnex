# Neon preflight — blocked, not a successful CP installation

2026-09-06. User supplied a burner credential file and explicitly authorized the
Neon walk. The local file was restricted to mode 0600. Credentials and endpoint
identifiers are excluded from this record. No Neon schema or user changes made.

The supplied file had direct and transaction-pooled PostgreSQL URLs. Selected
the direct endpoint. Strengthened sslmode=require to verify-full using the API
image's system CA bundle; preserved channel_binding=require without downgrade.
Executed both checks from the existing AWS CP VM, not the administrator laptop.

## Observed

- Native PostgreSQL 16 client connects successfully with channel binding required.
- Client `\conninfo` reports TLSv1.3 / TLS_AES_256_GCM_SHA384.
- Server reports PostgreSQL **18.6 (c5250a2)**.
- Public schema table count 0; citext available, not installed. Read-only queries.
- Backend `pg_stat_ssl` reports false. This is not the same measurement as the
  client-to-Neon TLS connection; do not use it to claim no client encryption or
  claim visibility into every provider-internal network hop.
- Current Tunnex candidate preflight exits 1:
  `database_url_parameter_unsupported: use the documented common PostgreSQL URL parameters`.

## Blocking compatibility gaps

1. `internal/dbcheck` rejects channel_binding because the shared URL allowlist
   does not support it. Current pgx v5.9.2 supports required channel binding,
   but the migration-side Go lib/pq v1.10.9 uses SCRAM-SHA-256 without its PLUS
   channel-binding variant. Adding only an allowlist entry is not a complete fix.
2. Current qualification explicitly requires version >=160000 and <170000.
   The supplied PG18 database is outside that contract, independently of the
   first failure. We did not strip channel_binding to reach the second guard.

No CP deployment switch, migration, security-parameter removal or success screenshot
was performed. RDS-backed CP remains running. Next decision: preserve PG16 scope
and fix channel-binding parity across runtime/migrations/backups, or explicitly
expand server/client/restore qualification to PG18 as well. User disposition needed.

## Companion CLI documentation

Website PR #40 commit `6d412f7` contains two images generated from actual captured
installer dry-run and RDS diagnostic transcripts, plus complete downloadable text.
Terminal-app screenshot access was denied even after user approval. The images
are explicitly labeled transcript presentations, not direct Terminal screenshots.
Installer dry-run made no host/product installation changes and does not satisfy
the signed installer/upgrade gate. Website build passed after these additions.
