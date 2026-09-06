# Customer-owned PostgreSQL (Helm foundation)

The database may be private, managed or self-hosted. Its DNS name and port must be
reachable from both the API pods and migration Job. No public database endpoint or
cloud credentials are required. Use a dedicated Tunnex database and a primary,
session-preserving connection; transaction pooling is unsupported.

Have your existing secret-management workflow create these Secrets in the release
namespace **before** Helm installation (the migration Job is a pre-install hook):

- `customer-db`: key `connection-uri` containing the PostgreSQL URL.
- `customer-db-tls`: key `ca.crt` containing the server CA; optionally `tls.crt` and
  `tls.key` for mutual TLS. Do not put private material into Git or Helm values.

Database-specific values (merge with the other required chart values):

```yaml
database:
  urlSecret: customer-db
  urlSecretKey: connection-uri
  tls:
    existingSecret: customer-db-tls
```

The URL in the Secret uses your private hostname and database, with
`sslmode=verify-full&sslrootcert=/etc/tunnex/database-tls/ca.crt`.
For mutual TLS also set `sslcert=/etc/tunnex/database-tls/tls.crt` and
`sslkey=/etc/tunnex/database-tls/tls.key`. URL-encode credentials and parameter
values as needed. Both workloads mount the same files read-only. Mounting a CA
does not itself enable TLS verification; the URL must request it.

Without a custom CA, omit the TLS Secret and use the trust configuration appropriate
to the server. Existing `urlSecret` users retain the default `TUNNEX_DATABASE_URL`
key. The chart does not create, own or delete your database or existing Secrets.

The migration Job now validates connectivity and migration prerequisites before
DDL. The API validates its runtime connection before serving. The BYODB candidate
supports PostgreSQL 16, 17 and 18; keep `database.requireTLS: true` in production.
For servers requiring channel binding, preserve `channel_binding=require` in the
URL. Tunnex also requires SCRAM authentication for that mode, rejecting trust,
password and MD5 authentication rather than silently accepting unbound sessions.
Backup clients are selected to match the server major. Restore with a matching
major client into an isolated compatible target before replacing a live database.
Optional `database.migrationURLSecret` and `database.migrationURLSecretKey` select
separate migration credentials for the same database and TLS files. Without them
the Job uses the runtime URL. Migration-role ownership and runtime grants remain
the DBA's responsibility; Tunnex does not create privileged database accounts.

Current boundary: private PG16 VM/RDS runtime walks and a PG16/17/18 TLS migration,
legacy-lock contention and dump/restore matrix passed. This remains an unmerged
candidate; signed public-release installer/upgrade and Kubernetes mTLS proof remain
pending. Consult the PR evidence for the latest Neon live-install result.
Changing a URL Secret requires restarting the consuming API workload; credential
rotation/recovery automation remains in the BYODB implementation plan. Preserve
database backups and the separately backed-up Tunnex master key.
