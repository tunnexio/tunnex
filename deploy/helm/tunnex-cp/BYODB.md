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

Current boundary: this slice adds Secret selection and TLS file delivery, not a
completed onboarding/preflight, automatic rotation or live compatibility proof.
Changing a URL Secret requires restarting the consuming API workload; credential
rotation/recovery automation remains in the BYODB implementation plan. Preserve
database backups and the separately backed-up Tunnex master key.
