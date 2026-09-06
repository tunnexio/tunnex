# BYODB: provider-neutral private PostgreSQL

Status: approved plan; implementation in progress on `codex/byodb-private-postgresql`.
Baseline: main `a3c192a`. Not release-ready or live-proven.

## Locked decisions

1. External means customer-owned, not publicly reachable. Deploy the CP where
   customer routing and DNS already reach PostgreSQL; no cloud credentials,
   mandatory connector, or CP-dependent bootstrap tunnel.
2. Support qualified PostgreSQL versions/features, not arbitrary database engines.
   Existing session advisory locks require a direct or session-preserving endpoint;
   transaction pooling is not supported. A dedicated logical database is sufficient.
3. Preserve `database.url` and `database.urlSecret`. Prefer existing Secrets and
   permit custom keys, custom CA and optional mutual TLS. Never emit credentials
   in diagnostics or commit customer credentials. Use verified TLS for production.
4. Validate from the deployment runtime before migration, not from the browser or
   administrator laptop. Validate DNS/connectivity, TLS/authentication, writable
   primary, version, extension and permissions with bounded, redacted failures.
5. Helm/GitOps remain first-class. CLI is optional. The Compose installer must stop
   requiring bundled Postgres in external mode; upgrades need external-aware backup.
6. Customer owns the DB lifecycle: uninstall never deletes it. Support scoped runtime
   access and separate migration credentials, controlled rotation/reconnect, and
   documented recovery including the separately backed-up Tunnex master key.

## Reviewable implementation sequence

- Slice 1: backward-compatible Helm Secret keys and shared DB TLS file mounts,
  render contracts and customer configuration example.
- Slice 2: shared bounded runtime preflight and migration credential separation.
- Slice 3: installer/Compose external mode and external-aware upgrade/backup handling.
- Slice 4: focused live private-only proof, rotation/recovery tests and customer docs.

Each slice records its tests honestly; render/unit tests do not satisfy live proof.
Required repository gates, story-end review and explicit merge sign-off remain owed.

## Deferred scope

Native cloud IAM token renewal, DB provisioning, arbitrary engine support, automatic
network creation and moving existing bundled data are separate follow-ups. Reuse
customer-managed secret synchronization without requiring a new secret operator.

## Acceptance

Private-only DB install, failure diagnostics (DNS/network/auth/CA), migration and
upgrade, backup/restore, credential rotation and restart/failover recovery. Qualify
mechanisms rather than repeating identical walks for every provider. No public DB
endpoint or customer cloud-admin credentials may be required.
