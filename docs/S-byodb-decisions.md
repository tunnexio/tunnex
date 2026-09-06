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

### Slice 1 checkpoint

Implemented custom URL Secret keys and shared read-only DB TLS Secret mounts for
API/migrations, preserving the legacy key default. Customer configuration notes:
`deploy/helm/tunnex-cp/BYODB.md`. The contract is wired into CI.

Local checks passed: Helm lint; parsed YAML contracts for legacy, TLS, custom key
and migrations-disabled configurations; existing HA deployment gate contract;
`git diff --check`. No cloud mutation or live DB proof performed. Full gates and
review remain pending; next implementation slice is runtime preflight.

### Implementation checkpoint — 2026-09-06

Installer and runtime wiring are now implemented: bundled/external choice, protected
URL-file input, preserved reinstall settings, external Compose profile, pre-migration
driver/TLS/PostgreSQL-16 checks, private TLS mounts, optional separate Helm migration
role, and external-aware dump/archive validation in the existing upgrade safety gate.
External mode requires verify-full. Common DSN parameters are deliberately enumerated
so API, migration and backup clients agree; native IAM renewal remains deferred.
Initial version qualification is PostgreSQL 16 (matching the bundled DB and backup
client). Additional major versions require compatibility/restore qualification.

Website docs are on companion branch `codex/byodb-installation-docs` in tunnex-web.
The production launcher pin is NOT advanced to an unpushed/unreleased source. Its
update follows a green signed BYODB-capable release; old manifests are refused for
external installation/upgrade rather than silently selecting bundled Postgres.

User-added same-PR scope: fix main CI run 34015654906. Its release guard assumed a
draft release created a Git ref and failed with HTTP 422. Explicit missing main-build
ref creation now follows ledger validation; no existing tag is moved. The offline
regression fails on baseline a3c192a and passes on the fix; published/moved refs still
refuse. No live release or tag has been created by this work.

## Deferred scope

### Approved compatibility expansion — 2026-09-06

User explicitly approved implementing and testing PG16/17/18 and required channel
binding against the existing Neon PG18 database. This supersedes the initial
PG16-only qualification target, but is not a claim that the new matrix passed.
Use pgx/v5 for both runtime and the golang-migrate database/sql adapter, preserving
the existing migration table and session advisory-lock mechanism. Preserve
channel_binding through preflight and native backup-client environment mapping.
Ship versioned PostgreSQL 16/17/18 clients; select pg_dump from the detected server
major so a newer dump client does not introduce restore incompatibilities for PG16.
Archive listing may use the newest pg_restore offline; actual restore drills must
use the appropriate versioned client against an isolated target. Keep the bundled
server at PG16; do not change customer server versions or drop security parameters.
Require migration/runtime/dump/restore matrix proof and fresh live Neon proof before
claiming compatibility. No automatic major upgrade or migration of customer data.

Native cloud IAM token renewal, DB provisioning, arbitrary engine support, automatic
network creation and moving existing bundled data are separate follow-ups. Reuse
customer-managed secret synchronization without requiring a new secret operator.

## Acceptance

Private-only DB install, failure diagnostics (DNS/network/auth/CA), migration and
upgrade, backup/restore, credential rotation and restart/failover recovery. Qualify
mechanisms rather than repeating identical walks for every provider. No public DB
endpoint or customer cloud-admin credentials may be required.
