# F05.1 runtime-bearer rotation review packet

Review state: **source-ready, not F05 Done**. This packet covers only the
runtime bearer. WireGuard key rotation remains F05.2, and the authorized AWS
development walk in `F05-decisions.md` has not been executed from this branch.

## Focused outcome

- Migration 0094 backfills one revision-1 current credential, permits one
  current plus at most one candidate, retains at most ten terminal rows, and
  refuses rollback once rotation state/history exists without changing hashes.
- An owner/admin requests a one-hour rotation through a dedicated permission.
  The operator API and released Agents route expose revision/state/deadline
  only. A plain member receives 403 and neither requests nor renders rotation
  telemetry.
- The current runtime bearer prepares only a locally generated successor hash.
  The first candidate poll/report promotes it atomically; the previous bearer
  then receives the existing uniform 401.
- The runtime replaces its root-owned mode-0600 credential atomically, switches
  the HTTP client in-process, survives a lost prepare response or restart, and
  restores the old bearer after a definite failed candidate authentication.
  The credential-only path never reapplies or restarts WireGuard.
- Suspend cancels the request/candidate while preserving current. Revoke/delete
  invalidates both and leaves clean tunnel offboarding to the existing F04 401
  path.

## Exact verification completed

From `apps/api`:

```text
TUNNEX_TEST_DATABASE_URL=postgres://...@127.0.0.1:32768/tunnex?sslmode=disable \
  go test ./db -run '^TestAgentCredentialRotation(MigrationPostgres|MigrationContract|QueryContract)$' -count=1 -v
PASS (including real up/down, rollback refusal, hash preservation, and 10-row bound)

go test ./db ./internal/agentruntime ./internal/devices ./internal/http ./internal/rbac -count=1
PASS

go test -tags enterprise ./db ./internal/agentruntime ./internal/devices ./internal/http ./internal/rbac -count=1
PASS

TUNNEX_TEST_DATABASE_URL=postgres://... go test ./internal/agentruntime \
  -run '^TestRuntimeServicePostgresContract$' -count=1 -v
PASS (non-skipped real PostgreSQL prepare, promotion, old-401 contract)

TUNNEX_TEST_DATABASE_URL=postgres://... go test -tags enterprise ./internal/http \
  -run '^TestAgentCredentialRotationEnterpriseRoutePostgres$' -count=1 -v
PASS (non-skipped member 403, owner request/refetch, audit, secret-free wire)

go build ./...
PASS

go build -tags enterprise ./...
PASS
```

From `apps/cli`:

```text
go test ./internal/cli -count=1
PASS
```

From `apps/web`, using the installed pinned binaries (the local pnpm wrapper
attempted an unnecessary non-TTY reinstall):

```text
./node_modules/.bin/tsc --noEmit && ./node_modules/.bin/vitest run && ./node_modules/.bin/vite build
PASS: 75 files, 1047 tests, typecheck, production build
```

`git diff --check` also passes. The OpenAPI Go/TypeScript clients, sqlc
bindings, and RBAC mirror were regenerated with the repository-pinned
versions. No live credential, private key, or license was added.

## Review findings already corrected

- The initial two-statement candidate promotion violated the partial unique
  current index on real PostgreSQL. It is now one atomic two-row transition.
- The first bounded-history trigger used an alias conflicting with PL/pgSQL
  `OLD`; the real migration test caught it and the alias was corrected.
- Rotation status was initially chained behind a successful F04 status read.
  The released route now loads both independently, so one unavailable status
  cannot hide the operator rotation control.
- A candidate scratch file could survive a suspend/refusal and be reused after
  resume even though PostgreSQL retained its hash as terminal history. Definite
  401 paths now restore/preserve current as appropriate and discard that stale
  successor; the executable runtime test covers both restart and current-bearer
  refusal cases.

## Remaining proof / risk

1. Execute the exact AWS DEV CP and Ubuntu VM checklist in
   `docs/F05-decisions.md` on an exact content commit. This is the remaining
   F05.1 live proof; no production deployment is authorized here.
2. F05.2 still needs a separately reviewed bounded-overlap WireGuard public-key
   rotation design and implementation. This branch intentionally does not
   alter WireGuard keys/configuration.
3. Full repository-wide API suites were not substituted for the focused
   default/Enterprise packages above. The exact F05 PostgreSQL integrations are
   non-skipped, and the full released-route web gate is green.
