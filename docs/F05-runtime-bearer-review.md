# F05 credential rotation review packet

Review state: **F05.1 + F05.2 source-ready, not F05 Done**. The one combined
authorized AWS development walk in `F05-decisions.md` has not been executed.

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
- The same operator action opens a bounded WireGuard request. The runtime keeps
  the successor private key locally and sends only its public half. Gateway
  desired state warm-stages that key with empty AllowedIPs while the old peer
  remains the sole owner of the `/32`.
- A gateway status report first acknowledges stage. The runtime then hot-swaps
  only the local interface key. A real nonzero candidate handshake on the
  assigned gateway atomically commits `devices.public_key`, telemetry, and the
  key revision; the next desired state retires the old peer. Timeout/suspend
  restores the last-good local key/config without changing the canonical key.

## Exact verification completed

F05.1's previously recorded default/Enterprise API, CLI, released-route, build,
and real PostgreSQL results remain unchanged. F05.2 added these focused current
head results from `apps/api`:

```text
go run ./cmd/migrate up
PASS: schema 94, dirty=false

go run ./cmd/migrate down
PASS on pristine state: schema 93, dirty=false
REFUSED with row/hash preservation after bearer history
REFUSED with row preservation after one WireGuard rotation row

TUNNEX_TEST_DATABASE_URL=postgres://... go test ./internal/agentruntime ./internal/nodes \
  -run '^(TestRuntimeServicePostgresContract|TestReportStatus)$' -count=1 -v
PASS (public-only prepare; zero-handshake stage; nonzero-handshake atomic key+telemetry commit; suspend cancellation)

TUNNEX_TEST_DATABASE_URL=postgres://... go test -tags enterprise ./internal/http \
  -run '^TestAgentCredentialRotationEnterpriseRoutePostgres$' -count=1 -v
PASS (non-skipped member 403, owner request/refetch, audit, secret-free wire)
```

From `apps/cli`:

```text
go test ./internal/cli -run '^(TestManagedRuntime(WireGuard|RotatesBearer|Refused)|TestAgentRuntime.*Unauthorized.*|TestManagedAgentRuntimeTerminalUnauthorized.*)' -count=1 -v
PASS (hot key switch, restart completion, cancellation restore, bearer no-WG-churn, F04 offboard)
```

From `apps/web`, using the installed pinned binaries (the local pnpm wrapper
attempted an unnecessary non-TTY reinstall):

```text
./node_modules/.bin/vitest run test/agentsruntimewiring.test.tsx
./node_modules/.bin/tsc --noEmit
PASS: 23/23 released-route tests and typecheck
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
   full F05 live proof; no production deployment is authorized here.
2. The local host is Darwin, so the injected executable hot-swap/rollback test
   is current source proof; real Linux `wg set`, gateway reconcile, and
   handshake evidence belong to the combined Ubuntu/AWS walk.
3. Full repository-wide API suites were not substituted for the focused
   default/Enterprise packages above. The exact F05 PostgreSQL integrations are
   non-skipped, and the full released-route web gate is green.
