# Optional sandbox module: source candidate evidence

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

Isolated worktree `<preserved-local-worktree>`, branch `story/sandbox-optional-module`, committed integration baseline `41697eb` (includes `400dba4`). Runner operator checkout and live configuration were not edited. No new database migration or API endpoint. Only the existing Meta contract gains an optional `sandbox_module_state` enum.

## Behavior and operator sequence

`TUNNEX_SANDBOX_MODULE=on|off|draining`; unset resolves disabled without runtime/fixture configuration, enabled with existing configuration. An upgraded configured installation therefore retains its existing behavior without adding an environment variable. Unknown modes fail validation; `draining` requires the existing runtime configuration; `off` refuses conflicting configuration.

Fresh disabled startup executes one bounded (10 second) retirement guard query. It does not construct a sandbox store, worker, runtime client, listener, sandbox certificate reader, channel, scheduler or ticker. Router sandbox repository/wake dependencies are genuinely nil, not typed-nil interfaces. Its public metadata reports disabled. Explicit on without runtime configuration exposes setup but creates no worker or runtime.

Draining blocks new API creation through existing availability callbacks while retaining management and the existing reconciler. It suppresses the optional operator initial-create intent. Existing accepted sandboxes can remain until deleted/expired and reconciled; the setting does not assert deletion and does not stop helpers/runner expiry supervision.

Safe deployment disable is deliberately staged:

1. Disable organization sandbox creation through the existing setting, which withdraws sandbox projections/access. This is an admission/policy change, not physical retirement.
2. Retain runtime configuration and use deployment `draining` while existing sandboxes are deleted/expired and cleanup/worker retirement finishes. A merely stopped sandbox still blocks deployment off.
3. All organizations must have creation disabled; all sandbox records must be desired/observed deleted; all runtime bindings must carry worker retirement receipts; no active sandbox peer or unrevoked runtime credential may remain.
4. Only then remove runtime/fixture configuration and select `off` (or leave it unset). The startup guard refuses implicit or explicit off if any durable obligation remains. Independently installed worker/helper services can be stopped only after their obligations are retired; this slice does not automate service teardown or prove remote host storage deletion.

The off guard is a deployment-startup check, not a distributed hot-reconfiguration transaction. Apply admission/draining consistently across replicas before stopping the last qualified cleanup adapter. Historical records and account public keys are preserved and do not block off.

Sidebar and command palette hide the module while metadata is absent, loading, failed or disabled. Direct sandbox routes wait for capability and redirect when off before importing any lazy sandbox page. Existing `/meta` health/version read and the capability provider share one cached request, with no new polling or endpoint. Capability changes require browser reload. Sandbox JS and CSS are separate lazy chunks.

For a disabled organization on an enabled shared server, policy snapshots skip ListActiveSandboxProjections. Existing SQL already required organization enabled, so the result remains empty and existing grants are withdrawn. This does not disable privileged retained-resource cleanup.

## Validation

Node 24.21.0 and pnpm 10.34.5 from the existing local QA tooling; frozen lockfile and ignored install scripts; lockfile unchanged. Pinned oapi-codegen v2.4.1 generated API/CLI contracts and openapi-typescript 7.4.4 generated TS types.

Focused Go command in apps/api: `GOFLAGS=-mod=readonly GOCACHE=<preserved-local-artifact> GOMAXPROCS=2 go test -p 1 ./internal/config ./cmd/server ./internal/http -run 'TestSandboxModule|TestMetaSandboxModule'`, also enterprise. Tests cover default off, configured backward compatibility, invalid mode/config combinations, no factory/store/timer/run/close/wake construction when off, retained cleanup callback while draining, blocked creation, pending retirement rejection and public metadata states. Both editions pass.

Disposable PostgreSQL regression: `go test -p 1 -count=1 ./internal/sandboxes -run TestSandboxModulePostgres -v`, same readonly/cache flags, repeated enterprise. Passed open 3.008s, enterprise 2.926s. It checks enabled-org admission fence, saved keys surviving fresh off and completed retirement, active projection presence, disabled-org withdrawal, zero projection query calls when disabled, continued delete/pending-cleanup/reconciliation, retirement blocked without worker receipt, and successful off only after receipt. API protocol/provider behavior is exercised with existing synthetic cleanup fixtures; no actual runtime or live database.

The prior shared test container was exited with no published ports. It was not restarted. A separate temporary `tunnex-optional-module-db-20261004` container used cached postgres:17-alpine, loopback-only dynamic port and tmpfs data, with local fixture trust authentication and no new credential. Testpostgres created/dropped its own migrated database per test. The URL was constructed only in subprocess memory. Fixture runner: `<preserved-local-artifact>`.

Web focused gate: sandbox-module, command-palette, responsive nav, login/SSO health-metadata and component style census. TypeScript checking and production Vite build pass. Build emits Sandboxes, SandboxSetup, SandboxCustomSkills and shared SandboxChrome JS/CSS chunks; existing main bundle size warning remains. Final focused counts are recorded in the handoff.

Native server builds pass open and enterprise. `git diff --check` passes. Broad unrelated suites, full Docker gates, remote/live qualification, deployment, push and merge were intentionally not run.

Actual local Chromium QA used the built source on loopback 5191 and intercepted every API request with synthetic responses. Modes: disabled/enabled/draining/metadata-error; desktop 1440x1000 and mobile 390x844. Off/error redirected direct /sandboxes URLs, hid sidebar and command-palette entries, and requested zero sandbox JS, CSS or inventory endpoints. Enabled/draining rendered the module and requested its lazy chunks. All modes had no page errors or horizontal viewport overflow. Desktop disabled and mobile enabled navigation screenshots were visually inspected. Evidence stays local under `<preserved-local-artifact>`; harness `<preserved-local-artifact>`, results.json and PNGs. No screenshots were uploaded.

## Honest residual overhead

Sandbox Go code and generated routes remain in the monolithic API binary. Existing schema/tables/indexes remain, historical/key rows are retained, a one-time startup retirement query remains, and a small metadata/route gate remains in the main web bundle. Other Tunnex services and their normal polling are unaffected. This slice removes dedicated sandbox service/timer/network/certificate/runtime construction for never-enabled deployments and removes sandbox page/style downloads when off; it is not a separate package or schema installation model.

Final focused web run: 5 files, 36 tests passed (4.15s). An invocation from the repository root emitted a Tailwind content-path warning during tests; the production build was run from apps/web and its actual CSS was verified in Chromium. No UI source/style failure remains in this focused set.

Cleanup complete: this task's temporary PostgreSQL container was stopped and auto-removed; the loopback preview was stopped. Existing operator/shared containers were left untouched. Final native open/enterprise server outputs were built to /tmp and not executed.
