# AI gateway implementation and qualification — 2026-09-07

Branch `ai-improvement`, rebased onto verified main `26a36afc9be657af94127c474e173783c91318c3`.
Original base was `5199b62d`; upstream added only release-CI handling and its shell
regression. Before/after rebase product trees were identical.
Approved team contract was committed as `f1c14c98` (`f4825465` before rebase) before policy implementation.
Community inclusion, organization opt-in default OFF, one explicit AI team and
honest soft admission thresholds are the user-approved release boundary.
This is a local qualification ledger, not merge or beta approval.

## Implemented customer behavior

- Existing active Agent Groups own exact OpenRouter model/key-ID policies; each
  agent chooses one current team and may narrow its model set. Human management
  endpoints reuse canonical ownership, roles and feature permissions.
- OpenAPI-generated HTTP/CLI/TypeScript contracts and migration 140 persist desired
  and applied revisions transactionally. Partial/failed synchronization is visible
  and refuses affected new requests. Bounded edit-time/periodic/manual reconciliation
  reads back native persisted and in-memory scope before marking applied.
- Stable sealed native identities preserve accounting through policy edits and
  historical team moves. Allocation is serialized at 64 retained bindings per org;
  two concurrent allocations at 63 permit one 64th and refuse the other before native
  key creation. No historical binding is silently deleted to reset the limit.
- Usage selectors derive native IDs from the authorized tenant. Empty selections
  return zero without an unfiltered engine query. Native observed cost remains the
  single ledger; unknown prices, incomplete stats and observed thresholds refuse
  monetary-policy admission. Concurrency can overshoot; no strict cap claim.
- Production server composition, Community UI policy/assignment/usage controls,
  optional private Compose/Helm setup and public documentation are implemented.
  Message payloads are restricted to qualified string text before authorization;
  multimodal blocks, tools, extra controls and nested duplicate fields are refused.

## Evidence collected

- Native production HTTP walk: actual Community agent enrollment, scoped credential
  exchange, pinned Bifrost and instrumented zero-spend provider. Complete SSE text,
  finish and terminal events; model denial with unchanged provider arrivals; stable
  key across edits; preserved old-team history after moves; canonical revocation
  refused while an independent agent remained active. Final current-product native race suites PASS: open gateway 49.730s / HTTP 52.564s;
  enterprise gateway 51.190s / HTTP 51.875s. No paid smoke was enabled.
- Independent policy concurrent-cap race tests: open 6.299s, enterprise 6.933s.
  Native usage integration race 12.810s; same-transaction MaxConns1 regression,
  scoped historical usage, empty/no-oracle handling and threshold refusal.
- Independent review found unqualified nested modalities, misleading notification
  wording, weak SSE completion assertions, missing edit-time team reconciliation
  and missing native-CI base migration. All accepted findings were folded. Root
  reviewed strict message validation; dedicated regressions show zero authorizer
  and provider arrivals on refused input. Focused races open 4.975s / enterprise 5.643s.
- Full web: 114 files / 1,314 tests PASS after final review folds. TypeScript and Vite build PASS. Browser fixture
  exercised policy selection, failed-to-applied retry, attributed/uncosted usage,
  load failure, empty setup and saving blank overrides as inherited models. Screenshot `walk-artifacts/ai-gateway-20260907/policy-fixture.png`
  contains synthetic data only. This is visual inspection, not a real installed UI session.
- Native codegen: 50 files hashed after regeneration; second full run zero drift
  using sqlc 1.31.1, oapi-codegen 2.4.1, openapi-typescript 7.4.4 and canonical RBAC/token
  generators. API open/enterprise and CLI builds PASS; CLI full suite PASS.
- Isolated PostgreSQL 140 dirty=false. Every local DB command verifies project
  `tunnexai0907`, its labelled postgres container and dedicated network. Full-open
  gate identified the missing canonical updated_at trigger, added to migration 140
  and the already-migrated disposable base only. Final full API suite passed in
  both editions, including schema tests; enterprise 62 packages had tests. API/CLI
  vet passed, and all four core Go modules had no gofmt drift. The unchanged Linux
  node runtime gate from the foundation remains applicable: apps/node and runtime
  sources have no diff from main. MCP authorization regressions passed in API gates.
- Pinned Linux arm64 image walkthrough: private listener refusal, native-key
  revocation, independent active control, seven-token history through restart,
  admin credential rotation, metadata-only SQLite storage and independent-volume
  same-version restore PASS. See `AI-4-linux-installation-qualification-20260907.md`.
- Public website guide committed locally in isolated worktree
  `/private/tmp/tunnex-web-ai-improvement`: `621b8d7` (initial guide `0ce158ef7c562f035f5198dc9de41fb4ccb0238d`).
  Astro build, formatting and 35 navigation targets passed; original dirty checkout
  and stash preserved. Nothing published.

## Final installed walkthrough

`AI-5-installed-process-walk-20260907.md` records a successful fresh reproducible
Linux run with the actual API process, real administrator login/password change,
canonical agent enrollment and production policy/credential routes. Distinct-team
cross-model requests refused before provider arrival. Strict SSE completed through
API and engine. Known pricing, complete scoped observed cost and applied revisions
were verified before the soft-threshold refusal, with an independent team control.
Canonical revocation, API restart, organization disable/re-enable and streamed plus
non-streamed SQLite content omission passed. No provider credits were spent.

`AI-gateway-provider-rotation-20260907.md` separately proves rotating the engine's
provider environment credential while preserving the native key ID and two-request,
ten-token history. Old credentials were rejected by the instrumented provider.

Both reproducer scopes received independent review. Exact-name collisions, volume
ownership, pre-start DB mount checks, optimized-Python refusal, immutable cleanup
IDs and positive response assertions were fixed before the final run. Three
zero-Docker isolation regressions passed. Owned walkthrough containers are stopped;
volumes and redacted evidence are retained. No customer infrastructure was changed.

All six AI legs have local implementation/qualification evidence. This does not
turn local tests into remote CI or prove the explicitly excluded deployment paths.

## Release qualification remaining

- Exact final-head remote CI. The AI job now supplies verified shipped Linux binary
  and isolated migrated PostgreSQL and runs both editions plus enrolled HTTP proof.
  It has not run remotely; local workflow review is not a green CI run. Live branch
  rules were read: gates, dependency review, formatting/vet, API/CLI/node/operator
  vulnerability checks, Go/JS CodeQL and the image-scan setup check are required.
  Extracted client jobs are not present in the current main-branch required-check
  rules; no client/helper source or runtime change was introduced.
- No Helm cluster/CNI/TLS, cross-version downgrade, HA, crash-atomic accounting or
  instantaneous active-stream revocation claim. Named trigger for any advertised
  Helm production support is a customer-installation qualification on enforcing CNI.
- No push, PR, merge, release, production deployment or cloud action performed.

Next action: obtain push/PR authorization for the committed candidate and run the
required checks on that exact remote head. No merge or release is authorized.
