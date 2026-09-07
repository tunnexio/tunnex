# AI gateway implementation and qualification — 2026-09-07

Branch `ai-improvement`, based on main `5199b62d15c5498bc8ede58703b9d5af5aa45c23`.
Approved team contract was committed as `f4825465` before policy implementation.
Community inclusion, organization opt-in default OFF, one explicit AI team and
honest soft admission thresholds are the user-approved release boundary.
This is an in-progress local qualification ledger, not merge or beta approval.

## Implemented customer behavior

- Existing active Agent Groups own exact OpenRouter model/key-ID policies; each
  agent chooses one current team and may narrow its model set. Human management
  endpoints reuse canonical ownership, roles and feature permissions.
- OpenAPI-generated HTTP/CLI/TypeScript contracts and migration140 persist desired
  and applied revisions transactionally. Partial/failed synchronization is visible
  and refuses affected new requests. Bounded edit-time/periodic/manual reconciliation
  reads back native persisted and in-memory scope before marking applied.
- Stable sealed native identities preserve accounting through policy edits and
  historical team moves. Allocation is serialized at64 retained bindings per org;
  two concurrent allocations at63 permit one64th and refuse the other before native
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
  refused while an independent agent remained active. Race PASS27.841s before
  final text-validation fold; final rerun is required below.
- Independent policy concurrent-cap race tests: open6.299s, enterprise6.933s.
  Native usage integration race12.810s; same-transaction MaxConns1 regression,
  scoped historical usage, empty/no-oracle handling and threshold refusal.
- Independent review found unqualified nested modalities, misleading notification
  wording, weak SSE completion assertions, missing edit-time team reconciliation
  and missing native-CI base migration. All accepted findings were folded. Root
  reviewed strict message validation; dedicated regressions show zero authorizer
  and provider arrivals on refused input. Focused races open4.975s/enterprise5.643s.
- Full web114files/1312tests PASS. TypeScript and Vite build PASS. Browser fixture
  exercised policy selection, failed-to-applied retry, attributed/uncosted usage,
  load failure and empty setup. Screenshot `walk-artifacts/ai-gateway-20260907/policy-fixture.png`
  contains synthetic data only. This is visual inspection, not a real installed UI session.
- Native codegen:50 files hashed after regeneration; second full run zero drift
  using sqlc1.31.1, oapi-codegen2.4.1, openapi-typescript7.4.4 and canonical RBAC/token
  generators. API open/enterprise and CLI builds PASS; CLI full suite PASS.
- Isolated PostgreSQL140 dirty=false. Every local DB command verifies project
  `tunnexai0907`, its labelled postgres container and dedicated network. Full-open
  gate identified the missing canonical updated_at trigger, added to migration140
  and the already-migrated disposable base only; remaining packages passed.
- Pinned Linux arm64 image walkthrough: private listener refusal, native-key
  revocation, independent active control, seven-token history through restart,
  admin credential rotation, metadata-only SQLite storage and independent-volume
  same-version restore PASS. See `AI-4-linux-installation-qualification-20260907.md`.
- Public website guide committed locally in isolated worktree
  `/private/tmp/tunnex-web-ai-improvement`: `0ce158ef7c562f035f5198dc9de41fb4ccb0238d`.
  Astro build, formatting and35navigation targets passed; original dirty checkout
  and stash preserved. Nothing published.

## Remaining before a completion claim

- Final current-tree full API gates and native tests after review folds.
- Actual control-plane-process installed walkthrough with real human auth and
  canonical enrollment; engine-only Docker and AuthFn test fixtures do not satisfy it.
- Exact final-head remote CI. The AI job now supplies verified shipped Linux binary
  and isolated migrated PostgreSQL and runs both editions plus enrolled HTTP proof.
  It has not run remotely; local workflow review is not a green CI run.
- No Helm cluster/CNI/TLS, cross-version downgrade, HA, crash-atomic accounting or
  instantaneous active-stream revocation claim. Named trigger for any advertised
  Helm production support is a customer-installation qualification on enforcing CNI.
- No push, PR, merge, release, production deployment or cloud action performed.

Next action: finish current-tree gates and the actual isolated CP-process walk,
then commit the final evidence and checkpoint before requesting remote validation.
