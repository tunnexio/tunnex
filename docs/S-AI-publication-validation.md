# Paired AI publication validation — 2026-09-09

Core [PR #67](https://github.com/tunnexio/tunnex/pull/67) and website
[PR #48](https://github.com/tunnexio/tunnex-web/pull/48) implement the user's request
to publish the existing AI/workload changes and documentation. The user subsequently
authorized merging when CI is green. Website PR #48 merged after both checks passed;
core still requires final-head CI and the configured GitHub code-owner approval.
Merge authorization is not a production qualification claim.

## Integration boundary

Core integrates main `219d422b55abc400f104f1486b91343ea231bd57` (NAT PR #66).
The new main migrations retain 0139–0141. The unpublished AI migrations moved
from 0139–0151 to 0142–0154 and workload migration 0153 to 0156. All 28 moved
SQL files retained their exact SHA-256 contents. No duplicate migration number
remains. Number 0155 is unused in this PR. All 338 operations from the union of
the AI and main OpenAPI sources remain present; generated outputs were rebuilt.

The original development preview remains on its existing schema153 and original
checkout. No publication migration was applied there, and the user's saved
credentials and workload were not changed. That development database requires
an explicit data-preserving conversion plan before moving to this new numbering.
The separate uncommitted MCP credentials/discovery implementation, unrelated
website design work and rejected standalone HTML preview are excluded.

## Executed local checks

| Check | Result |
| --- | --- |
| Main schema141 → integrated schema156 | PASS; both clean, isolated fixture only; [migration log](../walk-artifacts/ai-publication0909/migration.md) |
| Fresh database creation through integration suites | PASS; `testpostgres.New` applies all embedded migrations to fresh disposable databases |
| Both API edition builds | PASS |
| Full CLI suite after integration | PASS |
| Web typecheck, 1,504 tests / 124 files, production build | PASS |
| Native pinned OpenAPI Go/TS, SQLC, RBAC and design-token generation | PASS; second pass produces zero tracked drift |
| Full enterprise API suite after integration | Every package except AI passed; seven AI tests referenced renamed fixture filenames. All references corrected and the entire AI package passed on rerun |
| Open edition after integration | AI, HTTP, RBAC, connectivity, database connection, migrations and generated query suites PASS; full open suite also passed before main integration |
| Probe diagnostic/deadline tests under race detector, 20 repetitions | PASS after replacing shared test counters with atomics; timeout behavior unchanged |
| CI/gate contracts, including both classifiers with a 10,002-file diff | PASS: 44 tests; regressions failed before fixing early-exit pipe readers |
| Toolchain guard plus four mutation/refusal contracts | PASS; first-party Go1.25.13 and upstream-required Go1.27.0 checked separately |
| Website lint, 221 tests, full formatting, typecheck, build | PASS at `4dfb7f41484fb8f1fa41017dde0fe5126a604a49` |
| Website remote CI checks and preview | PASS at that same website head |
| Users browser regression on integrated API/UI | PASS: all seven tests, including both role endpoints' unverified refusal, multi-role save/audit, last-owner protection and invitation enumeration resistance; E2E TypeScript check also passes |

Native generation used oapi-codegen2.4.1, sqlc1.31.1 and openapi-typescript7.4.4;
this is recorded as native generation evidence, not as execution of the Docker
`make generate-check` target. Initial local runs encountered a duplicate React
installation, disposable tmpfs capacity exhaustion and one unchanged audit-order
timing failure; repaired dependencies/fresh disposable fixtures and reruns are
recorded without counting those failed attempts as passes. The audit test passed
five isolated repetitions and in the later integrated enterprise suite.

The DB wrapper prints and verifies `COMPOSE_PROJECT_NAME=tunnexworkload0909`,
container `tunnexworkload0909-postgres-1` and network
`tunnexworkload0909_default`; only that tmpfs fixture was recreated. No live CP
volume, VM, deployment or user's model access was changed.

## Remote and qualification limits

The first core CI run exposed a test-only call-counter race and an overbroad
toolchain equality check against the independent immutable Bifrost builder.
Both are corrected with local race/refusal coverage. A subsequent CI scope job
failed while printing the large changed-file list. CI/security classifiers now
drain pipeline input so broken pipes cannot fail classification or disable
required lanes; both actual classifier scripts pass the large-diff regression.
Remote CI must be assessed
again on the final pushed head; earlier passing or cancelled jobs do not qualify
that head.

Core CI at `9facf4fa` passed every required check but failed the optional browser
E2E job at the obsolete Users & Roles link. The existing Users tests now target
Users & Groups and the multiple-role editor, retaining the security assertions.
All seven tests pass against a newly seeded `merge_users_e2e0909` database on the
verified disposable project, separate Redis and API/UI ports. The first local
attempt found a new test assertion expecting 200 instead of the specified 204;
both save/cleanup assertions were corrected before the full passing rerun.
Sanitized evidence: [browser regression](../walk-artifacts/ai-publication0909/users-e2e.md).

Previously committed real Azure walkthrough evidence remains in
[S-AI-workload-azure-live-boxwalk.md](S-AI-workload-azure-live-boxwalk.md). It
predates this integration and does not prove a new combined NAT/AI live rollout.
The held W7 retirement-receipt behavior, unknown Azure monetary pricing, central
authenticated MCP execution, production autoscaling/multiple-API qualification,
and native Windows workload proof remain open as documented in the workload
review. These deferred qualification limits remain open after the authorized
merge; the browser correction is not story-end or production acceptance.
