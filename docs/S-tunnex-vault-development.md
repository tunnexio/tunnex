# Tunnex Vault: local implementation evidence

Date: 2026-10-21. Scope: [local ledger decisions](S-tunnex-vault-decisions.md).

## Delivered source

- Added Tunnex Vault under the existing Access & Sharing navigation. The existing shell, page header, shared form/dialog components, design tokens, table and pagination patterns are reused.
- Personal passwords/API keys remain application-private to their owner. Organization administrators create user/group assignments, and current recipients can read and rotate those entries and inspect their versions. Assignment deletion remains an administrator action.
- Added reusable service names, private personal service names, optional usernames, browser cryptographic password generation, explicit audited reveal/copy, and automatic concealment.
- Updates append encrypted history with actor/time and an expected-version precondition. The encrypted payload is bound to its tenant, entry and version; historical username snapshots are preserved. History cannot be rewritten through an UPDATE.
- Added nine OpenAPI operations, generated server/CLI/TypeScript contracts, generated RBAC mirror and SQL models, production dependency wiring, and migration 230. No additional runtime dependency is required.
- Every operation checks current active/verified tenant membership. Reveal and history checks include current group membership. Browser identity, CSRF, request-size limits, strict single-object JSON and generic validation errors guard secret-bearing requests. Broad existing CLI credentials, machines and agents are refused.

## Verified checks

| Check | Result |
|---|---|
| Backend PostgreSQL integration, open and enterprise | Pass, including race detection; no skipped Vault database proofs |
| Real-router security tests, open and enterprise | Pass against isolated PostgreSQL 17 |
| Combined Vault backend/router race suite | Pass |
| Migration 229 to 230, rollback to 229, reapply to 230 | Pass in a disposable database; unrelated tenant data preserved |
| CLI module test suite | Pass |
| Focused Vault UI and password generator tests | 19 passed in the available host test runner, including late reveal/history paging regression; pinned runtime verification below |
| Web typecheck in pinned Node 24.21.0 / pnpm 10.34.5 | Earlier run passed; post-rebase serial run was memory-killed, standalone verification pending |
| Pinned Linux API build of all packages | Pass, including retained Linux-only source |
| Full generated artifact drift gate | Pass with the repository-pinned generators and Linux Go toolchain, rechecked after the latest-main rebase |
| Full active API suites, both editions | Bounded run in progress; fresh public-schema fixture setup is being corrected for affected existing tests |
| Full web suite and production build | Serial run: 2875 passed, 27 failed, two expected failures; Vault placeholder/census failures corrected and targeted rechecks pending; production build memory-killed |
| Node-agent gate | Build succeeded; one existing IPsec test-package compilation was killed, so the complete gate is inconclusive |
| Isolated real HTTP/session smoke and browser read walk | 43 checks passed; real app login, inventory and masked history verified; see the committed wire proof |

The host Go installation is 1.27.1. The repository pins Linux Go 1.26.9; the final contract is regenerated with that exact toolchain, including its embedded-spec compression. A native build of all API commands cannot substitute for the Linux build because one retained sandbox command has only a Linux entry point.

An initial concurrent broad web run was killed with SIGKILL, and a concurrent Linux API test compilation was OOM-killed (container memory event verified). These interrupted runs are inconclusive. The reruns use serial package/file execution and bounded memory; unrelated test timing failures from the interrupted run are not claimed as baseline defects.

Independent final UI/API-call review found one late-response state issue when paging history. Both paging controls now invalidate pending reveal requests through the existing concealment function. A regression test exercises both directions; the reviewer rechecked the correction with no outstanding findings in that reviewed scope.

## Visual verification

Inspected the actual Vault component and real global CSS/tokens/shared components in an isolated Vite harness with synthetic metadata. Desktop inventory, scrolling creation dialog, masked secret/version-history dialog, and a 390-pixel iframe viewport were checked in the browser. The harness mocks only API/auth/organization dependencies; it is visual evidence, not a production-login or full-stack acceptance claim. The shared shell source changes only by adding its navigation destination.

Then verified the real application through an isolated local API, PostgreSQL and Redis workspace. Real browser login, populated Vault inventory and masked history rendered inside the existing app shell. Actual HTTP mutations and permission checks passed 43 assertions with 12 secret-free audit events. [Committed wire evidence](S-tunnex-vault-box-walk.md) distinguishes this proof from the earlier visual harness and from full production acceptance.

## Remaining boundaries

- Source is local to the feature branch. No push, PR, merge, production deployment, existing local-stack migration or reset was performed.
- Public SDK/CLI automation, scoped application credentials and OpenBao integration are deferred as recorded in the decision paper. API-key values are supplied by the issuer; the UI generates passwords only.
- Service/subject directories currently return the whole authorized directory; add directory pagination before large-organization rollout. Entry and version lists are paginated.
- A copied password remains usable outside Tunnex until it is changed at the external service. Personal privacy is enforced by application authorization; this MVP does not claim end-to-end encryption against the installation operator.
