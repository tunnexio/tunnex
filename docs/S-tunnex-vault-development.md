# Tunnex Vault: local implementation evidence

Date: 2026-10-21. Scope: [local ledger decisions](S-tunnex-vault-decisions.md).

## Delivered source

- Added Tunnex Vault under the existing Access & Sharing navigation. The final UI imports the actual Beam workspace stylesheet and reuses its inventory/table classes, shared `AppAccessEmptyState`, row menus, pagination, and right-side drawers. Rows and details use text and existing monochrome tokens; colored avatars and decorative glyphs are removed. Vault-only CSS removes redundant table/section rules and action outlines. Only shared utility icons remain.
- Personal passwords/API keys remain application-private to their owner. Organization administrators create user/group assignments, and current recipients can read and rotate those entries and inspect their versions. Assignment deletion remains an administrator action.
- Added reusable service names, private personal service names, optional usernames, browser cryptographic password generation, audited saved-secret reveal/copy, and automatic concealment.
- Quick generate opens the same right-side drawer with a masked 24-character password first. Users can explicitly copy the unsaved draft, generate again, then supply service, ownership/assignment and optional username before saving. Draft generation/copy stays in the browser; saving uses the existing authorized create flow.
- Updates append encrypted history with actor/time and an expected-version precondition. The encrypted payload is bound to its tenant, entry and version; historical username snapshots are preserved. History cannot be rewritten through an UPDATE.
- Added nine OpenAPI operations, generated server/CLI/TypeScript contracts, generated RBAC mirror and SQL models, production dependency wiring, and migration 230. No additional runtime dependency is required.
- Every operation checks current active/verified tenant membership. Reveal and history checks include current group membership. Browser identity, CSRF, request-size limits, strict single-object JSON and generic validation errors guard secret-bearing requests. Broad existing CLI credentials, machines and agents are refused.

## Verified checks

| Check | Result |
|---|---|
| Final focused Vault backend and real-router security suites, open and enterprise | Pass in pinned Linux against isolated PostgreSQL 17: five top-level tests and 22 subtests per edition; none skipped |
| Earlier Vault backend/router race checks | Pass, including the combined race suite |
| Migration 229 to 230, rollback to 229, reapply to 230 | Pass in a disposable database; unrelated tenant data preserved |
| CLI module test suite | Pass |
| Final Vault UI and password generator tests | 24 passed in pinned native Node 24.21.0 / pnpm 10.34.5, including Quick generate and final spacing |
| Final web typecheck | Pass in the same pinned native runtime after the Quick generate follow-up |
| Independent Beam/Vault/glyph/census checks | 15 files, 177 tests passed in the same pinned native runtime before the final icon/rule removal and Quick generate follow-up |
| Web production build | Pass in pinned native Node 24.21.0 / pnpm 10.34.5 before the final icon/rule removal and Quick generate follow-up |
| Pinned Linux API build of all packages, both editions | Pass, including retained Linux-only source |
| Full generated artifact drift gate | Pass with the repository-pinned generators and Linux Go toolchain, rechecked after the latest-main rebase |
| Broad API suites | Incomplete: open edition passed through hostupgrade; later HTTP and enterprise coverage did not complete |
| Full web suite | Docker serial run: 2875 passed, 27 failed, two expected failures. Vault glyph/census and missing-jq cases subsequently passed targeted checks. AI-provider failures remain unresolved; not proven to reproduce on the current-main baseline. Native full run was stopped for the requested UI redesign |
| Node-agent gate | Build passed; IPsec test-package compilation was killed and the bounded retry was stopped. Complete gate remains inconclusive |
| Isolated real HTTP/session smoke and browser read walk | 43 checks passed; final inventory, Add/history drawers and no-results state verified read-only; see the wire proof |

The host Go installation is 1.27.1. The repository pins Linux Go 1.26.9; the final contract is regenerated with that exact toolchain, including its embedded-spec compression. A native build of all API commands cannot substitute for the Linux build because one retained sandbox command has only a Linux entry point.

Earlier concurrent runs and Docker typecheck/build attempts were memory-killed. The completed native typecheck/build and focused checks above supersede those individual attempts; the unfinished broad suites remain inconclusive. These results do not establish that all repository gates pass, and AI-provider timing/assertion failures are not classified as preexisting defects.

The border cleanup and Quick generate follow-up were independently reviewed and verified in the browser. The final focused tests and typecheck above cover the current source; the broader test run and production build were not repeated for these follow-ups.

Independent final UI/API-call review found one late-response state issue when paging history. Both paging controls now invalidate pending reveal requests through the existing concealment function. A regression test exercises both directions; the reviewer rechecked the correction with no outstanding findings in that reviewed scope.

## Visual verification

The final UI follows the user's Local Sharing structure and monochrome correction: actual `beam-inventory-table`, `beam-app-identity`, `beam-row-actions` and related Beam classes; shared empty/no-results states with `icon={null}`; and every Vault modal uses `placement="right"`. Credential, service, access, version and menu labels are text, without colored avatars or decorative glyphs. Vault-only overrides remove table rules, empty/disclosure borders, action outlines and secret/history section dividers; shared navigation, inputs, focus outlines and drawer structure remain. Independent review confirmed that these presentation-only corrections leave API calls, permissions, expected-version checks and secret concealment unchanged.

The real app was checked against an isolated local API, PostgreSQL and Redis workspace. Final browser evidence covers the monochrome inventory, right-side Add and masked-history drawers, shared no-results state, and masked Quick generate drawer. The zero-entry state uses the same component and is covered by component tests. Opening Quick generate created only a local unsaved draft, which was cancelled; Copy, Show secret and Save were not used. No browser step changed server data. Actual HTTP mutations and permissions passed 43 assertions with 12 secret-free audit events. Earlier component-harness and colored-avatar screenshots are historical evidence, not proof of the final presentation. [Wire evidence and final screenshots](S-tunnex-vault-box-walk.md) record the distinction.

## Remaining boundaries

- Source is local to the feature branch. No push, PR, merge, production deployment, existing local-stack migration or reset was performed.
- Public SDK/CLI automation, scoped application credentials and OpenBao integration are deferred as recorded in the decision paper. API-key values are supplied by the issuer; the UI generates passwords only.
- Service/subject directories currently return the whole authorized directory; add directory pagination before large-organization rollout. Entry and version lists are paginated.
- A copied password remains usable outside Tunnex until it is changed at the external service. Personal privacy is enforced by application authorization; this MVP does not claim end-to-end encryption against the installation operator.
