# Tunnex Vault: local implementation evidence

Date: 2026-10-21. Scope: [local ledger decisions](S-tunnex-vault-decisions.md).

## Delivered source

- Added Tunnex Vault under the existing Access & Sharing navigation. The final UI imports the actual Beam workspace stylesheet and reuses its inventory/table classes, shared `AppAccessEmptyState`, row menus, pagination, and right-side drawers. Rows and details use text and existing monochrome tokens; colored avatars and decorative glyphs are removed. Vault-only CSS removes redundant table/section rules and action outlines. Only shared utility icons remain.
- Personal passwords/API keys remain application-private to their owner. Organization administrators create user/group assignments, and current recipients can read and rotate those entries and inspect their versions. Assignment deletion remains an administrator action.
- Added reusable service names, private personal service names, optional usernames, browser cryptographic password generation, audited saved-secret reveal/copy, and automatic concealment.
- Quick generate opens a content-height right-side drawer capped at 420px with a directly visible 24-character password, Copy and Close. It retains the shared Local Sharing controls and monochrome tokens; sizing is scoped to Quick generate. Generation alone stays local. Copy first commits an encrypted, creator-private Unconfigured entry, then releases its value to the clipboard. A stable request UUID makes retries idempotent; deleted entries leave tombstones, and save failure prevents copying.
- Owners can Configure an Unconfigured entry once with a title, service, optional username and personal/assigned scope. Assignment also requires vault administration. Configuration accepts no replacement password, uses an expected-version precondition, and atomically appends version 2 with the original password and configured username. Normal rotation requires configuration first.
- Updates append encrypted history with actor/time and an expected-version precondition. The encrypted payload is bound to its tenant, entry and version; historical username snapshots are preserved. History cannot be rewritten through an UPDATE.
- Added eleven OpenAPI operations, generated server/CLI/TypeScript contracts, generated RBAC mirror and SQL models, production dependency wiring, and migrations 230/231. Migration 231 preserves existing configured entries and refuses rollback while Unconfigured entries remain. No additional runtime dependency is required.
- Every operation checks current active/verified tenant membership. Reveal and history checks include current group membership. Browser identity, CSRF, request-size limits, strict single-object JSON and generic validation errors guard secret-bearing requests. Broad existing CLI credentials, machines and agents are refused.

## Verified checks

| Check | Result |
|---|---|
| Final focused Vault backend and real-router security suites, open and enterprise | Pass in pinned Linux against isolated PostgreSQL 17: eight top-level tests and 24 subtests per edition; none skipped |
| Earlier Vault backend/router race checks | Pass, including the combined race suite |
| Migration 229 to 230, rollback to 229, reapply to 230 | Pass in a disposable database; unrelated tenant data preserved |
| Migration 230 to 231 and rollback guard | Pass for both editions: existing ciphertext preserved; rollback refuses a live Unconfigured entry; explicit fixture cleanup permits rollback/reapply |
| Final CLI module test suite | Pass after the new contract and enum compatibility update |
| Final Vault UI, generator and clipboard tests | 38 passed in pinned native Node 24.21.0 / pnpm 10.34.5, including persist-before-copy, failure/boundary handling and Configure |
| Final web typecheck | Pass in the same pinned native runtime after persist-before-copy and Configure |
| Independent Beam/Vault/glyph/census checks | 15 files, 177 tests passed in the same pinned native runtime before the final icon/rule removal and Quick generate follow-up |
| Final web production build | Pass in pinned native Node 24.21.0 / pnpm 10.34.5 after persist-before-copy and Configure |
| Pinned Linux API build of all packages, both editions | Pass, including retained Linux-only source |
| Final generated artifact drift gate | Pass with the repository-pinned generators and Linux Go toolchain after the latest contract changes |
| Broad API suites | Incomplete: open edition passed through hostupgrade; later HTTP and enterprise coverage did not complete |
| Full web suite | Docker serial run: 2875 passed, 27 failed, two expected failures. Vault glyph/census and missing-jq cases subsequently passed targeted checks. AI-provider failures remain unresolved; not proven to reproduce on the current-main baseline. Native full run was stopped for the requested UI redesign |
| Node-agent gate | Build passed; IPsec test-package compilation was killed and the bounded retry was stopped. Complete gate remains inconclusive |
| Earlier real HTTP/session smoke | 43 assertions passed with 12 secret-free audit events |
| Final quick-entry HTTP proof | 129 assertions passed with 17 secret-free Vault audit events, including concurrent first saves, replay, privacy, Configure and delete tombstones |
| Isolated demo upgrade to 231 | Pass: original entry/version counts and key files preserved; only the verified task API restarted; Redis untouched |

The host Go installation is 1.27.1. The repository pins Linux Go 1.26.9; the final contract is regenerated with that exact toolchain, including its embedded-spec compression. A native build of all API commands cannot substitute for the Linux build because one retained sandbox command has only a Linux entry point.

Earlier concurrent runs and Docker typecheck/build attempts were memory-killed. The completed native typecheck/build and focused checks above supersede those individual attempts; the unfinished broad suites remain inconclusive. These results do not establish that all repository gates pass, and AI-provider timing/assertion failures are not classified as preexisting defects.

The border cleanup, quick-entry lifecycle and compact visible-password follow-up were independently reviewed. The 38 focused UI tests, typecheck and production build passed again after the compact drawer change. The earlier independent 177-test run and broad suites were not repeated for these follow-ups.

Independent final UI/API-call review found one late-response state issue when paging history. Both paging controls now invalidate pending reveal requests through the existing concealment function. A regression test exercises both directions; the reviewer rechecked the correction with no outstanding findings in that reviewed scope.

## Visual verification

The final UI follows the user's Local Sharing structure and monochrome correction: actual `beam-inventory-table`, `beam-app-identity`, `beam-row-actions` and related Beam classes; shared empty/no-results states with `icon={null}`; and every Vault modal uses `placement="right"`. Credential, service, access, version and menu labels are text, without colored avatars or decorative glyphs. Vault-only overrides remove table rules, empty/disclosure borders, action outlines and secret/history section dividers; shared navigation, inputs, focus outlines and drawer structure remain. Independent review confirmed that these presentation-only corrections leave API calls, permissions, expected-version checks and secret concealment unchanged.

The real app was checked against an isolated local API, PostgreSQL and Redis workspace. Final browser evidence covers Unconfigured inventory, the Configure drawer, and an existing assigned entry's masked version-2 history preserved across migration. The latest Quick drawer was verified at 420px wide and content height, with its entire new value visible, then closed without saving. Shared Add/no-results states were also checked; the zero-entry state is covered by component tests. No browser Copy, metadata Save, Reveal, delete or assignment mutation occurred. Save/configure/rotate/version pairing is proved by actual HTTP: the initial 43 assertions and final 129-assertion extension. Earlier component-harness, colored-avatar, metadata-first and full-height masked Quick screenshots are historical evidence. [Wire evidence and final screenshots](S-tunnex-vault-box-walk.md) record these boundaries.

## Remaining boundaries

- Source is local to the feature branch. No push, PR, merge, production deployment, existing local-stack migration or reset was performed.
- Public SDK/CLI automation, scoped application credentials and OpenBao integration are deferred as recorded in the decision paper. API-key values are supplied by the issuer; the UI generates passwords only.
- Service/subject directories currently return the whole authorized directory; add directory pagination before large-organization rollout. Entry and version lists are paginated.
- A copied password remains usable outside Tunnex until it is changed at the external service. Personal privacy is enforced by application authorization; this MVP does not claim end-to-end encryption against the installation operator.
