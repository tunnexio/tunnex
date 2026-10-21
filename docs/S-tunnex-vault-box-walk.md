# Tunnex Vault: isolated local wire proof

Date: 2026-10-21. Local development scope; no publication or existing-stack changes.

## Environment

Built the real server, migration and seed commands using the available native Go toolchain. Ran the server against a separate database in the task-owned PostgreSQL 17 container and a task-owned Redis instance. All API, agent, metrics and UI listeners were isolated. Source-defined demo accounts and synthetic secrets were used exclusively. This supplementary native proof does not replace the pinned Linux edition gates.

The complete existing React app runs through its normal Vite proxy and the real API. The browser signed in as the seeded demo owner and opened Vault in the existing app shell. API and browser use the same configured UI origin and normal CSRF handling.

## Results

The [sanitized HTTP record](../walk-artifacts/tunnex-vault-20261021/live-http-result.json) records **43 passed checks** and **12 Vault audit events**, without secret values or login credentials.

- Real verified owner/member browser-session cookies; anonymous requests and mutations without CSRF refused.
- Member personal entry excluded from the administrator's inventory; administrator reveal, history and mutation denied.
- Shared service created by the administrator and reused for an assigned credential; administrator and current recipient both authorized.
- Recipient rotation appends a version; historical secret and username remain paired, while current values reflect the new version.
- Stale updates return conflict without appending a version; recipients cannot delete administrator assignments.
- Listing/history/error/audit metadata and API logs exclude synthetic plaintext. Four encrypted version records remain in the fixture database.

The final browser walk verified the Local Sharing structure with the user's monochrome correction, without revealing a secret or changing server data:

- [Monochrome inventory](../walk-artifacts/tunnex-vault-20261021/monochrome-inventory.png)
- [Right-side Add credential drawer](../walk-artifacts/tunnex-vault-20261021/local-sharing-add-drawer.png)
- [Monochrome masked history drawer](../walk-artifacts/tunnex-vault-20261021/monochrome-history-drawer.png)
- [Monochrome no-results empty state](../walk-artifacts/tunnex-vault-20261021/monochrome-empty-state.png)
- [Masked Quick generate drawer](../walk-artifacts/tunnex-vault-20261021/quick-generate-drawer.png)

The source imports the actual Beam workspace stylesheet and table classes, shared `AppAccessEmptyState`, row menus and pagination. All Vault dialogs use the shared right-drawer placement. Colored avatars and decorative glyphs are removed; empty states omit their optional icon. Vault-only CSS removes table/section rules and redundant action outlines while preserving shared navigation, inputs, focus outlines and drawer structure. Existing monochrome tokens and shared utility icons remain. Earlier live, recovery and colored-avatar Local Sharing screenshots are historical only. The Add drawer screenshot remains current because that form is unchanged by these corrections.

Quick generate adds a password-first entry point in the same drawer: the new 24-character password is masked, Copy is explicit and browser-only, and the user supplies service, visibility/assignment and optional username before Save. It does not create an entry or reveal an existing secret automatically. Saved-entry copy retains its authorized, audited API flow.

The browser opened Quick generate once, verified the masked field and controls, then cancelled the unsaved draft. Copy, Show secret and Save were not used. Generation stayed local to the browser.

## Review-runner failure and recovery

During user review the temporary Docker UI process disappeared, leaving the rendered page unable to fetch Vault data. The API, Redis and separate smoke database remained healthy. The cause of that process exit was not established; other memory-killed validation runs are recorded separately.

Stopped the task-owned broad test lanes and replaced the UI runner with native Vite using the official checksum-verified Node 24.21.0 runtime and locked pnpm 10.34.5 dependencies. Reopened the real browser page and verified that data and service controls loaded. The [recovered native inventory](../walk-artifacts/tunnex-vault-20261021/restored-native-inventory.png) records that recovery before the subsequent user-requested Local Sharing layout correction.

Final pinned native typecheck and all 24 Vault/generator tests passed after Quick generate and final spacing. The successful production build and independent 177-test/15-file Beam/Vault/glyph/census run precede the monochrome/rule cleanup and Quick generate follow-ups. Pinned Linux builds and focused Vault/router suites passed for both API editions, the CLI module passed, and generated-artifact drift passed after the latest-main rebase. The broader API, web and Node-agent gates remain incomplete or inconclusive as detailed in the [development evidence](S-tunnex-vault-development.md).

## Boundaries

The final browser leg covers navigation, populated inventory, Add/history drawers, the no-results state and local unsaved Quick generation; it performs no reveal, copy or save. The zero-entry state uses the same shared component and is covered by component tests. Creation, rotation and permission checks were exercised over actual HTTP; their browser mutation wiring is covered by component tests. This record does not claim a complete browser mutation or production acceptance walk. Desktop/narrow checks from the earlier isolated component harness predate the final layout correction.

The disposable review workspace is available at `http://127.0.0.1:5178/vault` while its task-owned services remain running. It uses sample data and is independent of the existing local stacks. The public SDK, CLI automation and external-service provisioning remain deferred.
