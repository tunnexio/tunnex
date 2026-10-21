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

The final browser walk verified the corrected Local Sharing UI read-only, without revealing or saving a secret:

- [Beam-style inventory and row menus](../walk-artifacts/tunnex-vault-20261021/local-sharing-inventory.png)
- [Right-side Add credential drawer](../walk-artifacts/tunnex-vault-20261021/local-sharing-add-drawer.png)
- [Right-side masked history drawer](../walk-artifacts/tunnex-vault-20261021/local-sharing-history-drawer.png)
- [Shared no-results empty state](../walk-artifacts/tunnex-vault-20261021/local-sharing-empty-state.png)

The source imports the actual Beam workspace stylesheet and table classes, shared `AppAccessEmptyState`, row menus and pagination. All Vault dialogs use the shared right-drawer placement. Password, API-key, service, access and history icons use the existing palette, including inside portaled drawer content. Earlier [inventory](../walk-artifacts/tunnex-vault-20261021/live-inventory.png), [history](../walk-artifacts/tunnex-vault-20261021/live-masked-history.png) and recovery screenshots predate this correction and are historical only.

## Review-runner failure and recovery

During user review the temporary Docker UI process disappeared, leaving the rendered page unable to fetch Vault data. The API, Redis and separate smoke database remained healthy. The cause of that process exit was not established; other memory-killed validation runs are recorded separately.

Stopped the task-owned broad test lanes and replaced the UI runner with native Vite using the official checksum-verified Node 24.21.0 runtime and locked pnpm 10.34.5 dependencies. Reopened the real browser page and verified that data and service controls loaded. The [recovered native inventory](../walk-artifacts/tunnex-vault-20261021/restored-native-inventory.png) records that recovery before the subsequent user-requested Local Sharing layout correction.

Final pinned native typecheck and production build passed. The corrected Vault/generator suite passed 21 tests; an independent Beam/Vault/glyph/census run passed 177 tests across 15 files. Pinned Linux builds and focused Vault/router suites passed for both API editions, the CLI module passed, and generated-artifact drift passed after the latest-main rebase. The broader API, web and Node-agent gates remain incomplete or inconclusive as detailed in the [development evidence](S-tunnex-vault-development.md).

## Boundaries

The final browser leg covers navigation, populated inventory, Add/history drawers and the no-results state; it performs no reveal or save. The zero-entry state uses the same shared component and is covered by component tests. Creation, rotation and permission checks were exercised over actual HTTP; their browser mutation wiring is covered by component tests. This record does not claim a complete browser mutation or production acceptance walk. Desktop/narrow checks from the earlier isolated component harness predate the final layout correction.

The disposable review workspace is available at `http://127.0.0.1:5178/vault` while its task-owned services remain running. It uses sample data and is independent of the existing local stacks. The public SDK, CLI automation and external-service provisioning remain deferred.
