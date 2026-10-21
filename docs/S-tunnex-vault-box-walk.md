# Tunnex Vault: isolated local wire proof

Date: 2026-10-21. Local development scope; no publication or existing-stack changes.

## Environment

Built the real server, migration and seed commands using the available native Go toolchain. Ran the server against a separate database in the task-owned PostgreSQL 17 container and a task-owned Redis instance. All API, agent, metrics and UI listeners were isolated. Source-defined demo accounts and synthetic secrets were used exclusively. This supplementary native proof does not replace the pinned Linux edition gates.

The complete existing React app runs through its normal Vite proxy and the real API. The browser signed in as the seeded demo owner and opened Vault in the existing app shell. API and browser use the same configured UI origin and normal CSRF handling.

## Results

The [initial HTTP record](../walk-artifacts/tunnex-vault-20261021/live-http-result.json) records **43 passed assertions** and **12 Vault audit events**, without secret values or login credentials. It covers the original ledger flow:

- Real verified owner/member browser-session cookies; anonymous requests and mutations without CSRF refused.
- Member personal entry excluded from the administrator's inventory; administrator reveal, history and mutation denied.
- Shared service created by the administrator and reused for an assigned credential; administrator and current recipient both authorized.
- Recipient rotation appends a version; historical secret and username remain paired, while current values reflect the new version.
- Stale updates return conflict without appending a version; recipients cannot delete administrator assignments.
- Listing/history/error/audit metadata and API logs exclude synthetic plaintext; the initial proof checked four encrypted version records.

The [final quick-entry HTTP record](../walk-artifacts/tunnex-vault-20261021/quick-http-result.json) adds **129 passed assertions** and **17 Vault audit events** for its synthetic entries:

- Six simultaneous first saves and six exact replays produce one entry/version/create audit; changed payloads conflict. Replays still compare the original password after configuration and rotation.
- Creator-private Unconfigured entries stay hidden from administrators and other users. An existing nonmember organization path returns 404 without exposing the entry.
- Configure requires creator ownership, expected-version and assignment authority. Its request cannot supply a password; configuration preserves version 1 and appends version 2 with the original password and new username. Repeated configuration and premature rotation are refused.
- Deleting configured or Unconfigured quick entries leaves retry tombstones. Metadata, errors, audit records, encrypted storage and API logs exclude synthetic plaintext.
- One owner-private Unconfigured entry was retained for the browser review. The controlled demo upgrade preserved existing data, both key files and Redis while migrating only the task database to 231 and restarting only its verified API.

The browser walk checked the Local Sharing structure and monochrome treatment without revealing a secret or changing server data:

- [Unconfigured inventory](../walk-artifacts/tunnex-vault-20261021/unconfigured-inventory.png)
- [Compact visible-password drawer](../walk-artifacts/tunnex-vault-20261021/compact-quick-drawer.png)
- [Configure credential drawer](../walk-artifacts/tunnex-vault-20261021/configure-credential-drawer.png)
- [Preserved assigned-entry masked history](../walk-artifacts/tunnex-vault-20261021/preserved-history-drawer.png)
- [Shared Add credential drawer reference](../walk-artifacts/tunnex-vault-20261021/local-sharing-add-drawer.png)
- [Monochrome no-results empty state](../walk-artifacts/tunnex-vault-20261021/monochrome-empty-state.png)

The history screenshot shows an existing assigned entry's version-2 history retained after migration; it is not a browser proof of the new Configure mutation. Quick configuration and username/version pairing are covered by the final HTTP record.

The source imports the actual Beam workspace stylesheet and table classes, shared `AppAccessEmptyState`, row menus and pagination. All Vault dialogs use the shared right-drawer placement. Colored avatars and decorative glyphs are removed; empty states omit their optional icon. Vault-only CSS removes table/section rules and redundant action outlines while preserving shared navigation, inputs, focus outlines and drawer structure. Existing monochrome tokens and shared utility icons remain. Earlier live, recovery, colored-avatar and metadata-first Quick screenshots are historical only. The Add drawer reference remains representative of the unchanged form.

Quick generate now opens a content-height right drawer capped at 420px, directly showing the fresh password with Copy and Close underneath. The browser verified the full value fits. The screenshot contains only a new unsaved candidate that was discarded; it is not a stored or external-service credential. Earlier full-height masked Quick screenshots are historical. Generation alone is local; Copy commits an encrypted creator-private Unconfigured entry before releasing the password to the clipboard. Stable request UUIDs prevent duplicate retry rows, including after clipboard refusal; tombstones prevent deleted entries from returning. Configure later accepts metadata only, checks ownership/version/assignment authority, and appends a new username snapshot while preserving the original password and version 1. Saved-entry reveal/copy retains its authorized, audited API flow.

The browser verified the compact visible-password drawer, then closed its unsaved candidate. Generation stayed local. No browser Copy, metadata Save, Reveal, delete or assignment mutation occurred.

## Review-runner failure and recovery

During user review the temporary Docker UI process disappeared, leaving the rendered page unable to fetch Vault data. The API, Redis and separate smoke database remained healthy. The cause of that process exit was not established; other memory-killed validation runs are recorded separately.

Stopped the task-owned broad test lanes and replaced the UI runner with native Vite using the official checksum-verified Node 24.21.0 runtime and locked pnpm 10.34.5 dependencies. Reopened the real browser page and verified that data and service controls loaded. The [recovered native inventory](../walk-artifacts/tunnex-vault-20261021/restored-native-inventory.png) records that recovery before the subsequent user-requested Local Sharing layout correction.

Final pinned native typecheck, production build and all 38 Vault/generator/clipboard tests passed again after the compact visible-password follow-up. The independent 177-test/15-file Beam/Vault/glyph/census run predates these follow-ups. Final pinned Linux builds and focused Vault/router suites passed for both API editions (eight top-level tests and 24 subtests each; none skipped), as did the whole CLI module and generated-artifact drift. The broader API, web and Node-agent gates remain incomplete or inconclusive as detailed in the [development evidence](S-tunnex-vault-development.md).

## Boundaries

The browser leg covers navigation, Unconfigured inventory, Configure and preserved-history drawers, the shared Add/no-results states and local unsaved Quick generation. The zero-entry state is covered by component tests. Creation, configuration, rotation and permissions were exercised over actual HTTP; clipboard ordering/failures and browser mutation wiring are covered by component tests. This record does not claim a live browser clipboard, complete browser mutation or production acceptance walk. Desktop/narrow checks from the earlier isolated component harness predate the final layout correction.

The disposable review workspace is available at `http://127.0.0.1:5178/vault` while its task-owned services remain running. It uses sample data and is independent of the existing local stacks. The public SDK, CLI automation and external-service provisioning remain deferred.
