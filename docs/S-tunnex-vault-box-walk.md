# Tunnex Vault: isolated local wire proof

Date: 2026-10-21. Local development scope; no publication or existing-stack changes.

## Environment

Built the real server, migration and seed commands using the available native Go toolchain. Ran the server against a separate database in the task-owned PostgreSQL 17 container and a task-owned Redis instance. All API, agent, metrics and UI listeners were isolated. Source-defined demo accounts and synthetic secrets were used exclusively. This supplementary native proof does not replace the pinned Linux edition gates.

The complete existing React app runs through its normal Vite proxy and the real API. The browser signed in as the seeded demo owner, opened Vault in the existing app shell and loaded its masked version-history dialog. API and browser use the same configured UI origin and normal CSRF handling.

## Results

The [sanitized HTTP record](../walk-artifacts/tunnex-vault-20261021/live-http-result.json) records **43 passed checks** and **12 Vault audit events**, without secret values or login credentials.

- Real verified owner/member browser-session cookies; anonymous requests and mutations without CSRF refused.
- Member personal entry excluded from the administrator's inventory; administrator reveal, history and mutation denied.
- Shared service created by the administrator and reused for an assigned credential; administrator and current recipient both authorized.
- Recipient rotation appends a version; historical secret and username remain paired, while current values reflect the new version.
- Stale updates return conflict without appending a version; recipients cannot delete administrator assignments.
- Listing/history/error/audit metadata and API logs exclude synthetic plaintext. Four encrypted version records remain in the fixture database.

Browser evidence:

- [Real app inventory](../walk-artifacts/tunnex-vault-20261021/live-inventory.png)
- [Real masked version history](../walk-artifacts/tunnex-vault-20261021/live-masked-history.png)

## Boundaries

The live browser leg covers login, navigation, the populated inventory and masked history. Creation, rotation and permission checks were exercised over actual HTTP; their browser mutation wiring is covered by component tests. This record does not claim a complete browser mutation or production acceptance walk. Desktop/narrow visual checks were also performed in the earlier isolated component harness.

The disposable review workspace is available at `http://127.0.0.1:5178/vault` while its task-owned services remain running. It uses sample data and is independent of the existing local stacks. The public SDK, CLI automation and external-service provisioning remain deferred.
