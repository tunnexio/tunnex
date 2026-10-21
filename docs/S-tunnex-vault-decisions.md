# Tunnex Vault: local ledger MVP

Status: implementation authorized by the user on 2026-10-21. Local development only.

## Locked decisions

- Deliver a browser-based encrypted credential ledger integrated with current Tunnex organizations, users and groups. Passwords and API keys are supported; username is optional. This ledger does not provision accounts or change secrets in external services.
- Reuse the existing installation AES-256-GCM sealer and PostgreSQL for this minimal release. Bind encrypted payloads to organization, entry ID and version and verify that binding on reveal. OpenBao is a researched candidate for a later storage integration, not a prerequisite or an approved deployment. It would add an independently operated service, recovery and backup requirements.
- Personal entries and their versions are visible/editable only to their owner through the application, including when the caller is an organization administrator. This is application authorization, not a claim of end-to-end encryption against the installation operator.
- Assigned entries and all their versions are readable/editable by organization vault administrators and their current assigned user/group members. Active tenant membership is required on every operation. Removing membership or assignment prevents future reads; passwords already copied require rotation at the external service.
- Use separate `vault:use` and `vault:assign` permissions. Default owner/admin/member roles receive use; only owner/admin receive assignment administration. Machine and agent principals have no Vault access. This MVP requires verified browser identity; bearer-based automation waits for dedicated scoped credentials.
- Service names form an organization-scoped reusable catalog. All Vault users can choose services; only vault administrators add shared catalog services. A personal entry can have a private service name without publishing it into the shared catalog.
- Each entry has a title, password/API-key kind, service reference or private service name, optional username, personal/assigned visibility, and an immutable assignment for the MVP. Only vault administrators create assigned entries. Assignment changes are deferred; administrators can delete and recreate an assigned entry after explicit confirmation.
- Updating a secret appends a version with actor and time. Expected-version checks prevent concurrent updates from overwriting one another. History lists contain metadata only. Revealing any version is explicit, authorized and audited, and never cached. Retain all versions in this MVP; deletion is explicit and requires owner authority for personal entries or vault administration for assigned entries. Recipients can rotate assigned secrets but cannot delete assignments.
- Secrets never appear in entry listings, history metadata, errors, audit metadata or browser persistent storage. Browser views clear revealed values when closed, when the organization changes, and after a short reveal timeout. Generation uses browser cryptographic randomness with rejection sampling and includes lowercase, uppercase, digits and symbols.
- Local implementation includes generated OpenAPI contracts, migration, backend service and authorization tests, web navigation and usable entry/service/history flows. No new runtime dependency is required.
- Preserve the existing Tunnex UI design and structure as explicitly requested: reuse the current shell, page header, inventory/table controls, forms, dialogs, typography and semantic tokens. Add only a Vault destination; do not redesign shared surfaces. Search and pagination are URL-backed.

## Deferred work

- Public SDK/package publication and CLI commands; application/workload identities with explicitly scoped, expiring and separately revocable Vault credentials must precede unattended access.
- OpenBao integration and migration tooling; CSV/Excel import/export; automatic rotation/provisioning; autofill; attachment storage; end-to-end encryption; reassignment workflow; permanent version pruning and configurable retention.
- Deployment, production migration, remote publication and merge require separate user instruction. No existing local stack is reset or seeded.

## Verification

Prove private-entry isolation from administrators and other users, tenant isolation, active-membership checks, live group membership, machine/bearer refusal, immutable version history, conflict detection, bound ciphertext, audited reveal and secret-free metadata. Verify browser generation, masked entry/history flows and assignment controls. Run generation/drift checks, both Go editions, relevant DB tests and web checks; record unavailable full/live gates explicitly rather than treating substitutes as live proof.
