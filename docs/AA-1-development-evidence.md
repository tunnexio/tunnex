# AA-1 registry and draft inventory

Status: locally accepted on 2026-10-03; no publication or browser-content access is implemented by
this story. AA-0 acceptance is recorded in [AA-0 evidence](AA-0-development-evidence.md).

## Baseline and boundaries

The user-requested `git pull --ff-only origin main` returned **Already up to date**
on 2026-10-03. Feature HEAD remains planning commit `5c1093e87db358cab06080cc272321a2e074802f`;
refreshed main and merge-base are both `bcf602770c54446b35a2f83bfa639e9f2a9a10c8`.
All implementation changes remain local and uncommitted. Unrelated AI directories
and the five pre-existing stashes remain outside ownership.

Three disjoint lanes own registry/migration/query service; OpenAPI/generated
contracts/RBAC/licensing/HTTP wiring; and web inventory/draft routes. Central
integration reviews their combined behavior and tests against the owned running
CP/gateway stack. Migration 167 is allocated after refreshed main's 166.

## Implementation contract

Add an independent named runtime feature and default-off organization opt-in.
Draft mutations require current entitlement, opt-in and a valid operator-controlled
app domain on a separate registrable domain from the console. Saved configuration
inspection and disabling remain available after entitlement loss under named
permissions. Existing user/group licensing is unchanged.

Registry and revision relationships are tenant scoped. Host claims are unique
installation wide and remain reserved across draft hostname changes. Immutable
revision history and optimistic expected versions prevent stale overwrite; audited
mutations must roll back if the audit transaction fails. Draft creation does not
prove connector eligibility, DNS, TLS, authorization or publication.

The admin editor now accepts one application subdomain label and appends the
operator-configured App Access `base_domain`, showing the full HTTPS address.
It does not derive the suffix from the console hostname. API requests retain the
complete `public_hostname` contract and existing server-side uniqueness checks;
older multi-label hostnames remain intact when editing unrelated metadata.

Optional uploaded icons use `icon_data_url` alongside the existing default-icon
enum. PNG/JPEG uploads are limited to 64 KiB and 512×512 pixels; the API decodes
and re-encodes a bounded PNG rather than retaining uploaded metadata. SVG and
external image URLs are rejected. Create/edit, replacement and explicit removal
use the existing version-checked save flow. Icons are branding metadata: members
see the latest saved image and fallback icon for applications they can access,
without another publication. Unsaved edits remain private. Member catalog
eligibility, names, descriptions and launch routes still come from the active
published revision; saving an icon never publishes routing or access changes.
Immutable revisions retain historical images for restore and audit.
Migration 174 adds default-empty revision storage and must precede an API update.
Existing empty-icon digests remain unchanged. Explicit legacy SQL reads tolerate
the additive column, but old operator tools may reject schema 174: rollback must
use compatible binaries or a verified pre-upgrade backup. Schema downgrade
refuses to discard uploaded historical icons.

The actual CP has no paid license; its runtime should prove entitlement denial.
Allowed-path HTTP/DB tests use only a test-injected license manager with fresh
ephemeral signing keys. Do not re-trust the published golden seed, add a production
entitlement bypass or use real signing secrets.

## Verification

- Full API `go test ./...` passed with cached Go 1.26.8 after fixing deleted-org query scoping, authwalk request fixtures and the explicit provisional licensing census. Focused HTTP and service/RBAC/licence/config race suites passed. Generated CLI client compiled. OpenAPI generation used pinned oapi-codegen 2.4.1 and openapi-typescript 7.4.4; SQLC and RBAC mirrors were regenerated.
- Owned child PostgreSQL tests passed migration 166→167, empty rollback/reapply, immutable history and history rollback refusal, foreign tenant/gateway, hostname retention/duplicates, optimistic version conflict, audit failure rollback, Unicode search bounds, deleted organizations, revoked gateways and historical gateway deletion conflict. Reads require live organizations; mutations lock them against concurrent soft deletion.
- Real session/router tests passed anonymous/member/machine, missing CSRF, invalid JSON and chunked oversized metadata refusals, plus settings/create/read/edit/history, foreign organization, membership removal and deactivated-user cases. App Access metadata uses the existing 128 KiB request cap.
- Web `verify` passed with verified official Node 24.21.0: typecheck, 146 test files (1806 passes and two existing deliberate expected failures), screen census, responsive contracts and build. The 19 App Access tests cover named permission gating, draft states and recovery. `git diff --check` passed.
- Browser review used a separate verified human fixture account, preserving bootstrap credentials. Native Community preview at 127.0.0.1:15173 denied paid mutations, retained inspection and offered disabling after opt-in. The separate test-only signed entitlement router at localhost:15174 used the same owned PostgreSQL and Redis database 1; no licence was installed into the native CP. Distinct hostnames prevent cross-port session cookie collision.
- Actual browser interactions enabled the registry, created an HTTPS-origin draft against the enrolled gateway, saved edits, recovered unsaved input after reload, and rejected a concurrent stale save while retaining input. The inventory explicitly reports unpublished drafts and unconfirmed connector capability. A 390×844 viewport had document width 390 with no horizontal overflow; screenshots were inspected. This proves draft UX and persistence, not origin connectivity or app delivery.
- Final-source API and test fixture binaries were rebuilt. The owned API is healthy, gateway ready, schema 167 clean; gateway restart retained node ID `01a100fb-de0b-747a-bcc3-8666eb0742b4`, certificate serial and key fingerprint with a fresh post-restart heartbeat. Exact-name resource guards passed nine mock regression tests and the real stack guard.

## Operational notes and remaining stories

Compose label reconciliation briefly stopped this owned API/database/Redis during a runtime refresh. All existing volumes and gateway identity survived. External resources now use exact names; preparation inspects ownership and recorded identity directly and refuses foreign names or missing previously recorded resources instead of silently replacing data. The restored stack passed readiness and reconnect checks; unrelated containers were preserved.

Historical revisions retain gateway references: deleting a referenced gateway returns typed 409 `node_app_access_history_retained`; ordinary unreferenced deletion keeps its existing behavior. No historical revision is removed to make deletion succeed.

AA-2 owns grants/effective access. AA-3 onward must prove connector capability, origin checks, publication and actual delivery. The existing licence-manager refresh interval is not evidence of the later five-second withdrawal bound; AA-7 needs fresh/versioned entitlement decisions. Draft UI has no publish, launch or invented connectivity success. Local screenshots are review artifacts under `/private/tmp`; no remote publication, push or CI dispatch occurred.
