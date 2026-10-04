# AA-2 explicit application grants

Status: locally accepted on 2026-10-03, following [AA-1 local acceptance](AA-1-development-evidence.md).
All changes remain local on `feature/app-access`; implementation is uncommitted.

## Contract

One organization-scoped store powers global and app-local grant management.
Grants select an explicit existing user or group, with optional UTC validity
bounds interpreted as `[starts_at, expires_at)`. Overlapping valid allows form a
union. No default subject or implicit administrator grant is created.

App and subject identity are immutable after creation. Updates and revoke use
expected versions. Additive changes require entitlement and organization opt-in;
inspection, revocation and disabling survive entitlement loss. All management
routes require the separate named `app_access:grant` permission and human browser
authority. User/group lookup remains tenant scoped.

Evaluation reads current users, memberships and group membership. Logical
membership access revocation, deactivation, deletion and missing subjects deny
eligibility; a stale group-members row is not authority. Intentional reactivation
can make a surviving grant match again under existing identity behavior. Physical
subject deletion must preserve grant history without blocking existing directory
deletion; a narrow transactional deletion hook revokes the retained grant.

Effective-access preview distinguishes matching grants from actual browser access.
AA-1 apps are unpublished drafts; the preview must not report them as accessible.
Future parent-login, app-session, live connector and serving revision checks remain
with their owning stories. Revoke confirms grant configuration, with no claim that
active streams have already terminated.

## Acceptance evidence

- Actual owned child PostgreSQL tests passed migration 167→168, empty down/up and retained-history rollback refusal, foreign user/group/app references, immutable subjects, null-FK rejection, audit rollback, union/default-deny and half-open validity boundaries. Window validation uses PostgreSQL microsecond precision so sub-microsecond bounds cannot pass validation then fail a database constraint.
- Logical membership revocation, deactivation, missing group membership and soft-deleted users deny eligibility. Existing group deletion and physical member removal succeeded through their real services. The transactional FK hook preserved subject identity/history, revoked and incremented the grant, and audited a named system actor; injected audit failure rolled directory deletion back. Rejoining did not resurrect a physically retired grant.
- A deterministic concurrent edit/deletion test observed the edit waiting on the subject lock; directory deletion committed without a deadlock, and the edit failed safely. Additive edits lock the immutable subject before the grant row. Impact counts and grant version come from one SQL statement snapshot, with accepted roles derived from the named RBAC policy.
- Real human-session/router/PostgreSQL tests passed explicit user and existing Everyone group grants, member/machine/CSRF refusal, stale edit 409, malformed window 400, spoofed publication 400, opt-out and signed licence expiry. Reads, disabling and revoke survived feature loss; repeated revoke was idempotent without duplicate audit. Matching grants never produced browser access to drafts.
- Final full API `go test ./...` passed with Go 1.26.8. Central service/HTTP race tests passed; RBAC/licence/config races also passed. SQL query isolation/deleted-org and migration compatibility gates passed. Regenerated CLI client compiled. Narrow typed aliases preserved existing generated FQDN enum exports after a new enum-name collision; policy behavior remained unchanged.
- Supported Node 24.21.0 web verification passed typecheck, 147 test files (1819 passes and two existing deliberate expected failures), responsive/screen census and build. Focused UI tests cover explicit subjects, precise timestamps, stale input, named permission before fetch, unavailable impact, versioned removal, feature loss, unpublished previews and filter changes without rebinding a form to another app. Independent backend and web reviews found no additional blockers.
- The owned database was privately backed up before upgrading the native CP. Final-source API and test-only entitlement fixture now serve clean schema 168. Native CP and the same enrolled gateway remain healthy/ready with fresh heartbeat; no native paid licence was installed.
- Live browser review created a real manual people group through the existing Community directory UI and added the fixture user. App-local explicit user/group grants saved through real handlers and appeared in the global inventory. With both grants, user-grant revoke impact was 1 matching user and 0 losing their last match; after that reviewed revocation, group-grant impact was 1 and 1. The group grant was retained for further local development.
- Calendar-selected expiry persisted as local 2026-10-04 18:00. A concurrent stale save rejected with its distinct 2026-10-05 09:00 input retained. Effective preview reported matching grant plus `app_unpublished` denial. The stale dialog had viewport/document width 390 at 390×844; screenshots were inspected and viewport override reset. Earlier generic automation filling did not populate the native date widget, so date claims rely on the subsequent real calendar interactions and readback.

Local review artifacts: `/private/tmp/app-access-aa2-revoke-impact.png` and
`/private/tmp/app-access-aa2-stale-mobile.png`. `git diff --check` passed. Five
existing stashes and unrelated AI directories remain preserved. No commit, push,
remote deployment or CI dispatch occurred. AA-3 onward owns connector/origin,
publication, sessions and actual delivery; these grants do not complete those stories.
