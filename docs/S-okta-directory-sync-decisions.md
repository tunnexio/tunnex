# Okta directory sync — local follow-up

Baseline: `sso-improvement`, SSO content commit `8488e005`. User authorized the recommended directory-sync follow-up locally; remote publication is outside this slice.

## Decisions

- Locked: add Okta behind the existing DirectoryProvider, reconciliation, policy permission, enterprise entitlement, audit and health interfaces. Preserve Google/Microsoft behavior. Generic OIDC is authentication only; SCIM push provisioning is deferred to the SCIM lifecycle slice.
- Locked by user: automatically import new Okta user accounts as well as group memberships. Existing ResolveOrgUser skips unknown users, so a separate source-owned account provisioning path is required. SCIM remains deferred.
- Locked by user: no new accounts or group grants without a valid licence or active entitled trial. Stop additions at expiry, including the existing 90-day grace period; missing licence-manager wiring must refuse additions. Keep directory reads, removals and disabled/deleted-user revocation running. Do not deactivate users solely because a licence expires. This overrides the former directory-addition grace behavior only; other licence features are unchanged.
- Locked by user: import only active users from explicitly mapped Okta groups, never the entire directory.
- Delivery order: first close and verify the shared provisioning licence predicate, then implement source-owned Okta account imports and directory adapter/UI. A passing licence slice alone does not establish Okta import support.
- Proposed credential contract: separate Okta OAuth service application with client ID, organization HTTPS origin, and an RSA private JWK containing its key ID. Seal private material using the existing credential store; return only its keyed fingerprint. Request only `okta.users.read` and `okta.groups.read`, using private_key_jwt against the org authorization server. Do not reuse an SSO client secret or request directory write scopes.
- Proposed UI: Okta row in Settings > Directory sync; setup instructions, explicit opt-in, group mapping, Sync now and existing health/error states. Explain that active users in mapped groups are imported automatically, receive the member role and can use direct Okta sign-in. Show the consequence of disabling/deleting upstream users before enabling sync.
- Proposed safety contract: public HTTPS org origin; no redirects/proxy inheritance; pin checked public IPs; pagination restricted to the same origin and expected collection path. Bound requests, pages and response sizes. Reject incomplete, malformed, unknown-status or failed page responses before reconciliation; never turn a failed continuation into an empty group. Do not expose upstream response bodies or credentials in errors.
- Proposed namespace contract: one Okta directory per organization, as in the existing provider-keyed model. An origin change with group mappings must be refused rather than silently applying mappings/external user IDs to another directory. Credential rotation within the same directory remains available.

## Required evidence

Adapter tests: signed client assertion, correct audience/scopes, pagination, same-origin restrictions, rate limits, authorization failures, missing/deleted groups versus failed continuations, disabled/deleted users, malformed payloads and unknown lifecycle states. Reconciler regression tests: no removals from partial fetches, existing-member matching, ordinary group removal versus full deactivation, manual membership preservation and entitlement behavior. API/schema generation; both Go editions; UI tests/typecheck/build; local simulated preview clearly labeled.

The full database-backed SSO walk remains pending: the configured Docker daemon was unavailable during the preceding validation. A mock HTTP provider test or browser design preview does not satisfy that proof. Use an isolated, explicitly identified database project/container/network for the eventual migration and callback/reconciliation walk; never the default shared stack. Real Okta qualification requires a test tenant and separately configured service app.

## Primary references

- [Okta service-app OAuth](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/): Okta-scoped service-app tokens require private_key_jwt.
- [Okta API pagination](https://developer.okta.com/docs/api): follow pagination links for complete collections.
- [Okta Groups API](https://github.com/okta/okta-sdk-python/blob/master/docs/GroupApi.md): group-member collection endpoint.

## Licence slice evidence and remaining identity decision

The service now requires StateValid plus the directory-sync entitlement; nil managers and expiry grace refuse additions. Health exposes provisioning_allowed and the CP Directory sync dialog explains that provisioning is paused while revocations continue. Regression tests first failed for nil-manager, exact-expiry and grace behavior, then passed after the predicate change. Active/expired trial and Starter cases exercise the actual service predicate through reconciliation and preserve deactivation/removal.

A bounded independent review found that one licence check per grant batch allowed later additions after expiry. The user's explicit no-additions-after-expiry requirement authorizes correcting this: check before each additive write; already-authorized in-flight writes may complete, but subsequent writes are refused. A regression failed with two additions, then passed with one. The subtractive loops remain outside the gate.

Locked by user: direct Okta login on the first sign-in for newly imported users. The directory user ID is bound to the verified Okta ID-token subject within the selected connection and exact issuer. Existing unrelated same-email accounts are never automatically adopted. Imported accounts receive the member role only. The associated Okta SSO connection must be explicitly selected from the same org and validated against the directory origin. Its namespace is locked once directory sync is associated, even before the first import. Connection edits must not silently change directory authority.

Managed login must not fall back to JIT for an unknown subject. A previously imported identity may log in after licence expiry only while its existing org membership remains active; a callback must never restore revoked membership or bypass group-removal authority. New account creation, org membership, identity binding and initial mapped-group grant must commit atomically with source ownership. Imported email is not proof of mailbox ownership; ID-token verification remains mandatory for login. Existing account collisions are reported for explicit authenticated linking, not merged.

The first-login decision is now resolved; no further user sign-off is needed for this selected implementation. Okta adapter/import implementation and isolated database proof are still outstanding.

Primary identity reference: https://support.okta.com/help/s/article/sub-claim-limitation?language=en_US — the ID-token sub is the immutable Okta user ID. This contract does not apply to access-token sub, which may be customized.

## Direct-login draft review — findings held for user disposition

The source implementation is a draft, not acceptance-ready. Two independent bounded reviewers found:

1. P1: default membership-insert trigger gives imported users manual/legacy provenance, preventing last-group revocation. Use a dedicated source-owned membership transaction and preserve legitimate provenance on pre-existing users.
2. P1: an expected joiner/email conflict aborts the group before unrelated leaver removals. Separate additive import errors from authoritative membership resolution and continue safe revocations.
3. P1: Okta API still inherits enabled=true default. Require explicit Okta opt-in, preserving legacy provider defaults.
4. P2: direct first SSO callback must mark imported email verified only after verified subject and matching account-email checks.
5. P2: concurrent first configs on different connections can replace the namespace. Guard immutable org/provider binding atomically.
6. P2: return safe enabled/configuration state and preserve it during credential rotation, with explicit enable/disable controls.
7. P2: new safe configuration error messages and working connection-load retry/rejection handling.

User disposition requested together via the in-app question. Do not report this draft as complete or wire-proven. Docker remains unavailable; migration, concurrency and full import-to-browser-login proof are outstanding.

## Review disposition
User approved all recommended fixes. Apply all seven held findings, then re-review the folded implementation. The existing-user ownership boundary and no-email-takeover rule remain locked.

## Approved fixes folded and local verification — 2026-09-06

All seven approved findings have been folded. The follow-up UI pending-mutation finding is also fixed: one synchronous guard covers save, activation, sync, map and unmap through refresh; forced-submit regression passes. Targeted independent UI re-review reports no remaining blocker. Backend source re-review resolved its four reported findings; neither bounded review is a production qualification.

The earlier Docker blocker is resolved with a dedicated Colima profile `tunnex-sso-review`, without changing the default Docker context. Every DB-capable validation verifies `COMPOSE_PROJECT_NAME=tunnexssoreview0906`, container `tunnexssoreview0906-postgres-1`, and network `tunnexssoreview0906_default`. Migration 138 applied cleanly. Runtime credentials and compose configuration remain ignored under walk-artifacts/sso-improvement/local-runtime.

Database integration verifies source-owned imported membership (no accidental manual/legacy grant), repeat import, expiry refusal and last-group revocation invocation. A signed local IdP token exchange plus real database test verifies direct imported-user first login, matching-email verification, refusal of unknown subjects, and revoked-membership refusal. Existing active imported identities can sign in after licence expiry. The deprovision integration uses a recording delegate: this proves invocation, not live gateway/session removal.

Adapter tests verify RS256 private_key_jwt signature, kid, issuer/subject, token audience and expiry, read-only scopes, cached token use across complete pagination, and no partial membership output on continuation 401/403/404/429/500 errors. Unknown lifecycle statuses intentionally retain prior state with an error; ACTIVE, SUSPENDED and DEPROVISIONED are supported.

Web: 60 focused tests pass, typecheck and production build pass (existing large-bundle warning). Rendered real Directory sync component checked with simulated expired licence: provisioning paused while polling stays enabled; dialog styles and spacing verified. This browser preview is explicitly simulated.

Remaining qualification: a full browser-to-running-CP import/login/session walk and real Okta service-app tenant. These are not satisfied by the signed-token service/database test. Full repository gate suite and remote CI are not claimed. No remote publication performed.

Final focused API checks passed in open and enterprise editions for internal/idpsync, internal/sso and internal/http; both API editions build. The auth walk now supplies valid SSO bodies and connection UUIDs so it verifies the intended unauthenticated 401 boundary. See walk-artifacts/sso-improvement/okta-local-verification.md.

## Running fixture walk follow-up

User authorized local CP plus fixture data. Full local browser first login now
passes through the running HTTP callback and session into the real CP dashboard.
Walk found a sessionless callback nil-principal panic; regression reproduced it,
then the narrow nil guard passed in both editions and the browser retry succeeded.
See the running-CP section of the walk record for isolated runtime identities,
test-only overlays and proof limits. This closes local first-login wire proof,
not real Okta tenant or signed licence deployment qualification.

## Configured login discovery
User requests only configured providers on normal login. Expose minimal public connection ID, name and provider for enabled verified connections; no issuer, credentials or user membership. Legacy providers require a single enabled organization because slug-less start rejects ambiguity. Preserve explicit links and password login; no enforcement change.

### Approved real-provider claim completion (2026-09-06)
User approved UserInfo fallback after real Okta org-server ID token omitted email_verified. Locked: custom Okta/OIDC only; verify ID token including nonce first; retain bounded public HTTPS/no-redirect transport; UserInfo subject must exactly match signed subject; require explicitly verified email; reject conflicting email and explicit false/null ID-token verification. Google/Microsoft behavior unchanged. No email-based identity adoption. Real provider walk must be repeated.
