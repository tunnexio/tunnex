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
