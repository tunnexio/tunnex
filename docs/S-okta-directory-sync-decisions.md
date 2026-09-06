# Okta directory sync — local follow-up

Baseline: `sso-improvement`, SSO content commit `8488e005`. User authorized the recommended directory-sync follow-up locally; remote publication is outside this slice.

## Decisions

- Locked: add Okta behind the existing DirectoryProvider, reconciliation, policy permission, enterprise entitlement, audit and health interfaces. Preserve Google/Microsoft behavior. Generic OIDC is authentication only; SCIM push provisioning is deferred to the SCIM lifecycle slice.
- Locked by user: automatically import new Okta user accounts as well as group memberships. Existing ResolveOrgUser skips unknown users, so a separate source-owned account provisioning path is required. SCIM remains deferred.
- Locked by user: no new accounts or group grants without a valid licence or active entitled trial. Stop additions at expiry, including the existing 90-day grace period; missing licence-manager wiring must refuse additions. Keep directory reads, removals and disabled/deleted-user revocation running. Do not deactivate users solely because a licence expires. This overrides the former directory-addition grace behavior only; other licence features are unchanged.
- Delivery order: first close and verify the shared provisioning licence predicate, then implement source-owned Okta account imports and directory adapter/UI. A passing licence slice alone does not establish Okta import support.
- Proposed credential contract: separate Okta OAuth service application with client ID, organization HTTPS origin, and an RSA private JWK containing its key ID. Seal private material using the existing credential store; return only its keyed fingerprint. Request only `okta.users.read` and `okta.groups.read`, using private_key_jwt against the org authorization server. Do not reuse an SSO client secret or request directory write scopes.
- Proposed UI: Okta row in Settings > Directory sync; setup instructions, explicit opt-in, group mapping, Sync now and existing health/error states. Explain that only existing organization members receive mapped memberships. Show the consequence of disabling/deleting upstream users before enabling sync.
- Proposed safety contract: public HTTPS org origin; no redirects/proxy inheritance; pin checked public IPs; pagination restricted to the same origin and expected collection path. Bound requests, pages and response sizes. Reject incomplete, malformed, unknown-status or failed page responses before reconciliation; never turn a failed continuation into an empty group. Do not expose upstream response bodies or credentials in errors.
- Proposed namespace contract: one Okta directory per organization, as in the existing provider-keyed model. An origin change with group mappings must be refused rather than silently applying mappings/external user IDs to another directory. Credential rotation within the same directory remains available.

## Required evidence

Adapter tests: signed client assertion, correct audience/scopes, pagination, same-origin restrictions, rate limits, authorization failures, missing/deleted groups versus failed continuations, disabled/deleted users, malformed payloads and unknown lifecycle states. Reconciler regression tests: no removals from partial fetches, existing-member matching, ordinary group removal versus full deactivation, manual membership preservation and entitlement behavior. API/schema generation; both Go editions; UI tests/typecheck/build; local simulated preview clearly labeled.

The full database-backed SSO walk remains pending: the configured Docker daemon was unavailable during the preceding validation. A mock HTTP provider test or browser design preview does not satisfy that proof. Use an isolated, explicitly identified database project/container/network for the eventual migration and callback/reconciliation walk; never the default shared stack. Real Okta qualification requires a test tenant and separately configured service app.

## Primary references

- [Okta service-app OAuth](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/): Okta-scoped service-app tokens require private_key_jwt.
- [Okta API pagination](https://developer.okta.com/docs/api): follow pagination links for complete collections.
- [Okta Groups API](https://github.com/okta/okta-sdk-python/blob/master/docs/GroupApi.md): group-member collection endpoint.
