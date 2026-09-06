# SSO improvement — local implementation

Baseline: main f240bd53; user branch sso-improvement. User authorized the recommended Okta + generic OIDC implementation and local test-IdP preview, not remote publication.

## Decisions
- Locked: preserve existing Google/Microsoft APIs and behavior. Add multiple organization-owned Okta/OIDC connections using stable UUIDs and explicit connection selection.
- Locked: new connections are disabled until a successful OIDC test round-trip. Test flows are bound to the initiating authenticated admin, connection revision, org, nonce and PKCE; they do not create a login session or provision users. Editing credentials/issuer invalidates verification and disables the connection. Enable checks the current verified revision atomically.
- Locked: custom-provider identity is connection + issuer + subject. Never automatically attach to an existing email account. Existing users must explicitly link from an authenticated flow; new users may JIT provision only with verified email and existing SSO admission entitlement. Existing Google/Microsoft behavior is unchanged.
- Locked: custom discovery uses public HTTPS endpoints only, bounded requests, no redirects, DNS-to-dial IP verification and no proxy inheritance. No runtime insecure-issuer toggle. Loopback test IdP is injected only in tests/isolated preview harness.
- Locked: existing org update/view authorization and SSO administration entitlement protect settings. Existing configured sign-ins survive entitlement expiry. Configuration changes are audited without secrets.
- Locked: UI provides provider selection, callback URL, credential setup, test, explicit enable, disable and connection name. Test status must distinguish simulation, real verification and failure. No secrets returned in reads.
- Deferred to private-IdP connectivity story: private network issuer policy and custom CA configuration.
- Deferred to later SSO lifecycle slices: SAML, SCIM, group/role mapping, enforcement and full diagnostics history. This release does not enable enforcement.

## Validation plan
Regression tests for SSRF refusal, identity linking refusal, stale verification, disabled login, provider token validation, RBAC and secret-free responses; migration and API generation; both Go editions; UI typecheck/tests/build; local test-IdP walkthrough and browser preview. Real Okta/other IdP tenant validation remains deferred to customer-test-tenant availability. Native desktop SSO compatibility is not established by a web preview.
