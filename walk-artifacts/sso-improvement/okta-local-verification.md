# Okta local verification — 2026-09-06

Branch: sso-improvement; local uncommitted product work following paper commit 935cea62.

## Database isolation

All DB-capable commands use ignored local-runtime/run.py, which prints and verifies:
- COMPOSE_PROJECT_NAME=tunnexssoreview0906
- Container tunnexssoreview0906-postgres-1
- Network tunnexssoreview0906_default
- Dedicated Colima socket tunnex-sso-review/docker.sock

Migration result: migrate_up_complete version=138 dirty=false.
Default Docker context and shared database were not changed.

## Observed results

- Open edition: internal/idpsync, internal/sso, internal/http passed against isolated PostgreSQL.
- Enterprise edition: same three packages passed against isolated PostgreSQL.
- Both API editions: go build ./... passed (GOFLAGS=-mod=readonly).
- TestImportedOktaFirstLoginAndRevocationIntegration passed: signed local test IdP token exchange, exact subject/email binding, first login email verification, existing login after expiry, unknown subject and revoked membership refusals.
- TestOktaImportedOwnershipAndExpiryIntegration passed: source ownership, stable repeat imports, expiry refusal, final-group revocation delegate invocation.
- Okta adapter tests passed: signed service assertion and full two-page read, token reuse, and continuation error refusal without partial results.
- Web: 60 focused tests, typecheck and production build passed. Existing large chunk warning remains.
- Browser: real Directory sync component rendered with simulated expired licence, polling enabled and provisioning paused. Styles verified by screenshot inspection.
- Targeted UI follow-up review: pending-mutation guard resolved, no remaining blocker reported.
- git diff --check passed.

## Limits

Browser preview uses an in-memory API. Signed-token/database tests are service integration, not a full running-CP browser/session walkthrough. Deprovision delegate invocation is not live gateway revocation proof. Real Okta tenant/service-app qualification, full repository gates and remote CI remain pending. No remote push or PR performed.

## Running CP and browser fixture walk — 2026-09-06

User authorized starting the local stack with fixture data. Actual API runs on
127.0.0.1:18771, real Vite CP UI on 127.0.0.1:8771, local IdP on 127.0.0.1:18772.
Dedicated Redis is tunnexssoreview0906-redis-1 on the same verified isolated network.

Test-only Go overlays, fixture service, JWK and runtime logs are in ignored
local-runtime. Overlays permit the loopback IdP and inject a 24-hour test trial
manager into the local server. They do not alter production source or signature
trust. This walk therefore does NOT prove production public-HTTPS transport or
signed-licence installation; those boundaries are covered separately.

Observed sequence:
1. Seeded Demo Organization and its development owner in the isolated database.
2. Authenticated local API owner session; configured Local Okta Workforce.
3. Admin connection test performed discovery, authorization, PKCE code exchange,
   signed ID token verification and real callback; returned sso_test=verified.
4. Enabled the tested connection, explicitly opted in directory sync, mapped
   00gEngineering. Dedicated service-app assertion used only read scopes.
5. Trigger returned last_sync_ok=true, provisioning_allowed=true, sync_health=ok.
6. Browser opened connection login and clicked Continue with company SSO.
7. First attempt exposed a real nil-principal panic in the HTTP callback. Added
   regression which reproduced the panic, then a nil guard. Regression passed in
   both Go editions. This is a sessionless first-login fix, not an auth bypass.
8. Restarted only the isolated fixture CP, retried browser login. Real dashboard
   rendered Demo Organization, Members 4, profile Alice, and authenticated API
   reads returned 200. No local password or pre-link used for Alice.

Fixture login user: alice@fixture.example, Okta subject 00uAliceFixture.
Connection: 01900000-0000-7000-8000-000000000099.
Admin development credentials are the repository's standard seed credentials.
Local services left running for user review. No production/remote mutation.

The earlier full-browser first-login gap is now closed for the local fixture.
Real Okta tenant qualification, live gateway revocation and full repository CI
remain outside this evidence. The running API also logs an unrelated product
alert SQL parameter-type error; no alert-system health claim is made.

## Real Keycloak provider — setup and verification

Keycloak 26.7.3 official container is running as
`tunnexssoreview0906-keycloak-1`, realm `tunnex-review`, loopback port 18774.
Created a confidential `tunnex-cp` client with exact CP callback and PKCE S256
required. Generated credentials are ignored and never printed. Created a verified
fixture identity matching the existing demo owner.

Actual browser CP admin test with explicit account linking redirected to real
Keycloak login. After credential sign-in, callback returned to CP with
“Sign-in verified” and “Verified · disabled”. This proves real provider discovery,
code exchange and signed identity verification/account linking, not yet fresh
login while enabled. Loopback HTTP transport and test trial manager remain
compile-time local overlays; production HTTPS/licence validation is not claimed.

Real Okta tenant integrator-4616469.okta.com was created by user-assisted signup
with support@tunnex.io. Chrome inspection currently shows Okta Verify QR enrollment;
admin access and app/service configuration have not yet been completed.

### Real Okta tenant walk — 2026-09-06

- Created approved `Tunnex Local SSO Review` Web OIDC app in `integrator-4616469.okta.com`; client `0oa17a3oynrexiyA5698`.
- Exact callback: `http://127.0.0.1:8771/api/v1/auth/sso-connections/callback`; Authorization Code only, PKCE required, no wildcard.
- Assigned only approved test account `support@tunnex.io`. Saved disabled CP connection `01900000-0000-7000-8000-000000000097`.
- Real Chrome Okta session completed authorization and returned to CP. Token verification reached normalization (issuer/audience/signature/expiry and nonce passed).
- Walk FAILED identity normalization: temporary ignored diagnostics confirmed subject/email present but `email_verified` absent, not explicitly false. No tokens or claim values included in diagnostics.
- Pending decision: bounded HTTPS UserInfo fallback for missing required claims, with exact subject match to verified ID token, explicit verification required, no override of explicit false or contradictory identity claims. Production trust checks must not be relaxed.
- Real directory-service app/import and fresh normal login remain unverified. Local trial/HTTP overlays remain test substitutes only.

### Approved UserInfo fallback retest — 2026-09-06

- Regression reproduced failure before implementation. Custom-provider UserInfo fallback now completes only missing claims after signed ID-token/nonce verification; explicit false/null, subject mismatch, email conflict and unverified UserInfo are refused.
- Full `internal/sso` package passed in open and enterprise editions after the change.
- Repeated real Chrome Okta authorization against the assigned support test account: CP returned `Sign-in verified`, `Okta Live Review` is `Verified · disabled`.
- This proves real authorization/code exchange/identity completion, not an ordinary new-member login. Directory service-app import, enabled ordinary login and final full gates remain pending. Local trial/network test overlays remain in use.

### Enabled connections and fresh Keycloak login — 2026-09-06

- User approved enabling both verified connections and creating the read-only directory service app. Both connections now enabled.
- Chrome fresh CP login -> Continue with Keycloak Review -> real local Keycloak credentials -> CP Overview as Owner succeeded.
- Okta directory service app `0oa17a42pgeDHzo6P698` created; public signing key `tunnex-local-directory-review` active; private_key_jwt authentication saved after registering public key. Private key remains ignored local-runtime, mode 0600.
- `okta.users.read` and `okta.groups.read` grants verified Granted.
- Admin role not yet saved: standard Read-only Administrator cannot be constrained and applies across test org; pending explicit approval of this role. Directory import and ordinary Okta member login remain pending.

### Real directory import and ordinary Okta login PASS — 2026-09-06

- Approved Read-only Administrator role saved for service app. User separately approved disabling its mandatory DPoP requirement; adapter uses private_key_jwt and does not implement DPoP. Signing key and read-only OAuth scopes retained.
- Existing fake directory namespace was preserved. Seeded separate local organization `01900000-0000-7000-8000-000000000010` and fixture owner `okta-owner@demo.tunnex.local`; real tested/enabled connection `01900000-0000-7000-8000-000000000096`.
- Created Okta group `Tunnex Review Engineering` (`00g17a49xa5TRubRp698`), assigned approved support test account, and mapped only that group in CP.
- Real API sync returned `last_sync_ok=true`, `sync_health=ok`. CP Users & Roles showed imported `support@tunnex.io` as member (not owner/admin); no email verification granted by directory import alone.
- Logged out fixture owner; ordinary connection login -> real Okta session -> CP Overview as Support in Okta Live Review succeeded. No password provisioning or email-based self-link used for imported identity.
- Tightened ignored local network overlay: ONLY exact local fixture/Keycloak HTTP endpoints use local transport; all real external requests use production public-IP-pinned HTTPS, no redirects, bounded response transport. Repeated real directory sync and ordinary Okta login passed with this restriction.
- Focused Okta/import/licence regression cases passed in BOTH editions. Full SSO package also passed in BOTH editions after UserInfo fix.
- Completed requested real-provider happy paths: real local Keycloak ordinary login; real Okta test callback, service-app directory read/import, imported member ordinary login.
- Boundaries: local licence is still a test trial overlay, not a real signed licence qualification. Licence expiry/removal refusal paths have regression proof, not a real-tenant lifecycle walkthrough. No native gateway/tunnel revocation or full CI/release qualification claimed. No remote push.

### Running expiry/removal/recovery walkthrough — 2026-09-06

- Ran API with expired trial claims via ignored local-only test-manager overlay. This bypasses signature verification and is NOT a signed-licence lifecycle qualification.
- Added a previously unknown ACTIVE local-IdP joiner `expiry-joiner@fixture.example`. Sync succeeded with `provisioning_allowed=false`; scoped DB audit confirmed zero matching user rows.
- Removed support test account from real Okta mapped group. Real directory sync under expired trial succeeded; DB audit confirmed its mapped CP group membership removed.
- Restored upstream Okta group assignment while still expired: sync succeeded but CP membership remained absent. No new grant on lapsed entitlement.
- Restored valid trial overlay and repeated both syncs: fixture joiner now exists exactly once and both its Engineering grant and support user's real Okta group grant are present. Preview restored to valid trial; real test-group membership restored.
- Target real-Okta organization has zero nodes and zero devices (global DB contains unrelated test fixture rows). No WireGuard traffic, device credential, gateway peer removal, suspended-Okta-user session sweep or real signed licence lifecycle proof claimed. Those remain outstanding for a complete deployment lifecycle walk.

## Suspension ordering regression and website documentation (2026-09-06)

- Running fixture suspension exposed a real `member_not_found`: org access was revoked before the disabled-account sweep used an active-only membership lookup. The regression failed before the fix.
- Sync-only deactivation now accepts the retained revoked membership; human deactivation remains active-membership scoped. Regression covers active/revoked cases, foreign-org refusal, human refusal, system audit and repeat-call idempotency.
- `internal/tenancy` and `internal/idpsync` pass in both editions against verified isolated project `tunnexssoreview0906`. The first open suite hit existing `TestCrossOrgRoleGrants` audit-ordering flakiness (ORDER BY created_at with same-transaction timestamps); isolated retry and full package retry pass. This flake remains unmodified.
- Restarted only the local review API. Retried fixture directory sync: `last_sync_ok=true`, `sync_health=ok`; `alice@fixture.example` status is now `deactivated`. Fresh browser sign-in refuses access with the mapped-group access message. Prior session had already been cut on org revocation; this retry does not claim a new live session sweep.
- Website docs updated locally in `/tmp/tunnex-web-sso-docs`, branch `sso-configuration-docs`; original dirty website checkout preserved. Guide includes Okta Web client, generic OIDC/Keycloak, separate directory service client/key/scopes/role, mapped import, expiry/removal behavior, rollout checklist and troubleshooting, plus six credential-free screenshots. Astro production build passes; all six images load in browser and rendered guide inspected. Preview: http://127.0.0.1:8775/docs/sso-setup/
- Remaining deployment qualification: issued signed licence lifecycle, separate non-admin real Okta suspension, enrolled gateway/client traffic and peer/credential revocation. No target-org node/device is enrolled. Local test-manager expiry and fixture suspension are substitutes for those missing real deployment checks, not satisfaction. Full repository gates/remote CI are not claimed. No remote publication.

## Real Okta non-admin lifecycle walk (2026-09-06)

- Created a dedicated non-admin tenant user `sso-walk@tunnex.example` and assigned it only to the existing mapped `Tunnex Review Engineering` group. It was imported by a real Okta service-app sync as an active Tunnex member with that mapped group.
- Suspended that account in the real Okta Admin Console, triggered a real Okta sync, and observed a healthy sync plus Tunnex `status=deactivated`, revoked org access and removed mapped-group membership. The account was then restored to `ACTIVE` in Okta and a second real sync restored only its mapped-group grant; the Tunnex account deliberately stayed deactivated.
- Verified owner-controlled recovery through the running local control plane API: explicit member reactivation restored active status. The account now ends in Okta ACTIVE / Tunnex active / mapped group present. This is intentional: upstream re-enable is not an automatic access restore.
- This closes the real non-admin Okta directory lifecycle proof. It does not provide signed-licence, enrolled gateway/device, peer/credential, or live traffic revocation proof; target organization remains without nodes or devices.
