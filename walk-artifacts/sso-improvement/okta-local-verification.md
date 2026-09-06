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
