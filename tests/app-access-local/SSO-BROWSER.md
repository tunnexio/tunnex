# Isolated rendered SSO fixture

This nonshipping `_test` fixture uses a disposable fully migrated child PostgreSQL database, Redis DB2 and new user/org UUIDs. It leaves the native/paid data, enrolled gateway, proxy and original browser cookies alone. Its loopback-only fake provider serves discovery/JWKS and signed RS256 tokens; the real OIDC client verifies signature, issuer, audience, nonce and PKCE. The production SSO callback creates the parent session. It does not publish an app, grant access, assert IdP MFA or qualify the native published-app SSO journey.

The UI hostname is exactly `sso.127.0.0.1.nip.io:15186`. Cookies are host scoped: using `localhost` or `127.0.0.1` for this console would collide with other fixtures despite different ports. macOS rejected binding `127.0.0.2` with `EADDRNOTAVAIL`; no OS alias was installed. All three published/listening ports remain bound to loopback.

From `apps/api`, compile with the pinned Go1.26.8 toolchain:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test -c -o ../../tests/app-access-local/.runtime/http-sso-browser.test ./internal/http
```

From `tests/app-access-local`, run `./ownership.py` first, then use only the existing owned network/image and private env file:

```sh
./docker-local.sh run --rm --pull never --network tunnex-app-access-aa0-1003_default --env-file .runtime/env -e APP_ACCESS_SSO_BROWSER_FIXTURE=1 -e APP_ACCESS_OWNED_PROJECT=tunnex-app-access-aa0-1003 -e APP_ACCESS_OWNED_CHECKOUT=/Users/pawangupta/tunnex/tests/app-access-local -p 127.0.0.1:15187:15187 -p 127.0.0.1:15188:15188 -v /Users/pawangupta/tunnex/tests/app-access-local/.runtime/http-sso-browser.test:/sso.test:ro alpine:3.23 /sso.test -test.v -test.run '^TestAppAccessOwnedSSOBrowserFixture$' -test.timeout 30m
```

From `apps/web`, run a separate React preview:

```sh
__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=sso.127.0.0.1.nip.io TUNNEX_DEV_API=http://127.0.0.1:15188 node node_modules/vite/bin/vite.js --host 127.0.0.1 --port 15186 --strictPort
```

Open `http://sso.127.0.0.1.nip.io:15186/login?next=%2Fapp-access`, choose **Continue with Google**, then **Continue with owned test identity**. Successful callback lands on the normal My Applications member page and shows the deliberately unlicensed/empty fixture state. No password, privileged session mint, browser security warning exception or trusted-key modification is used.

Current rendered evidence is `.runtime/aa8-rendered-sso-myapps.jpg`. The qualified binary is `.runtime/http-sso-browser-next.test`, SHA256 `823379230bb974500a386b149e36c4e6e63ac892604c8a5221d3870c7b47e876`. Stop only the fixture container identified by its exact mounted test artifact; SIGTERM allows the child database cleanup. Never flush Redis or stop the paid/native/proxy processes. Fixture-created Redis sessions/flow keys are bound to its unique user/state IDs and have ordinary bounded TTLs.

## Published native application qualification

The additional nonshipping `TestAppAccessOwnedNativeSSOBrowserFixture` uses the exact owned main database and Redis DB1, existing sealer and existing verified **member** `aa8-direct@example.test`. It uses normal Google configuration, OIDC verification, native callback parent mint and the current explicit grant. It neither injects a parent nor creates a publication. Independently published Payroll revision17/authority9 remains the serving route.

`run-native-sso-browser-fixture.sh` publishes only loopback15187/15189. The secondary HTTPS console is `sso-console.127.0.0.1.sslip.io:15190`, with distinct host cookies and a seven-day leaf under the existing development CA. No root trust or primary app/console certificate was changed. The secondary adapter uses the exact owned backend and verified forwarded HTTPS transport.

Before normal audited configuration Set, the fixture writes the complete original sealed configuration (or absence) to a private0700 mount with exclusive0600 snapshots. It then captures the exact installed row. Graceful cleanup uses an independent bounded context, locks and compares every installed field, restores original sealed bytes and timestamps atomically, and commits a scoped audit. Concurrent changes refuse restoration. Retain private backups for exceptional cleanup; never blindly reset configuration.

The bounded test-only proxy override pointed only to the secondary console. Actual Chrome passed public pending launch → normal Google login → native callback → safe internal Continue → single redemption → published origin and asset → same-origin form echo. The member administration route showed a permission denial. Normal own-session UI revoked only its newly created session (`51b6355b` short ID); the app returned to Continue and its SSO console remained authenticated. This does not assert IdP MFA or universal browser compatibility.

The original proxy binary and console15180 were restored; all primary certificate, key and credential hashes matched the initial manifest. Graceful fixture shutdown passed; independent DB readback matched original configuration absence and one restoration audit. The primary human console login, other app session, grant and Payroll publication were preserved. Qualified runtime SHA256: `b75a11352a5651591db0bedc6f5d5822b598267917041eb5d40df08394ccffb8`. Later source hardening adds unknown-commit detection and refuses unrelated sidebar inventory prefetches; it does not change the qualified login/app flow. Both secondary containers were stopped; private artifacts were retained.

Private evidence: `.runtime/aa9-native-sso-final-proof.json`, `.runtime/aa9-rendered-native-sso-origin.jpg`, `.runtime/aa9-rendered-sso-member-denied.jpg`, `.runtime/aa9-sso-console/rollback-completed.json`. These qualify the local fixture, not an external live IdP.
