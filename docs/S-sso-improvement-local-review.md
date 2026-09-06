# SSO local preview and held review

Branch: sso-improvement. Baseline f240bd53. Implementation is local and unpushed.

## Preview
Run the web Vite server on loopback and open `/sso-preview.html` (currently http://127.0.0.1:8770/sso-preview.html).
The page reuses the product SsoConnections component with an isolated in-memory adapter.
Its test action is explicitly simulated: no external provider credentials, provisioning,
or real activation. The dev entry is not an input to the production Vite build.

## Verified so far
- Focused Go SSO/HTTP tests passed.
- API builds passed with and without enterprise tags.
- Web typecheck/build passed; 17 focused UI tests passed (new connection UI, existing login and SSO view models).
- Local fake IdP discovery, token exchange and JWKS signature validation exercised by Go tests;
  wrong nonce/audience/unverified email rejected. This is not a browser-to-provider roundtrip.
- Browser walkthrough: provider selection, credentials screen, test-required screen, simulated verified-but-disabled screen.
- Docker daemon unavailable. Migration and database-backed transactional/link/activation proof NOT run.
- No real Okta tenant or native desktop SSO proof.

## Ranked review findings — accepted by user and resolved
1. P1: bind public login callback to the initiating browser to prevent login CSRF.
2. P1/P2: provide authenticated self-link for existing ordinary members; admin-only self-link cannot migrate a workforce.
3. P2: decide immutable issuer after identity linking vs explicit migration. Recommendation: immutable issuer after linking; new issuer uses a new connection.
4. P2: restore Authentication section and tested org/connection on callback return.
5. P2: safe, actionable test failure categories and refresh/retry.
6. P2: prevent pending async responses from crossing setup editors.

The user approved the recommended fixes. All six findings were folded and re-reviewed by the independent backend and UI reviewers. Two remaining callback UX cases (company retry context and an empty-list self-link failure) were corrected within that approved scope and passed targeted re-review.

Final checks: focused SSO/HTTP tests and authorization-order inventory passed in both editions; both API builds passed; 17 focused UI tests and production web build passed. The local IdP tests verify discovery/JWKS/token checks; the browser simulation does not perform a real IdP roundtrip. Database integration tests are included but skipped explicitly without an isolated database. Transaction concurrency, migration execution, and full callback/self-link DB flows remain unverified. No release-readiness claim or remote publication.

Existing organization/settings integration suites also passed: 27 tests across orgseam, accessorgswitch and settingswiring (44 UI tests total across the two focused runs). User-facing preview remains open on provider selection at http://127.0.0.1:8770/sso-preview.html.
