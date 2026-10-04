# App Access local UI quality qualification — 2026-10-04

The local UI pass aligns App Access with the existing Users & Groups and Settings workspaces. Applications now has one workspace heading, the shared active tab rail, a structured inventory table and grouped availability controls. Create/edit uses separate identity and origin Cards with descriptions beside fields on desktop and stacked fields on mobile. Connection, publication, grants, events and session actions use consistent section headers and grouped controls. Member application cards keep the server-provided launch URL and show scoped sessions with explicit session identity. Successful metadata uses neutral badges; liveness retains its existing status meaning.

No API contract, launch nonce, RBAC boundary, grant or authentication configuration was changed by the UI pass. Existing admin/member separation, publication readiness and exact session revoke behavior are retained.

## Rendered evidence

Private screenshots live in `tests/app-access-local/.runtime/ui-pass/` (directory0700, files0600). `reference-settings.jpg`, `before-applications.jpg` and `before-editor.jpg` record the existing reference and old layout. `after-applications-default.jpg` provides a same-viewport comparison; desktop inventory/editor and mobile create/editor/connection/grants/review/events/member views are also retained. The events mobile screenshot precedes the final navigation-class correction; it is not evidence of that final rail styling.

In-app rendered checks at1280×900 and390×844 show page width equal to viewport width; wide event/session tables scroll inside their named table region. Keyboard checks cover step navigation, inventory search/filter/table/application link and member search/Open link. The disabled publication filter displays the precise no-match state, and member sessions display the actual empty state. Connection loading was observed; focused tests cover read errors and retained current publication after a failed request. Viewport override was reset after checks.

Normal Chrome browser actions pass: fresh saved connection check, confirmed republish with all five readiness conditions, Payroll origin plus asset, synthetic member denial on an administration route, exact new-session self sign-out and exact new-session administrator revoke. Administrator revoke has one durable tombstone and one scoped audit. The console remains authenticated and grants/settings are untouched. Payroll is active revision17/authority10. Private proof: `.runtime/ui-quality-lifecycle-proof.json`.

These lifecycle actions used `index-BGrIzm-p.js`. The final change only applies the existing `workspace-tabs` class to events-source navigation. Final static browser readback confirms `index-DPTg4cAy.js`, active revision17 and readiness. Lifecycle actions were not repeated after that class-only change. Browser scope is local Chrome and the in-app browser; this does not establish a broader browser matrix or publicly trusted TLS. The existing human-accepted local certificate warning remains.

## Final gates and source binding

- Focused wiring29, connection/publication26, grants/events19 and member/session14 tests pass.
- Typecheck and final build pass; build4.15seconds. Existing annotation and bundle-size warnings remain.
- Final full web suite:152files,1881passed plus2expected failures,78.59seconds.
- Final JS: `index-DPTg4cAy.js`, SHA256 `e2712cf77d335f8165504dfc6e8bd82c2dd8141a5ab3ce6d8e634041aaaf912c`.
- Final CSS: `index-B6l53l53.css`, SHA256 `7b85051ec740e98bcf51ecec10f6e5ead72591a2269202790b7674eccb4b5dd7`.
- Private source/artifact manifest binds2266selected source files, scope SHA256 `25fbafcd6ea45750b38c70a6997aad00e8397843deee26831d3f65002018cea5`. Its pre-UI copy is retained as `aa9-source-artifact-handoff-before-ui-pass.json`.

The source remains uncommitted WIP on `feature/app-access`, baseline HEAD `5c1093e87db358cab06080cc272321a2e074802f`. Shipping API/node/proxy artifacts retain their prior provenance. This pass has no push, PR, AWS, SCP or deployment actions. Protected production signing/distribution and separately authorized remote-topology proof remain release gates. Earlier local AA-0 through AA-8 acceptance remains9/9; AA-9 per-app MFA remains deferred.

## Domain settings follow-up — 2026-10-04

The follow-up keeps the existing Settings rail, section container, theme, fields and buttons. `Settings → App Access domains` is limited to verified control-plane administrators; ordinary organization administrators and members cannot change deployment-wide addresses. The form saves a versioned portal URL and application base domain. DNS records, TLS certificates and identity-provider redirect registrations remain customer-managed; the form labels format validation separately from external readiness.

Rendered checks on the local development console changed the application base from `apps.127.0.0.1.nip.io` to the portal parent `console.127.0.0.1.sslip.io`, saved it and loaded it again. The create form then displayed `https://demo.console.127.0.0.1.sslip.io` for prefix `demo`. The existing published Payroll hostname and revision17 remained unchanged. No new application was published for this check. The original base was restored through the same Settings form afterwards. Screenshots are `/private/tmp/app-access-domains-reference-settings.png`, `/private/tmp/app-access-domains-prefix-local.png` and `/private/tmp/app-access-domains-settings-final.png`.

The in-app browser checks used the local HTTP development console. Separate tests use verified TLS; this browser evidence does not establish a publicly trusted certificate or a live customer-domain deployment. Vite now preserves the browser Host rather than replacing it with the API target: correct-origin logout returns204 and an unrelated origin remains403.

Qualification includes the full web suite (154files,1941passed and2existing expected failures), typecheck and production build; the later Vite forwarding regression has2passing tests and a passing typecheck. Domain persistence, optimistic concurrency, permissions, published-host preservation and rollback protection passed with isolated PostgreSQL. HTTP origin checks cover DNS and IP addresses with default and non-default ports. Signed-IdP/PostgreSQL tests and HTTP callback/cookie tests verify that an SSO flow retains its original callback and final landing when the configured portal changes mid-login. Login/logout passes with its real database dependency.

The full app-proxy race suite and30repetitions of the expiry regression pass. The expiry correction closes the underlying socket when an active authorization lease expires, avoiding a blocking TLS shutdown; it keeps the original deadline assertion and completed-response guard. These follow-up changes remain local and do not update the AWS control plane or sandbox deployment.

Final API source passes `go test ./...` (log `/private/tmp/app-access-final-api-h4zthx86/full-api.log`). The owned paid API fixture and proxy were refreshed with backups; database state and retained account/config/certificate hashes remained unchanged. Browser reload after the API restart still reads saved settings. Against both refreshed binaries, an independent member login and fresh launch returned through the canonical console and reached Payroll with verified TLS1.3, SNI and the retained test CA. Content, assets, form, redirect, application cookie and session metadata checks pass; consumed launch-code replay returns403. Private protocol evidence is `tests/app-access-local/.runtime/domain-expiry-final-launch-20261004.log`. This is local protocol integration proof, separate from rendered browser and signed-IdP tests.

Final enterprise HTTP/SSO suites also pass. The refreshed API binary passed isolated PostgreSQL login/logout, domain authorization/CSRF and callback-landing checks, plus the signed-IdP SSO test. Logs are retained alongside the final API log. Independent review found no additional actionable auth/domain/proxy/UI issues. The browser-only unsaved prefix-test form was discarded; no persisted app was removed.
