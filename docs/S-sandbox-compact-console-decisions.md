# Compact Sandbox console

Baseline: f36fa8028fadb96453454ebddca08e8a3c929d90. User requests a compact layered console instead of a full scroll of repeated cards. Isolated UI worktree; runtime checkout, API, OpenAPI, deployment and provisioning are outside scope.

Decisions locked by this request:
- One shared workspace surface: narrow header/navigation/status, dense responsive inventory rows, small empty state. No onboarding hero or repeated metric cards.
- Environment and candidate information remains truthful and reachable through compact disclosures. Detailed measurements, provenance, test bounds and compatibility remain available without dominating inventory.
- Private Skills become searchable rows. Popup editor/import/preview, revision and deletion semantics remain unchanged.
- Setup controls keep their real CAS endpoints, permissions and activation prerequisites. Readiness/settings/catalog share one surface with compact rows and disclosure details.
- Keep current dedicated detail route and full pinned SSH/lifecycle behavior. A new drawer route/state machine is deferred; density applies to the existing route.
- Refresh remains explicit; lifetime calculation already updates once per minute. No fabricated telemetry, polling or runtime qualification.
- Genuine brand assets, keyboard focus, responsive layouts and reduced-motion preserved.

Validation: affected interaction tests, full web suite, typecheck/build and actual local Chromium visual QA at normal desktop/mobile viewport, including scroll container lower content. Fixture QA substitutes for authenticated live review; parent owns live browser review and deployment. No screenshot upload without separate authorization for this new set.
