# Compact Sandbox console validation

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

## Scope and behavior

Isolated branch `ui/sandbox-compact-console` starts at clean committed runtime/UI baseline `f36fa8028fadb96453454ebddca08e8a3c929d90`. No edits to the active runtime checkout, API/OpenAPI/generated contracts, provisioning, gates or deployment. Decision paper was committed before UI edits.

The inventory now has one shared console surface: slim header/navigation/count strip, collapsed unavailable-reason notice with an admin Setup action, responsive workspace rows, collapsed catalog/profile measurements, and a small local-tool strip. Empty inventory is a short row rather than an artwork/tutorial hero. All errors, missing runtime/catalog and stale or expired private connections keep their real behavior. There is no telemetry, background API polling or readiness simulation; Refresh fetches status and the existing lifetime clock remains local.

Skills uses searchable/sortable rows with the existing popup editor, local import, inert Markdown preview, owner privacy and immutable revisions. Setup uses one grouped surface with real readiness, CAS settings and publication controls; the activation prerequisites, unpublish/deletion confirmations and warnings remain intact. Details use a single surface with SSH and metadata plus collapsed network access. All real brand/provider assets are preserved.

Copy review removed tutorial/marketing paragraphs and repeated qualification prose. Architecture, measurements, provenance and test bounds remain accessible through native keyboard-operable disclosures. Destructive/privacy warnings remain visible where actions occur. The wizard uses one environment selector and selected resources; a sole approved configuration defaults only when there is no explicit template query. It never selects candidate profiles, invents network scope or skips final review.

## Checks

Toolchain: isolated Node24.21.0 and pnpm10.34.5. Workspace dependencies resolve to this checkout's generated shared types; reused dependency bytes do not change source contracts.

- Full standard web suite with `--maxWorkers=2`:148 files passed;1,822 tests passed and2 expected failures (1,824 total),137.00s.
- After final SSH copy and runtime compatibility label refinements: all40 affected Sandbox/Skills/Setup/profile tests passed. Full suite above preceded only these display refinements; runtime mismatch is distinguished from absent runtime, with a focused regression test.
- Typecheck passed; final production build (`tsc -b && vite build`) passed. Existing large-bundle warning remains.
- `git diff --check` passed.

Local logs: `<preserved-local-artifact>,focused,types,build,qa}.log`.

## Actual visual QA and density evidence

The parent inspected the authenticated live page at1180×760: large unavailable panel, first workspace card near y620 and cut off, then a separate empty-runtime panel and outer candidate panel containing three cards with repeated qualification prose. No live browser/Computer Use tool is exposed on this Mac executor. Parent's live findings were used with actual local Chromium rendering of the exact current source and synthetic API fixtures; local QA is not a production/live runtime proof.

Normal desktop viewport1180×760 and mobile390×844. Captures keep the real viewport and scroll the application's actual `main` container; no CSS height/overflow expansion was used for this density evidence.

- Unavailable/expired fixture default: first desktop workspace row y398–460; inventory, collapsed catalog and footer all visible without scrolling. The equivalent mobile row y372–520; full default surface ends above the bottom of the844px viewport.
- Eight-row desktop fixture: rows about63px high, six complete workspace rows visible before scrolling. Eight mobile rows remain compact responsive rows; final row/catalog/footer inspected at actual scrollTop910.
- Default Workspaces/Skills/Setup have zero `.sb-runtime-card` elements. Default unavailable page has85 visible words within `main`; empty69, two-skill list77, Setup92. These counts include labels/values/navigation; detailed instructions stay behind disclosures.
- Expanded catalog, profile/architecture measurements, provenance/test bounds, lower Setup/candidate sections and detail connection/lifecycle were inspected from normal scroll positions. No horizontal document overflow in any captured state and no page errors.
- Wizard tested through every step, Back draft persistence, only-final-create, duplicate suppression, focus trap, Escape/Cancel/browser Back; Skills search/no-results, local import, preview, retained draft, save/new revision and delete cancellation/confirmation all passed. Reduced-motion dialog animation is `none`.

All local QA inputs are synthetic: intercepted auth/org/inventory/runtime/profile/skills endpoints, dummy key and network values, no actual user/org data. No new screenshots were uploaded or publicly shared. Screenshots and JSON are local under `<preserved-local-worktree>`.

Useful previews: `desktop-live-shape.png`, `desktop-catalog-bottom.png`, `desktop-skills.png`, `desktop-setup.png`, `wizard-environment.png`, `wizard-review.png`, `mobile-live-shape.png`, `mobile-many-bottom.png`, `mobile-catalog-bottom.png`, `mobile-measurements-bottom.png`, `mobile-setup-candidates-bottom.png`, `mobile-skill-editor.png`. `qa-results.json` records fixture isolation, errors, synthetic mutations, exact scroll/row/card/word metrics and reduced-motion result.

Integration, authenticated live review, runtime qualification and deployment stay with the parent/runtime owner. No push or deployment was performed here.

## Production-preview confirmation

While stopping the development server, its local serving allowlist was found to deny font bytes from the reused dependency path. This was a preview-environment issue, not a built artifact failure. All final screenshots were refreshed by rerunning the entire browser interaction/scroll matrix against the production bundle served by `vite preview`. The runner awaited `document.fonts.ready`, asserted loaded Inter Variable and JetBrains Mono Variable, and recorded zero failed non-API asset requests and zero page errors. Desktop row metrics and word counts remained unchanged; the production font reduced the mobile unavailable row to y372–520 (15px shorter than the dev fallback rendering). `qa-results.json` now explicitly records `productionBundle:true`, `fontFaces` and `assetErrors:[]`. Final production pixels were inspected. No product source changed during this correction.
