# Sandbox console, creation wizard and private Skills UX

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

UI-only implementation based on committed `22b3329`, isolated branch `ui/sandbox-experience`. No runtime, API, RBAC, policy or deployment changes.

## Final behavior

- Scoped layered dark surfaces, restrained Tunnex red, real mark/wordmark and a CSS spatial launch illustration inspired by a visual inspection of https://www.runpod.io/. No Runpod artwork is copied into the product.
- Workspace/environment cards show actual runtime memory, maximum lifetime, expiry/remaining lifetime, status and permitted scopes. CPU/storage are explicitly unspecified because the API exposes neither. Ubuntu identification appears only when the approved template names Ubuntu. Other templates use Tunnex.
- Creation is a four-step Radix modal: environment, access, optional skills, review. `/sandboxes/new` and template deep links open the same wizard over the real inventory. Back preserves keys, scopes, lifetime and selected skill configuration. Template changes clear incompatible selections. Cancel, Escape, close and browser Back restore inventory without writes. Keyboard focus is trapped and moved to the new step; dismissal restores a usable inventory control. The pending request blocks dismissal and duplicate mutation. Double-clicks cannot turn step progression into a launch.
- Only final review submits. Existing public-key validation, normalized public keys, idempotency key reuse, maximum scopes, skill eligibility/configuration and backend availability gates are retained.
- Skills is a private library with real names/descriptions/revisions, search across those fields, sort, separate empty/no-results/error/loading states, and add/import/edit popup. Imported bytes remain local until Save. The editor validates the backend's supported scalar front-matter format, tracks the byte limit and provides a Markdown preview. Raw HTML is skipped and external images are shown as inert references. Save creates a new immutable revision. Existing deletion confirmation and generation guards remain. Current revision ID/digest are visible; earlier revision documents are not fabricated.
- Ready SSH metadata is shown only for a started, ready, unexpired sandbox with a current connection response. Expired/stopped/starting responses do not expose stale connection instructions. Lifecycle gating remains.
- Responsive modal layout, native keyboard interactions, focus states and reduced-motion handling share the same design across workspaces, wizard, detail and skills.

## Checks

Toolchain: Node 24.21.0, pnpm 10.34.5, installed in an isolated `<preserved-local-artifact>` directory. Runtime checkout dependencies were not modified.

- `pnpm --filter @tunnex/web typecheck`: passed.
- `pnpm --filter @tunnex/web test --maxWorkers=2`: 146 files passed; 1,807 tests passed, two expected failures (1,809 total). The unconstrained verify attempt was interrupted after it stalled; the constrained standard test script completed in 87.54 seconds.
- Final affected tests plus screen census: 31 tests passed. Both existing sandbox pages were added to the census's COVERED registry with their actual wiring/failure coverage; ledger is 21 covered / 12 pending / 33 accountable.
- `pnpm --filter @tunnex/web build` (`tsc -b && vite build`): passed. Existing Vite large-chunk warning remains.
- `git diff --check`: passed.

## Actual browser QA

Local Chromium rendered the real application at 1440×1000 and 390×844 using isolated synthetic API fixtures. No real user, organization, session, or production sandbox data was used. API mutation records are synthetic. No screenshots were uploaded.

Checked header launch and browser Back; wizard final-only submission, repeated-click suppression, keyboard focus trap, Escape, Cancel, Back/Next draft/skill persistence; current/starting/expired connection responses; Skills search/no-results, valid local import, editor/preview, create, save new revision, revision identity, canceled deletion and confirmed deletion; mobile layouts and reduced motion. Browser page errors: none. Document horizontal overflow: none in every captured case. Actual rendered pixels were inspected, including separate full-content captures for internally scrolling routes.

Evidence directory: `<preserved-local-worktree>`. `*-full.png` captures expand the local main scroller for full-content inspection; paired ordinary captures preserve the application's actual viewport layout.

Principal screenshots:

- `workspaces-empty.png`, `workspaces-empty-full.png`, `workspaces-unavailable.png`, `workspaces-no-runtime.png`, `workspaces-populated.png`, `workspaces-populated-full.png`, `workspaces-error.png`.
- `wizard-environment.png`, `wizard-access.png`, `wizard-skills.png`, `wizard-review.png`.
- `detail-populated.png`, `detail-populated-full.png`, `detail-starting.png`, `detail-starting-full.png`, `detail-expired.png`, `detail-expired-full.png`.
- `skills-empty.png`, `skills-error.png`, `skills.png`, `skills-full.png`, `skills-search.png`, `skills-no-results.png`.
- `skill-import-write.png`, `skill-import-preview.png`, `skill-created.png`, `skill-revision-identity.png`.
- `mobile-workspaces.png`, `mobile-workspaces-full.png`, `mobile-detail.png`, `mobile-detail-full.png`, `mobile-skills.png`, `mobile-skills-full.png`, `mobile-wizard-environment.png`, `mobile-wizard-access.png`, `mobile-wizard-review.png`, `mobile-skill-editor.png`.

QA runner (local-only): `<preserved-local-artifact>`. Summary and synthetic mutations: `qa/premium/qa-results.json`. Asset provenance: `apps/web/src/assets/sandbox/ATTRIBUTION.md`.

Live integration, user review and deployment remain with the main runtime task. Local fixtures demonstrate presentation/interaction, not live runtime readiness.
