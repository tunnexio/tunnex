# Desktop client ownership cleanup

Status: local implementation on `TUNNEX-CLIENT-CLEANUP`; no push, merge, or repository-settings change authorized by this task.

## Evidence and scope

The user explicitly requested removing the desktop client code from `tunnex` after moving the working application to `tunnexio/tunnex-client`.

- Source baseline: `tunnexio/tunnex` main `6a4ae8c5` (PR #52), verified from Git. The older story checkpoint in PLAN.md is historical and does not identify this cleanup branch.
- Destination inspected at `7c0edcf6606f747d705d02433f8ac42becdfbc40`, with release `v0.1.1` published 2026-09-02. Its release has macOS PKG, Windows EXE, and SHA256SUMS assets.
- Of 160 source/build/script files compared, 155 are identical. The standalone package version differs; its macOS resolver and regression test contain a newer permissions fix. One CSP test assertion differs but the CSP implementation is identical. Only the historical privileged-install spike is absent there; it is a development experiment, not a shipped component.
- Standalone CI builds/tests the helper and packages both platforms. Its renderer, shared snapshots, native vendor assets, and helper are local to that repository; it does not require a checkout of this repository.
- No retained Go module imports `apps/helper` or `apps/client`. The dashboard entry already uses browser routing and relative API transport independently of the Electron bridge.

## Decisions

| Item | Disposition |
| --- | --- |
| Desktop shell and helper ownership | Locked: remove `apps/client` and `apps/helper` from this repository. The user authorized this contraction; their active home is `tunnexio/tunnex-client`. |
| Desktop renderer | Locked: remove `client.html`, its bootstrap, `src/client`, bridge/view-model modules, desktop-only tests and connect-orb CSS. Build the dashboard through `index.html` only. |
| Shared and server contracts | Locked: retain `apps/api`, `apps/node`, `apps/operator`, `apps/cli`, OpenAPI, generated types, shared tokens/branding, browser authentication, CLI authorization, CORS, device credentials, posture, routes and gateway compatibility. No API, schema, database, or protocol migration. |
| Installation and release | Locked: retain Linux/macOS/Windows control-plane installers and headless CLI releases. Retire only Electron packaging and helper build/scanning jobs; remove the server-release dependency on desktop packaging. |
| Development wiring | Locked: remove desktop workspace dependencies, helper Make targets, ownership/dependency-bot entries and desktop install/uninstall/spike scripts. Regenerate the lockfile with the pinned pnpm 9.12.0. |
| Documentation and attribution | Locked: redirect current desktop ownership/build/security guidance to the separate repository. Preserve historical decision papers, design references, walk evidence and third-party notices. Mark the design census desktop surface as absorbed by that named repository. |
| Required checks | Local workflow retirement is part of cleanup. The remote ruleset change is deferred to explicit approval before this cleanup merges; see the exact prerequisite below. Do not replace retired checks with success-only jobs. |
| Existing installations | Locked: this changes repository ownership only. Do not run helper uninstallers or touch installed apps, credentials, resolver files, tunnels, databases, containers or deployment hosts. |

## Required-check migration before merge

On 2026-09-05, active `Protect main` ruleset **20828163** requires three contexts owned by the retiring modules:

- `client (macos-latest)`
- `client (windows-latest)`
- `govulncheck (blocking) (apps/helper)`

Before merging this cleanup, obtain approval to remove exactly those three contexts from that ruleset. Preserve `gates`, dependency review, remaining Go-module scans, gofmt/vet, CodeQL, Trivy, review requirements, linear history, and all other rules. Re-read the ruleset at execution time; do not overwrite concurrent changes. Until then, the local change is reviewable but the PR will be blocked by those missing required contexts. This document does not authorize that external mutation.

## Verification and rollback

1. Capture dashboard baseline typecheck, unit tests and build before removal.
2. Run the same checks after removal and verify a fresh web build emits the dashboard entry without a desktop entry/bundle.
3. Run installer, signed-release and upgrade contracts; lint workflow wiring and ensure retained release dependencies resolve.
4. Check retained runtime directories against the baseline and search active code/configuration for unresolved desktop paths. Run code generation and non-database checks when available; record unavailable gates explicitly.
5. Self-review and independent story-end review. Report findings for disposition before folding review changes.

Runtime compatibility rests on unchanged server/web contracts and the independently owned client source, not a claim that source inspection proves a live tunnel. A fresh installed-client-to-server walk is deferred to the pre-merge compatibility walk; local tests are a substitute until that walk runs.

Rollback before merge: restore the cleanup changes from Git. After merge: revert the cleanup commit(s) through a reviewed PR, restoring desktop source/build wiring; restore the three ruleset contexts if they were retired. No user data rollback or installed-client downgrade is involved.
