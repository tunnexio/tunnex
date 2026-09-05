# Desktop cleanup local validation

Date: 2026-09-05. Branch: `TUNNEX-CLIENT-CLEANUP`, based on main `6a4ae8c5` (PR #52). Decisions were committed first at `79bf04a1`.

## Result

Removed 162 tracked desktop-only files: Electron shell/packaging, native privilege helper, desktop renderer/bridge/view-models/tests and four macOS development/uninstall/spike scripts. Retired their workspace, devcontainer, dependency-bot, ownership, Makefile and workflow wiring. Server image publication and release assets now depend only on retained jobs. Current documentation points desktop work and downloads to `tunnexio/tunnex-client`.

Compared all 162 deleted files with standalone commit `7c0edcf6606f747d705d02433f8ac42becdfbc40`: 157 identical, four understood differences (package version, CSP test assertion, newer macOS resolver implementation/test), and one missing historical privileged-install spike. No shipped implementation was missing from the destination. The standalone checkout and published release were not changed.

## Checks executed

Local web checks used Node 25.9.0 and the repository-pinned pnpm 9.12.0. CI uses Node 20; local results do not claim a CI run.

| Check | Result |
| --- | --- |
| Baseline web typecheck, tests, build before deletion | Passed: 106 test files, 1,331 tests |
| Reduced workspace frozen install | Passed; three workspace projects |
| Lockfile comparison | Retained importers and dependency versions unchanged; 348 obsolete package entries removed; no new package entries |
| Web typecheck, tests, build after deletion | Passed: 104 test files, 1,263 tests. The removed cases covered the retired desktop renderer/model and Electron-entry adoption. |
| Production artifact inspection | Only `index.html` emitted; every referenced entry asset exists; no `client-*` bundle |
| API Linux build, open and enterprise editions | Both passed using Go 1.25.13, `GOFLAGS=-mod=readonly`, `CGO_ENABLED=0` |
| CLI, node and operator Linux builds | All passed with the same toolchain and readonly module mode |
| Installer provenance and signed-release contracts | Passed |
| Shell fresh-host and Windows PowerShell bootstrap contracts | Both passed against command stubs; no installation performed |
| Upgrade, upgrade-apply, upgrade-runner and public-URL contracts | All passed against stubs/temporary files |
| Go toolchain pin agreement | Passed for all retained modules and build sites |
| Workflow graph and actionlint 1.7.7 | Passed for all workflows; optional shellcheck/pyflakes integrations disabled because those tools are unavailable |
| Retained-tree comparison | API, CLI, node, operator, OpenAPI and shared packages byte-identical to baseline; control-plane installer scripts and deployment compose also byte-identical |
| Whitespace check | `git diff --check` passed |

The first post-removal web run caught a census import requirement. The dashboard route census now reads `App.tsx` through the existing comment stripper, and the full web suite was rerun successfully. The pre-existing Vite large-chunk warning and React Router future-flag warnings remain.

Equivalent Go build commands ran separately from each module directory:

```sh
GOTOOLCHAIN=go1.25.13 GOFLAGS=-mod=readonly GOOS=linux CGO_ENABLED=0 go build ./...
# Additionally, from apps/api:
GOTOOLCHAIN=go1.25.13 GOFLAGS=-mod=readonly GOOS=linux CGO_ENABLED=0 go build -tags enterprise ./...
```

## Remaining prerequisites

Docker is unavailable at the configured Colima socket. The full container-based `make generate-check`, migration/API integration tests, node data-plane tests and live box-walk were not run. No database, installed application, privileged helper, network interface or deployment was changed. These local checks are a substitute, not completion of those gates; run them on an isolated stack and perform an installed-client compatibility walk before merge.

The active main ruleset still requires the three retired desktop contexts listed in [the decision paper](S-client-cleanup-decisions.md#required-check-migration-before-merge). Removing exactly those requirements needs explicit approval before merge. All other required checks and review protections remain. No push, PR, merge, or ruleset mutation was performed.

## Independent review

Two independent, read-only review passes compared the completed cleanup with baseline `6a4ae8c5`:

- Application/shared-contract review: no actionable findings. Confirmed destination coverage, unchanged retained APIs and browser authentication, desktop-only CSS ownership and absence of dangling runtime imports.
- CI/workspace review: no actionable findings. Confirmed release dependency/artifact wiring, retained scan coverage, unchanged retained lockfile versions/integrity and removal of active references to retired paths.

Both reviews were limited to source/configuration/dependency evidence; neither claims hosted CI or a live installed-client compatibility walk. The known ruleset prerequisite remains outstanding.
