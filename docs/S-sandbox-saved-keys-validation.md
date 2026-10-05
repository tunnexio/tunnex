# Saved public SSH keys: local source validation

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

Worktree: `<preserved-local-worktree>`.
Branch: `story/sandbox-saved-public-keys`; committed baseline: `9b5d17d`.
Local `main` was stale at `f8544bf`, so this branch was aligned to the explicitly requested committed foundation baseline. Original checkout and its branch were not edited.

## Delivered

Migration 0179 creates account-owned named public keys, unique account/fingerprint identity and a partial unique default index. Existing public key parser validates allowed algorithms, excludes private material/options/certificates and strips comments. Account row locking serializes save/default/delete and the 50-key account limit. All mutations and reads bind the authenticated human account server-side using existing sandbox organization permissions; machine and agent principals are refused.

Organization routes under `/saved-ssh-keys`: GET list, POST save; `/{keyId}` DELETE; `/{keyId}/default` PUT. First saved key defaults; deleting a default leaves no default. Sandbox creation uses public-key snapshots through the existing immutable create contract. Existing access never changes through registry edits. No caller-supplied ownership or private keys.

Compact, scrollable saved-key picker shows names/fingerprints/default, selection, save, remove, and default controls. Manual multiline input remains available, including during registry failures. Selection survives returning to access; delayed loads preserve input; changing default leaves the current selection intact.

## Passed

- Pinned oapi-codegen v2.4.1 generated API and CLI Go contracts; openapi-typescript 7.4.4 generated shared TS contract.
- `GOFLAGS=-mod=readonly GOCACHE=<preserved-local-artifact> go test ./internal/sandboxes ./internal/http -run 'TestSavedSSH|TestSandboxAPI|TestSandboxGenerated'`, repeated with `-tags enterprise`.
- `go build ./...` and `go build -tags enterprise ./...` in apps/api, same readonly/cache flags.
- TypeScript `tsc -b apps/web` and final `tsc --noEmit -p apps/web/tsconfig.json`.
- Focused picker and sandbox UI: 31 tests passed; component style census passed after removing an Input width override.
- Production Vite build from apps/web passed. Existing large-chunk warnings remain.
- `git diff --check` passed.

## Limits and failures

Initial run skipped PostgreSQL tests because `TUNNEX_TEST_DATABASE_URL` was unset. Follow-up inspection recovered the existing documented local disposable fixture; the tests now pass as recorded below. No live database was accessed.

Full web suite before the style fix: 145 files passed, 5 failed; 1834 tests passed, 6 failed, 2 expected failures. The slice's Input override was fixed and its style test passed on rerun. Two unrelated source checks still fail: sandbox-connection.test.ts omits the shared comment stripper; existing connection copy in Sandboxes.tsx contains an em dash. Both offending content locations are unchanged from baseline. AI provider onboarding had a timeout and a mock call count mismatch; Kubernetes wiring could not find View services. Those files are unchanged. Follow-up archived-baseline execution is recorded below.

Full HTTP suite cannot run inside the sandbox because an unrelated AI gateway test opens a TCP listener. Focused affected tests run without listeners and passed. Both API editions build.

Initial inspection found no callable browser control tool. Follow-up inspection recovered the existing local Playwright harness and cached Chromium; actual rendered synthetic QA now passes as recorded below. Synthetic local proof remains a substitute for live proof; no live keys were imported, no infrastructure provisioned, no access changed, no deployment or push performed.

Installed validation dependencies only inside this worktree using frozen lockfile and ignored install scripts. System Node20/pnpm9 did not meet repository engines; direct validation used available Node22.23.2 (repository wants Node24.21.x) and pinned pnpm10.34.5 for installation. Lockfile unchanged. Full repository Docker generation/migration/gate targets were not run.


## Follow-up verification: recovered local capabilities

The earlier blockers were discovery gaps, not absent capabilities. Prior compact/premium QA documentation identifies `<preserved-local-artifact>`, which contains Playwright, Node 24.21.0 and cached Chromium 1243. Prior persistent-runtime documentation identifies the dedicated existing `tunnex-sandbox-feature-db-20261002` container, image `postgres:17-alpine`, bound only to `127.0.0.1:55482`. Initial database skips were solely the missing test environment variable. No new credentials or PostgreSQL service was created.

Database container identity/image/loopback binding were asserted before using its existing configured local authentication. The test URL was constructed only in subprocess memory, never printed or persisted. `testpostgres.New` creates and drops an independently named migrated database per test; the preexisting fixture service stays unchanged.

Command: `GOFLAGS=-mod=readonly GOCACHE=<preserved-local-artifact> GOMAXPROCS=2 go test -p 1 -count=1 ./internal/sandboxes -run 'TestSavedSSHKeyPostgres|TestSSHPublicKeysPostgres' -v`, repeated with `-tags enterprise`.

Final results: open 13.081s PASS, enterprise 11.645s PASS. Tests cover migration 0179 on fresh fixture databases; down/up migration round trip; cross-owner list/default/delete isolation; account-local duplicate fingerprint handling; default deletion with no replacement; immutable sandbox public-key snapshots; twenty concurrent default updates with exactly one final default; and the 50-key registry bound. No integration tests in this command skipped. Local runner: `<preserved-local-artifact>`; output: `<preserved-local-artifact>`.

Actual Chromium QA: built source served only on `127.0.0.1:5189`, all `/api/**` requests intercepted with synthetic responses. No authenticated live endpoint was called. `<preserved-local-artifact>` adapted the prior local harness, using Node 24.21.0 and existing Chromium 1243. A harness-only heading mismatch (Private skills vs actual Skills) was corrected before the successful run.

Passed at desktop 1440x1000 and mobile 390x844: selected default; making a new default preserves current selection; deleting default leaves none; duplicate error; empty registry; save-and-select; Back restores selections; registry failure preserves manual compatibility and advances to Skills; document horizontal overflow checks; bounded scrolling with 20 synthetic keys; long-name/fingerprint wrapping. No page errors. Screenshot pixels inspected for desktop default, mobile add-key, mobile 20-key list, and mobile registry failure. Local-only evidence: `<preserved-local-artifact>` and paired PNGs in that directory. No screenshot upload or sharing.

The discovered repository-compatible Node 24.21.0 also passed final TypeScript checking and production build (6.92s); production output is `<preserved-local-artifact>`. This closes the earlier Node version limitation for typecheck/build and QA.

Baseline comparison used a `git archive 9b5d17d` source copy under `<preserved-local-artifact>`, with identical dependency binaries. Both source-census failures reproduced: sandbox-connection.test.ts lacks the comment stripper; Sandboxes.tsx existing connection copy contains an em dash. AI-provider and Kubernetes suites passed on baseline under Node 24.21.0, `--maxWorkers=2`: 110 tests, 52.05s. Their earlier full-suite failures therefore were not reproduced under controlled supported-runtime settings; no unrelated source was repaired.

The same controlled AI-provider/Kubernetes comparison on this branch passed all 110 tests in 22.83s. Results: `<preserved-local-artifact>`; baseline results: `<preserved-local-artifact>`. These runs establish that the earlier three component failures are not reproducible in either tree under matched supported-runtime settings; the original full-suite result remains recorded and is not represented as green.
