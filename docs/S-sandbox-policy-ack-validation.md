# Prompt policy acknowledgement validation

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

Source content tip: `e52b0eaf19a55dcb70e15d6ab6aa21f4ecc9ecec` on
`story/sandbox-readiness-diagnostic-live`, based on `6adb6994dcde54bb1d159a7d0d08d22ec54ea7c0`.
Decision-first commit: `f843093`. Worktree:
`<preserved-local-worktree>`.

The node now queues a nonblocking, coalesced notification when inline policy
application or periodic recovery changes actual applied status/capabilities.
Unchanged outcomes stay quiet. Its existing single reporter snapshots actual
state, preserves endpoint-generation acceptance and the periodic cadence, and
retries every failed send with the existing one-to-30-second bounded backoff.
The API wakes its existing sandbox worker only after a valid authenticated
report persists successfully. Canonical readiness checks are unchanged.

All checks used cached Go1.26.8, `GOPROXY=off`, `GOSUMDB=off`,
`GOTOOLCHAIN=local`, and `GOFLAGS=-mod=readonly`.

| Focused check | Result |
| --- | --- |
| Native explicit-file reporter helper tests, `-race -count=1` | PASS13 top-level tests,1.625s; covers prompt wake, cadence, steady-state retry/reset/cap, interrupted backoff, serial in-flight sends/latest queued state, cancellation, actual outcome changes/failures/recovery/no-op/coalescing. Worker tool outputs retain the result; no standalone log was created. |
| Same helpers, `go vet` | PASS. |
| Supported Linux node tests, including two existing stale endpoint-generation rejection tests | PASS15 top-level /23 total PASS records, no skips; `<preserved-local-artifact>`. |
| Existing Linux egress last-good hash/apply-failure and unsupported-policy refusal tests | PASS2; `<preserved-local-artifact>`. |
| Real PostgreSQL report ingress/notification and existing health-field contract, `-race`, open edition | PASS21 records, no skips/race warnings,5.995s; `<preserved-local-artifact>`. |
| Same report tests, enterprise edition | PASS21 records, no skips/race warnings,5.212s; `<preserved-local-artifact>`. |
| Existing exact-hash/org/health/freshness readiness rejection cases, `-race`, open edition | PASS26 records, no skips/race warnings,2.766s; `<preserved-local-artifact>`. |
| Same readiness cases, enterprise edition | PASS26 records, no skips/race warnings,2.102s; `<preserved-local-artifact>`. |
| Changed API handler/server `go vet`, both editions; supported Linux node command vet | PASS; `<preserved-local-artifact>,enterprise}-vet.log`, `<preserved-local-artifact>`. |
| Linux AMD64 API server builds, both editions, and node command build | PASS; local artifacts listed below. |
| Whitespace check | PASS. |

Report integration checks prove persistence before callback/204, certificate-
selected identity despite spoofed cross-org body fields, server-owned report
time, untouched other node, nil callback compatibility, and no notification or
evidence change after decoding, validation, authentication, or actual storage
failure. Each uses a fresh migrated local database. Only the existing local
fixture `tunnex-sandbox-feature-db-20261002` on127.0.0.1:55482 was started; it
was restored to its original stopped state and verified `exited`.

Linux test binaries ran in the already cached `golang:1.26.8-alpine` image with
no network, read-only root filesystem, all capabilities dropped, and
no-new-privileges. No packages or dependencies were added. A native whole
`cmd/agent` test invocation failed on existing macOS/Linux-only symbol/stub
gaps. The focused portable helper race tests and supported Linux package tests,
build, and vet passed; no platform-support work was folded into this fix.

Local undeployed Linux AMD64 artifacts:

- `<preserved-local-artifact>`: SHA256 `8bed92a2f947ce3e8af02702aaef865f4b9b9236de7b9f42a96f0c82c4613bde`.
- `<preserved-local-artifact>`: SHA256 `700e4d94c677b4d0c55c6f7c3d463c7d5a17d7302c7f334d65158222b4322e04`.
- `<preserved-local-artifact>`: SHA256 `0aa97b6626e30da40b5f40aab49649124fae8a4dc951e0a6b2551a10b53b8aa9`.

No live trial, deployment, push, merge, UI changes, credentials/access changes,
or TTL change occurred. Full monorepo gates and browser QA were not run for
this narrow source-only patch. Local tests are substitutes for future separately
authorized wire timing, not a measured startup improvement or diagnosis of the
retired trial's exact gateway apply/report timing. An in-flight HTTP report can
still delay a queued wake; its existing timeout and peer telemetry cadence are
unchanged. First-Ready usable lifetime remains a separate known requirement;
the current creation-based900-second contract is unchanged.
