# Dev reservation source validation and activation handoff

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

Source `98ec56d78ce837bc97bb1f67292b500105c31795`, branch `codex/persistent-sandbox-catalog`, isolated task-5 worktree. Previous persistent source is `32d934bf9b97e0cd9a9d5ede4cb711cdf7fb3ed3`; reconciled prior validation `8bc135a`, reservation decisions `fa5dd46`. No main checkout edit, push, live read/mutation, deployment, catalog registration, organization enablement or credential/policy grant occurred in this task.

Opt-in `BoundedRuntimeBinding.DevReservation` checks the one exact historical identity/immutable runtime/template/peer/time/device tuple. Protected config requires `PeerStatus`, `LaunchGatewayID` and a physical-cleanup evidence reference. This is an operator attestation to already verified erasure; the source cannot certify an arbitrary evidence string. It never supplies a missing withdrawal/retirement receipt. Pending historical state counts; drift closes admission/start while new-workload cleanup remains possible. Every persistent effect and orchestration entry rejects the historical identity. The org lock orders two-retained/one-nonreservation admission across all creators/templates. Deleted without a binding/retirement receipt remains retained. Genuine historical completion cannot create another reusable position. Setup's optional `runtime_limits` exposes maxima/occupancy/status separately from stored caps2/2. Ordinary persistent caps1/1 and original trial behavior remain. No new migration or CSS/styling change; pinned OpenAPI generation preserves existing lifecycle enum names explicitly to avoid an existing compatibility-alias collision.

## Final checks on source98ec56d

All PostgreSQL tests use separate migrated databases created/dropped by `testpostgres` on the existing disposable local fixture, with credentials consumed only in process memory. Go uses readonly modules, two CPUs (`GOMAXPROCS=2`) and package concurrency1. No broad policy/shared-database/node/monorepo CI run is claimed; prior unchanged policy census/shared-DB limitations remain documented in the persistent validation paper.

| Check | Result |
|---|---|
| Complete `go test -p 1 -count=1 ./internal/sandboxes ./internal/sandboxruntime ./internal/config` | Open PASS161.223/0.753/0.688s; enterprise PASS136.054/0.683/0.592s. Includes reservation, sequential profiles, policy/epoch/TTL/restart/retirement, original trial and scoped-trial regression. |
| Focused reservation | Open PASS16.230s; enterprise reservation + trial/scoped-trial PASS18.940s. |
| Sandbox HTTP tests (`-run '^TestSandbox'`) | Open PASS0.961s; enterprise PASS1.115s. Includes truthful wire limits without fabricated readiness. |
| API `go build -p 1 ./...` both editions; CLI build; affected API vet | PASS. |
| Linuxamd64 worker build; Linuxarm64 sandbox test compilation | PASS. |
| Actual Linux kernel socket UID tests and trial retirement; persistent expiry/restart/cleanup and exact legacy denial | PASS in unprivileged UID10001 offline container, one CPU, 128MiB,32PIDs, read-only root/caps dropped/no-new-privileges. Wrong API and worker UIDs denied. This is source IPC evidence, not native workload or direct Mac qualification. |
| Pinned Go generator2.4.1 + TypeScript generator7.4.4, repeated file hashes | PASS: API/CLI/shared types unchanged on regeneration. |
| TypeScript `tsc --noEmit` | PASS using existing Node24.21.0,1536MiB heap. Initial512MiB cap OOMed; host-default Node20/pnpm9 and missing Mac Rollup were tooling limits, not green checks. |
| Four Sandbox UI suites | PASS41 tests/4files,7.72s. Cached pinned Node24.21.0 Linux container offline,768MiB,512MiB heap,one CPU/worker,96PIDs; existing main dependencies mounted read-only, only task caches writable. |
| Web production bundle (`vite build`) | PASS18.13s in cached offline Node24 container,one CPU,1536MiB heap/2GiB container; initial512MiB heap was insufficient. Existing dependency comment/chunk-size warnings remain. |
| Formatting and diff check | PASS. |

New focused fixtures cover two concurrent creates/one success; complete synthetic sequential different-profile launch/withdrawal/provider/files/retirement; historical reservation remaining untouched; org-wide stopped/Deleting/Deleted-unretired/missing-binding counts outside the allowlist; immutable config restrictions, wrong status/gateway and missing/drifted reservation proof; drift denying direct/API launch while cleanup/retirement proceeds; genuine historical completion with and without a separate retirement marker still allowing only one workload; exact admin caps/CAS/disablement; historical worker effects and old pin recovery denied. Fixtures use public historical IDs only in disposable databases and synthetic profile/status/gateway/evidence values. They never establish live Ready.

## Historical activation boundary

The original exact-host activation proposal remains outside publication. No activation follows from this validation record. DevReservation is a legacy qualification compatibility mode and is rejected under explicit organization admission. Current deployment controls are documented in the portable runtime decisions and offline installer.

## Current Mac binding amendment (2026-10-04)

Fresh isolated worktree based on committed source `3329b38bcb6c987ba8ebe7b19f68bd7c0540983e`; main verified at `967dfbcd2ce548cd223fc324c450bf21d543f469`. Salvaged after task-5 explicitly stopped and relinquished ownership. Backend patch is unchanged from its completed checks: focused PostgreSQL/Go open 33.839s, enterprise 33.371s; both API builds, vet and Linux amd64 runtime build passed. Source checkpoint also reported TypeScript, 26 UI component tests, 3 shell tests, and Vite build exit0 (33.91s).

Final worktree corrected doubled escapes in the new SSH helper and shell fixture (IPv4 regex, command newlines and printf). Exact final focused `sandboxes.test.tsx` and `sandbox-connection.test.ts` passed: 22 tests, 3.87s, Node24 container with main dependencies read-only and temporary config storage. Local non-database DevReservation unit/RPC regressions passed (0.837s); PostgreSQL cases in this repeat were skipped because no endpoint was supplied, so database validation relies on the stopped source's completed checks above. `git diff --check` passed. No live reads, writes, deployment, push, or accepted-workload retargeting occurred.
