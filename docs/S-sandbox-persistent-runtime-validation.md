# Persistent bounded runtime validation and operator handoff

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

Source branch `codex/persistent-sandbox-catalog`, isolated worktree `<preserved-local-worktree>`, baseline `77e12b9f3e9e1954191b632eaf223753b79bd7f1`.

Decision commit `024e0e2ad305802859b07953163fe94c04345999`; source/test commit `32d934bf9b97e0cd9a9d5ede4cb711cdf7fb3ed3`. The parent retains integration and every live action. This task created no instances, registered no templates, enabled no org, granted no credentials/policies and deployed nothing. The original checkout was never edited; its independent operator continued committing their own evidence.

## Delivered source

- `apps/api/internal/sandboxes/bounded_runtime.go`: absent mode / `trial` preserves the original absolute-deadline, one-template, 128-PID contract. Explicit `persistent` accepts up to four trusted qualified template/config-digest/native-amd64/evidence/PID records, 128 MiB / one CPU, at most 900-second workload TTL and exact org/creator/device/gateway. Qualified means an explicit protected operator attestation for the intended deployment; the source cannot independently certify the contents of an arbitrary evidence reference. No default profile is promoted or registered.
- `store.go`, `setup.go`, `start.go`: admission and Setup count retained workloads, including Deleted records with unfinished worker cleanup. Completed history does not consume the persistent slot. Scope remains empty, the exact current human device must remain on the pinned gateway, normal membership/skill/effective-policy admission remains active, and persistent admin enablement requires quotas 1/1. Settings and publication retain existing permission, CAS and audit behavior. The new local placement check applies only to persistent mode; legacy scoped trials still start with a NULL local-terminal gateway.
- `workspace.go`, new `persistent_worker.go`, `worker_rpc.go`: API grants carry immutable sandbox/profile/TTL identity and current generation. Worker effects reject foreign identities, changed caps/profile/expiry, old generations and completed identities. Network epochs remain separate from original enrollment generation 1. Atomic per-sandbox completed markers follow provider absence, worker network withdrawal/gateway-absence checkpoint and exact asset/control directory removal; restart and lost API acknowledgement recover the same cleanup receipt. Persistent authority survives, while trial retirement still closes the socket permanently.
- `api_orchestrator.go`, `cmd/server/main.go`: dispatch current owned records across allowed templates and ignore completed history. Expiry cleanup advances durable generation before worker authorization. Readiness supports persistent lifetime while retaining the existing UID-authenticated health check, API-owned DB/sealer and canonical policy freshness.
- `cmd/tunnex-sandbox-runtime/main_linux.go`: persistent deployment uses a separately owned `worker/persistent-control` root and an amd64 runtime build; the old `worker/main-control` trial retirement proof remains intact. No automatic directory/config creation or ACL change occurs.
- `internal/sandboxruntime/provider.go`, `provider_test.go`, `assets_test.go`: persistent create checks the actual preloaded OCI config ID, architecture and Linux OS before launch. Fingerprint includes architecture for persistent specs; omitted architecture preserves trial fingerprints. Immutable images retain their own CMD/entrypoint (Alpine Bash versus existing Ubuntu Python); no universal Python wrapper or launch-time installation is introduced. Existing positional test specs were converted to named fields.
- New `persistent_runtime_test.go` supplies synthetic operator attestations explicitly labeled as fixtures; these are never a native or live qualification claim.

No schema/migration, OpenAPI/generated contract, candidate measurement metadata, node helper or UI styling changes were required. The existing network helper already supports exact `--gateway-org-id` binding.

## Local verification

All tests use existing local disposable PostgreSQL `tunnex-sandbox-feature-db-20261002` / loopback 55482. `testpostgres` creates and drops separate migrated fixture databases. Local test DB credentials were consumed in memory without output or persistence. Go runs use `GOFLAGS=-mod=readonly`, `GOMAXPROCS=2`, `-p 1` and a task-local `/tmp` cache. Approved local socket/container access did not change sandbox security settings.

Commands below were executed from `apps/api` with `TUNNEX_TEST_DATABASE_URL` supplied only to local fixtures:

| Check | Result |
|---|---|
| `go test -p 1 -count=1 ./internal/sandboxes ./internal/sandboxruntime ./internal/config` | Passed: 61.914 / 0.362 / 0.261 seconds, before the final scoped-trial review fix. |
| Same complete suites with `-tags enterprise` | Passed: 69.711 / 0.708 / 0.533 seconds, before the final scoped-trial review fix. |
| Final delta: `go test -p 1 -count=1 -run 'TestTrialPostgresScopedStart\|TestPersistent' ./internal/sandboxes ./internal/sandboxruntime` | Passed open: 7.241 / 0.543 seconds; enterprise: 6.981 / 0.307 seconds. Includes the final placement fix and every new persistent test. |
| `go test -p 1 -count=1 -run '^TestSandbox' ./internal/policy` | Passed open 0.275 seconds / enterprise 0.552 seconds. |
| `go build -p 1 ./...`, same with `-tags enterprise` | Passed after final source changes. |
| `go vet -p 1 ./internal/sandboxes ./internal/sandboxruntime ./cmd/server` | Passed after final source changes. |
| Linux amd64 runtime build and sandbox test compilation | Passed. No Linux amd64 live execution is claimed by this source task. |
| Existing Linux `TestWorkerRPCLinuxKernelPeerCredentials`, reentrant ping/trial retirement and persistent RPC identity/expiry/cleanup/crash tests | Passed in native Linux arm64 Docker Desktop, UID10001, network none, read-only root, caps dropped, no-new-privileges, 128 MiB, one CPU, 32 PIDs. Wrong API UID and wrong worker UID were denied; original trial socket closed. |
| `gofmt`, `git diff --check` | Passed. |

Focused proofs cover two sequential different profiles; all four registered synthetic profiles visible/compatible; exact org/owner/device/locality; concurrent quota1; mismatched template/digest/architecture/OS/caps; expired grants; stop and delayed generations; fresh resume epochs without re-enrollment; current canonical ACK failure withholding Ready and retaining Deleting; provider/file cleanup and completed markers; crash between marker publication and slot removal; lost API cleanup acknowledgement; automatic expiry before first effect; stop race before first network activation; admin settings/publication CAS; qualification/socket config admission; original trial lifetime quota and permanent retirement. Existing sandbox suites additionally retain stale ACK, stop race, enrollment, address retention, immutable fingerprints and skill/policy tests.

Independent reviewer identified the scoped-trial placement regression; it was fixed and tested. Parent relayed that the reviewer reread the final guard/test and found no remaining blocker in that reviewed snapshot. This does not substitute for live acceptance or whole-repository CI.

### Broader baseline test limits

An attempted complete `internal/policy` run was not green. Unchanged `TestNodeSetSeedCensus` expects exactly four node-set seed writes while current source has five. The same failure was reproduced by running only that test against the original source checkout, with no edits. Other legacy policy integration tests connect to a migrated shared database; pointing their admin endpoint at the disposable-fixture admin database produced `relation organizations does not exist`. No shared/main database was initialized or changed to accommodate them. Relevant sandbox policy tests passed independently. Whole-monorepo gates, all legacy policy/shared-DB tests, node/web suites and CI are not claimed as executed or green; unrelated UI/node/codegen sources were unchanged.

## Native evidence and honest catalog labels

Parent supplied, and this task read from committed `4ec1934`, `S-sandbox-pr-validation.md`:

| Profile | Exact native amd64 OCI config digest | Verified fixture cap |
|---|---|---|
| Minimal | `sha256:ba91b86b3ffd50880f47d14be0d04b9e6cfaca454435b7fe5ed5bb51cf4b16d5` | 128 MiB / 1 CPU / 64 PIDs / 900-second TTL |
| Python | `sha256:a1ae8007032ccd196d7d52efd62f656190bc24349c3dd7c41e13601907a21994` | same |
| Node | `sha256:0c8afe8d5f8c8bca193dc496dc9f82438e6db72cedb07360a72a6f15f280c6fb` | same |
| Existing Ubuntu | `sha256:956864613a2e5356b9da8afe8a7ceef90c5cdcc0bca911957df98fb59f4914f1` | Separate historical 128 MiB / 1 CPU / 128-PID evidence; 64-PID compatibility is not inferred. |

The Alpine receipt records SSH UID1001, exit37, files/wrong-pin rejection, stop/resume, worker restart with fresh Ready, natural TTL Deleted generation6 and Finish; final zero owned workload/credential/asset/control/namespace FD state and restored fixture schema175/binaries/storage baseline. Ready samples 6.182 / 5.905 / 7.613 seconds exclude preload and are one sample per profile.

These are fixture lifecycle proofs through a gateway proxy. They are not direct creator-device forwarding proofs. Workload AppArmor profile was empty; rootless/seccomp/zero effective capabilities/no-new-privileges/read-only root evidence does not imply AppArmor attachment or complete production security qualification. Existing candidate Docker measurement architecture/emulation/qualification labels remain unchanged. Ubuntu's prior direct Mac SSH proof did not attain canonical Ready; its new TTL/cap deployment needs separate operator disposition and acceptance.

## Historical operator boundary

The original exact-host activation proposal is preserved outside the publishable tree. It supplied no general installation or current activation authority. Immutable identity, canonical cleanup and retirement remain required. Organization admission and the configurable Linux installer supersede the fixed human/device deployment limitation in [the current decisions](S-sandbox-portable-runtime-decisions.md). Historical qualification above applies only to its recorded image and host scope.
