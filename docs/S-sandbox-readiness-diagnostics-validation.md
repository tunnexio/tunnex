# Sandbox readiness diagnostics validation

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

Source-only refinement on `story/sandbox-supervisor-layout`, tested with cached Go 1.26.8 on Darwin ARM64. No deployment, new product sandbox, live lease change or protection change followed. The existing user SSH key and selected-skills product work are unchanged by this diagnostic patch.

## Result

The focused readiness/initial-launch/Resume suites passed with `-race -count=1 -p 1` in community and enterprise editions, with zero skips. Each edition produced 57 PASS records, including subtests. The server package compiled and has no tests. Community took 129.914 seconds including compilation (sandbox package 49.143 seconds); enterprise took 50.194 seconds including compilation (sandbox package 47.646 seconds). The separate non-policy log-shape regression passed in both editions (package durations 2.279 and 1.838 seconds). `gofmt -l` and `git diff --check` were clean.

Tests used only the existing task-owned PostgreSQL fixture `tunnex-sandbox-feature-db-20261002`, `postgres:17-alpine`, bound to `127.0.0.1:55482`; `testpostgres` creates and drops separate migrated databases. Its existing trust-authentication configuration was retained. The initial harness rejected its absent password before invoking tests; the corrected harness supports that existing configuration and restores the originally stopped fixture in a `finally` block. No private credential files were read, printed or saved. Offline module resolution used `GOPROXY=off`, `GOSUMDB=off` and `GOFLAGS=-mod=readonly`; no dependency installation occurred.

The [sanitized validation receipt](S-sandbox-pr-validation.md) records exact commands and results. Detailed sanitized test logs and the local fixture runner remain in the task's `S-sandbox-pr-validation.md` directory outside this worktree.

## Behavior covered

- An actual Ready → Stop → Resume fixture preserves `readiness-policy-before`, `errors.Is(ErrDisabled)`, the current generation, Starting state and absent connection when policy proof is missing. No terminal probe follows that rejection.
- Hash mismatch, unknown/missing desired hash, missing health/report, stale/future reports, apply failure, invalid/foreign/duplicate nodes and missing gateway still deny Ready. Existing local advisory-site health remains permitted without masking apply failure. Selected-node SQL, predicate order and freshness boundaries are unchanged.
- Serialized structured logs exclude malicious hash, capability, unknown-kind and raw-cause sentinels. Nested errors retain `errors.Is`/`errors.As` behavior. Unknown facts remain distinguishable from known zero values; invalid organization evidence omits node identity. Non-policy retry logs retain their existing shape.

## Evidence required for a later approved trial

The new `sandbox_runtime_reconcile_pending` attributes expose the inner stage, fixed `policy_gate_reason`, binding mode, eligible bound node ID, known-health/report flags, normalized health kind, push-known/hash-equality booleans, report age, total gate duration and policy-health reader duration. Hash values, policy contents, raw errors and credentials remain absent. Health-reader duration is not a pure compiler timer, and `policy_push_known=false` alone cannot distinguish compilation failure from missing policy/topology evidence.

For the next separately approved trial, retain these failure observations for each construction-bound terminal/runtime gateway alongside canonical Create/Resume intent, provider start, bootstrap consumption, first policy proof, first private pinned-SSH success and Ready timestamps. Use the same runtime/spec/image/resource identity in the record. Check the unchanged readiness conditions, original hard expiry, offline enforcement and confirmed retirement separately. This should identify the blocking predicate; the retired trial's old stage-only logs cannot recover it. No new trial or deployment is implied by this source commit.

Full-repository tests, new UI QA, native execution of the diagnostic build and statistical latency benchmarks were not run for this narrow patch. The observed startup delay remains unresolved. The [usable-lifetime proposal](S-sandbox-usable-lifetime-decisions.md) is design only; provisioning limits, total resource authority and Ready/actor-ack publication ordering remain open before implementation.
