# Same-PR CI performance qualification

User approved this expansion in PR #59 on 2026-09-06. No merge or release.

## Baseline observations

Run 34025271682 spent 4m25s in Kubernetes chart contracts before codegen or
API/web/tooling could start; that run was later cancelled and is not green proof.
Run 34025665297 waited approximately 3m40s before its gates runner started.
The old workflow serialized all gate work, disabled chart Go caching, and did not
mount reusable Go module/compiler caches into disposable test containers.

## Implementation and safety

- Cheap fail-closed scope classification precedes independent codegen, API edition,
  tooling and web lanes; contract tests run independently and unconditionally.
- API open/enterprise run on separate runners with explicit edition/run/attempt
  Compose projects. Package tests remain serial within each database.
- Existing local test-editions still runs both editions; each edition now explicitly
  builds as well as tests. API/tooling tests force count=1 despite compiler caching.
- Optional Docker Go caches have platform/toolchain/dependency/lane-scoped CI keys.
  No database, secrets or test fixtures are cached. Local cache defaults unchanged.
- Charts share the runner compiler cache across packaging invocations; pnpm caches
  its dependency store, not installed node_modules.
- Required gates is an always-running, fail-closed aggregator. Missing outputs/jobs,
  failures, cancellation and unexplained skips are rejected. Existing downstream
  outputs and release prerequisites are retained; no protection changes needed.

## Verified before push

- 42 aggregation/wiring regressions pass, including failure/cancellation/missing
  lanes, conditional skips, malformed scope, actual CLI refusal and matrix cache keys.
- actionlint 1.7.12 passes; git diff --check passes.
- Local gate-cache isolation, signed-main release and release source-ref contracts pass.
- Full real Helm/chart contract target passes with a shared compiler cache.
- Two independent read-only reviews completed; no remaining actionable findings
  in reviewed scopes. Initial cache-writer collision was fixed before final review.

The full local cached API/build/node/operator/CLI chain and codegen rerun were
started in explicit isolated lanes. Their completion and exact pushed-head CI
results will be reported in PR #59; this document does not predeclare them green.
The 8–12 minute warm-cache target remains an estimate until measured. Compare
queue time separately from execution and report cold versus warm cache behavior.
Existing test resources are retained; no default Compose project or cloud changes.
