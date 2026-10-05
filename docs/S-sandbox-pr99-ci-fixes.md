# PR #99 CI corrections

## Scope and decisions

The user requested correction of the failing checks on draft PR #99. The
starting source is `11d41654ea12b7045830e25fc2a7d58abd069e74`. Existing source,
worktrees, live services and qualification limits remain preserved.

1. **Release dependency contract — locked:** the release asset job now requires
   `tooling` in addition to image publication, pullability and CLI release. Its
   older literal three-dependency assertion is stale. The corrected contract
   must require all four dependencies; publication guards remain enforced.
2. **Source packaging — locked:** reproduce the Docker checkout refusal and
   correct its exact cause. Preserve source SHA, clean-tree, public inventory,
   architecture and checksum verification. Any Git ownership exception must
   name only the verified mounted source directory, never a wildcard.
3. **Actor socket fixture — locked:** correct the Linux fixture rejection while
   retaining real absent/stopped/unknown/live endpoint recovery assertions and
   socket-path validation. Both editions and actual Linux behavior must pass.
4. **Sandbox fixture cost — locked:** investigate cumulative migration setup at
   the unchanged ten-minute package timeout. A pristine migrated template may
   be reused only to create unique, independently owned test databases. Keep
   historical-version and migration tests independent; retire every owned
   template and child. Do not remove assertions, skip tests or relax the gate.
5. **Producer interoperability prerequisite — locked:** the API test container
   must provide Python for the real stdlib machine-report producer assertion.
   The pinned Alpine Go image lacks it. Add the interpreter only to the test
   target; workload images and their offline launch path remain unchanged.

## Acceptance and execution order

- Save the failed authenticated job logs outside the Git source tree and record
  concrete causes before folding fixes.
- Apply and review small, independently testable corrections. Test API changes
  in both editions; prove Linux-only behavior with an owned local fixture.
- Run affected package/contract checks and existing required checks. Preserve
  prior failed results, then update the validation record and PLAN checkpoint
  last before pushing to the existing draft branch.
- Read the actual pushed SHA and follow required CI on that exact head. Do not
  merge, deploy, activate a runner, change live policy or resume unrelated
  security remediation.

Native sandbox qualification, latency benchmarking, First-Ready-relative TTL
and the post-PR SCP check retain their existing status. Live SCP requires an
approved already-running target; stopped services must not be restarted.

## Confirmed causes and corrections

The original exact-head CI run `37307748915` failed the release contract,
source-packaging tooling and both editions' `other` API shards. The effective
repository rules require ten contexts; nine passed and the aggregate `gates`
failed. The authenticated logs and local fixture evidence remain outside the
publishable source tree.

- `22760727` updates the stale three-dependency release assertion and adds a
  semantic four-dependency assertion. Removing any required dependency fails
  the new guard. Existing publication conditions are unchanged.
- `6f7730fc` fixes Git's refusal of a runner-owned checkout mounted inside a
  root-owned Docker container. Every exception is command-local and names the
  explicit source directory. Dirty and staged source still fail before a
  compiler runs. The actual `make test-sandbox-package` target passes on a
  separately committed public-source fixture matching the corrected files.
- `11e205f4` fixes the Linux actor recovery fixture's use of UID0. Root now runs
  that fixture as a real UID/GID65534 subprocess. Production root refusal,
  socket identity checks and all recovery/refusal assertions remain unchanged.
- Latest-schema sandbox fixtures now clone a sealed package-owned migration
  template into independently named databases. The previous suite replayed all
  197 migrations for every fixture and cumulatively exceeded the existing
  600-second package budget. Historical-version tests still migrate fresh
  databases. Tests verify isolated schema/state, concurrent clone ownership,
  source connection refusal and confirmed child/template teardown.
- The API and e2e test containers install their required Python interpreter
  before running tests. The pinned `golang:1.26.8-alpine` image lacks Python;
  host-runner Python cannot satisfy the real machine-report producer assertion
  inside that container. Both editions execute that assertion in the actual
  pinned image with the prerequisite present. No workload image or launch
  dependency changed.

No production authorization, readiness, expiry, resource or capacity limit
changes form part of these CI corrections. The existing ten-minute timeout and
all required gate selections remain in place. Initial harness failures and
later results are recorded separately in the validation record.
