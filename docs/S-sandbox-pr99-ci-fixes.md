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
