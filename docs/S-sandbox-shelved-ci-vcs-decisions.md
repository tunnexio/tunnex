# Shelving CI compile metadata correction

Draft PR #103 at `9a3ab4f735f827aa81248aa1c25ee5e88ed203cc` failed
the `test-node` and `test-cli` tooling lanes before test execution. Both new
full-source compile steps reported `error obtaining VCS status: exit status
128` inside the existing source-mounted containers. Their test checkout does
not provide usable Git metadata to the compiler.

## Decisions before correction

- Locked: add `-buildvcs=false` to `GOFLAGS` only in these two test containers.
  Package discovery also loads VCS metadata, so a build-only argument is
  insufficient. Preserve complete source compilation, CLI vet, selected
  ordinary tests, readonly modules and the existing native VPN prerequisites.
- Locked: leave release build flags, release provenance, workflow permissions,
  required checks and shared product behavior unchanged. This correction does
  not reactivate sandbox code or import the preserved implementation history.
- Locked: validate a real Go build with unavailable Git metadata, compile the
  two modules for Linux AMD64 and run the affected CI contracts. Remote checks
  must pass at the actual updated PR head; the failed original run remains
  evidence and is not counted as a passing run.

## Local validation

- Real Go 1.26.8 fixture: unavailable Git metadata reproduces both build and
  discovery failures; inherited corrected flags pass build, vet, actual
  package selection and selected ordinary tests.
- Complete Linux AMD64 node and CLI module builds pass with readonly cached
  dependencies and the corrected flags.
- CLI vet and all five selected ordinary package test invocations pass.
- Affected CI contracts: 72 passed, two explicit historical skips, no failures.
- Independent bounded review and `git diff --check` pass; release source and
  provenance flags are unchanged. Corrected remote checks remain a separate
  exact-head gate, not established by local tests.
