# Shelving CI compile metadata correction

Draft PR #103 at `9a3ab4f735f827aa81248aa1c25ee5e88ed203cc` failed
the `test-node` and `test-cli` tooling lanes before test execution. Both new
full-source compile steps reported `error obtaining VCS status: exit status
128` inside the existing source-mounted containers. Their test checkout does
not provide usable Git metadata to the compiler.

## Decisions before correction

- Locked: add `-buildvcs=false` only to these two compile-only `go build ./...`
  steps. Preserve complete source compilation, CLI vet, selected ordinary
  tests, readonly modules and the existing native VPN prerequisites.
- Locked: leave release build flags, release provenance, workflow permissions,
  required checks and shared product behavior unchanged. This correction does
  not reactivate sandbox code or import the preserved implementation history.
- Locked: validate a real Go build with unavailable Git metadata, compile the
  two modules for Linux AMD64 and run the affected CI contracts. Remote checks
  must pass at the actual updated PR head; the failed original run remains
  evidence and is not counted as a passing run.

The architecture choice in the earlier user prompt is already recorded in
the preserved local runner implementation. It does not require copying that
unfinished product history into this shelving PR.
