# Custom skills local source milestone

2026-10-02; isolated branch `story/sandbox-foundation`, public main baseline `f6d494516a8e0567aff3fd7c559e37a916ecd0d4`.

The explicit requirement is user-added skills. The instruction-only SKILL.md format and quotas are proposed MVP choices, not claimed user-specified schema. Owner-private metadata CRUD is independent of the closed provisioning gate. Immutable revisions preserve existing selections on edit; explicit deletion disables every revision and requests policy refresh after commit. No control-plane install or privilege expansion occurs.

Validation: final `go test ./internal/sandboxes -count=1` against the task-owned disposable PostgreSQL fixture passed (23.513s). Earlier open/enterprise API builds and sandbox/HTTP race tests passed. Web TypeScript check passed; eight component tests across sandbox creation and custom skills passed, covering create retry, version edit, explicit delete and oversized import rejection. UI test container peak was 250359808 bytes, zero OOM events; typecheck peak was 822530048 bytes, zero OOM events. `git diff --check` passed.

Remaining: real CRUD HTTP authorization/ownership fixture coverage, successful file import and private selection UI regression coverage, changed-UI build and supported browser visual QA. No normal production build rerun: Docker VM available memory inspection was about 1.28GiB despite a task-chosen 1.5GiB limit on the prior failed build. No global environment settings changed. Runtime skill materialization, durable start/recovery and qualified network/private SSH readiness are pending. Public creation/resume remains closed.

Approximate planning estimate: 45–50% of source implementation, 0% verified end-to-end user readiness. This is a rough effort estimate, not a test result or completion fraction. S01–S03 have substantial local foundations; S04–S08 have tested partial implementations; S09–S12 still require delivery/qualification. The twelve-story plan and remaining acceptance checklist are authoritative for scope.
