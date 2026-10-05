# Sandbox foundation local validation

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

2026-10-02; base freshly fetched upstream/main f6d494516a8e0567aff3fd7c559e37a916ecd0d4.

Implemented: independent sandbox identity/model, org/creator ownership predicate, legal lifecycle transition validation; preparatory enforcing-policy guards against legacy user/group/agent grants and human destination-group membership. Existing managed-agent behavior retained. No public route, DB migration, provider, sandbox grant projection or UI is wired yet.

Passed with local writable GOCACHE=<preserved-local-artifact> and GOFLAGS=-mod=readonly:
- go test -race ./internal/sandboxes ./internal/policy (full policy package)
- go vet ./internal/sandboxes ./internal/policy
- gofmt and git diff --check

Feature tests cover zero/cross-org/non-owner identities, start/stop/delete and invalid/retry/failure-cleanup transitions, all legacy source subject kinds, compiler-level no-grant behavior, destination-group exclusion and retained agent owner behavior.

Self-review: sandbox model is a foundation only; ownership predicate intentionally does not replace membership/RBAC. Identity immutability, revision CAS and ready evidence must be enforced by future store/reconciler. Compiler guard applies to enforcing-mode legacy grants; it does not make mesh mode or explicit CIDR rules safe. Future creation must reject mesh/off mode and separately project bounded sandbox grants. No existing device is retyped and no pilot is changed. No independent story-end review or live box-walk completed; full API build/integration/UI gates unrun because this slice has no public/storage/UI wiring. Unit evidence does not prove packet enforcement.

Environment: initial module command from workspace root corrected to apps/api; default Go build cache denied by filesystem sandbox, resolved by writable /tmp cache. Public source fetch required approved network escalation and succeeded. No remaining tool blocker for this slice.
