# AI publication integration — 2026-09-09

The user authorized publishing both repositories and opening their PRs. Core PR #67 and website PR #48 are drafts; neither is authorized to merge.

## Decisions

- Locked: integrate core main `219d422b55abc400f104f1486b91343ea231bd57` into the AI publication branch in a separate checkout. Preserve both the merged NAT functionality and the AI changes.
- Locked: main owns migration numbers 0139–0141. Renumber the unpublished AI migrations 0139–0151 to 0142–0154 and 0153 to 0156, preserving their SQL contents and relative order. Number 0155 remains unused in this PR; the uncommitted MCP credentials/discovery implementation is excluded.
- Locked: regenerate OpenAPI, SQL and RBAC outputs from their combined sources. Do not resolve generated conflicts by deleting one feature.
- Locked: prove fresh migration and migration from main schema 0141 using only the explicitly labelled disposable `tunnexworkload0909` fixture. Do not apply this new migration ordering to the existing local AI preview database, whose old migration numbers have already been applied.
- Deferred: converting the existing development preview database to the publication migration ordering requires a separate data-preserving migration plan. The running preview, saved credentials, original worktrees and unrelated changes remain untouched by this publication integration.
- Locked: publish validation results accurately. Existing live AI walkthrough evidence predates this integration; it is not a new live NAT/AI combined rollout proof. Keep the PR draft while recorded review and production qualification gaps remain.

## CI follow-up

- Locked: keep Tunnex's first-party Go 1.25.13 toolchain unchanged. The separate immutable Bifrost source `9537b2fadf42af90eb34ed47d3d4252e1beff4a0` requires Go 1.27.0 in its transport/core/framework modules. Check its Docker builder against that exact separate pin, retaining blocking drift detection for both first-party and upstream builds; do not downgrade upstream or broadly upgrade the control plane merely to satisfy an equality check.
- Locked: synchronize HTTP fixture call counters read by the deadline test. CI's race detector found a test-only unsynchronized handler write; retain the exact timeout assertions and production timeout behavior.

- Locked: a large PR must not fail classification or lose CI/security coverage because an early-exit reader closes a shell pipe. Replace truncated/quiet readers with consumers that drain the input; preserve existing classification patterns and fail-closed defaults. Execute both actual classifier scripts against a synthetic large diff as a regression.

## Merge authorization and browser regression

The user authorized merging the feature branches into main if CI is green on
2026-09-09, then confirmed approval. Website PR #48 passed both checks and was
merged at `914b9c7a0cee742161234850041eaf0c9e231da2`. Core PR #67 remains subject
to successful CI and the repository's required GitHub code-owner review.

- Locked: update the existing Users browser tests to the approved Users & Groups
  navigation and multiple-role editor. Preserve member/unverified-admin refusal,
  sole-owner protection, invitation enumeration resistance and the mutation-to-audit
  proof. Test role changes through the role-set endpoint and restore the exact
  original role set during cleanup; do not weaken assertions to match removed controls.
- Locked: run the affected browser suite against a separately seeded database,
  isolated Redis and local API/UI ports. Do not use or migrate the running preview.
- Deferred qualification items in the workload review remain documented; merging
  does not claim a production rollout or completion of those separate proofs.
