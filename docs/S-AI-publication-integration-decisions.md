# AI publication integration — 2026-09-09

The user authorized publishing both repositories and opening their PRs. Core PR #67 and website PR #48 are drafts; neither is authorized to merge.

## Decisions

- Locked: integrate core main `219d422b55abc400f104f1486b91343ea231bd57` into the AI publication branch in a separate checkout. Preserve both the merged NAT functionality and the AI changes.
- Locked: main owns migration numbers 0139–0141. Renumber the unpublished AI migrations 0139–0151 to 0142–0154 and 0153 to 0156, preserving their SQL contents and relative order. Number 0155 remains unused in this PR; the uncommitted MCP credentials/discovery implementation is excluded.
- Locked: regenerate OpenAPI, SQL and RBAC outputs from their combined sources. Do not resolve generated conflicts by deleting one feature.
- Locked: prove fresh migration and migration from main schema 0141 using only the explicitly labelled disposable `tunnexworkload0909` fixture. Do not apply this new migration ordering to the existing local AI preview database, whose old migration numbers have already been applied.
- Deferred: converting the existing development preview database to the publication migration ordering requires a separate data-preserving migration plan. The running preview, saved credentials, original worktrees and unrelated changes remain untouched by this publication integration.
- Locked: publish validation results accurately. Existing live AI walkthrough evidence predates this integration; it is not a new live NAT/AI combined rollout proof. Keep the PR draft while recorded review and production qualification gaps remain.
