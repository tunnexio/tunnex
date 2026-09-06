# Release draft visibility repair

User requested fixing post-merge main CI failure on 2026-09-06.
Baseline: main 231f63f (merged PR #59). Branch: codex/fix-release-draft-permissions.

## Cause and decision

PR #56 (0b34861) added draft/source-ledger revalidation before image publication
but retained publish job contents:read. Main run 34027093570 attempt 2 fails
at gh release view with "release not found". The exact source-tag draft exists,
verified read-only with the operator identity. GitHub restricts draft visibility
to push-capable identities; release-version-guard has contents:write, publish does not.
Earlier workflows did not perform this draft read in the read-only image job.
PR runs skip publication, so green PR gates could not exercise that token boundary.

Grant contents:write only to the already push-only publish job. Preserve its event,
branch/tag, feature-toggle, gate/E2E prerequisites and all source/draft/ledger guards.
Keep checkout credentials non-persistent in this job. Do not make a draft public
early, recreate a release, use a personal token, bypass verification or widen PR
job permissions. Add a pre-merge regression that reads effective workflow permissions
and executes the actual revalidation script against a permission-aware fixture.

Test successful draft validation and read-only, absent/published release, moved
source and mismatched ledger refusal. Fixture proof substitutes for GitHub's live
token behavior; the next approved main publication is the real qualification.
No merge, release, cloud changes or cleanup authorized by this repair alone.

Reference: https://docs.github.com/en/rest/releases/releases
