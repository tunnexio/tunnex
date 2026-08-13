# Dev environment hygiene — known local-baseline breaks

A broken local test baseline erodes every future gate's signal (a real regression hides behind a
"flaky test" reputation). Fixes/characterizations for known local breaks live here so a red suite is
matched against a KNOWN cause, never dismissed on plausibility alone.

## Seeded-DB agent-CA master-key mismatch (surfaced S8.5, 2026-07-19)

**Symptom:** `make test-editions` (or the individual suites) fails in `internal/agentca`,
`internal/tenancy` (`TestOrgLimitByEdition`, `TestOrgLifecycle`), and `internal/nodes`
(`TestNodeEnrollmentLifecycle`) with:

```
agent CA exists but is unusable; refusing to regenerate (a new CA would orphan every enrolled agent):
decrypt CA key: cipher: message authentication failed
```

**Root cause (environmental, NOT a code regression):** the agent CA row (and other encrypted rows)
in the persisted `postgres` volume were encrypted with a `master.key` (`internal/secrets/master.key`)
that was later REGENERATED — a fresh `make up` / secrets-dir reset mints a new `master.key` while the
DB volume keeps rows sealed under the old one. AES-GCM auth then fails on decrypt. The CA's
refuse-to-regenerate guard (correctly — regenerating would orphan every enrolled agent) surfaces it as
a hard failure. These suites reuse the live seeded DB, so they inherit the mismatch.

**Proof it is pre-existing (the characterization discipline):** the three packages are byte-identical
to `main` on any story branch (`git diff --stat main...HEAD -- apps/api/internal/{agentca,tenancy,nodes}`
= empty), and the SAME failures reproduce on `main` at the branch point (run the suites from a
`git worktree add --detach <wt> main`). Same code + same failure on the baseline = environmental.

**Fix (when the baseline is worth resetting):** re-align the DB with the current `master.key` — reset
the DB volume and re-seed under the current secrets dir:

```
make down            # or: docker compose down -v  (drops the postgres volume)
make up && make migrate && make seed
```

Do NOT delete `master.key` to "fix" it — that orphans every already-sealed row (the exact failure the
CA guard prevents). The key is the anchor; the DB is what re-aligns to it.

**Gate rule:** a red in these three suites is dismissable ONLY after confirming (a) the packages are
untouched vs main on the branch AND (b) the error is the decrypt-CA-key message above. Any OTHER
failure in them is a real signal — stop and characterize.
