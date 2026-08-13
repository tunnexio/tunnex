# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Re-entry rule (fresh session)

Re-enter from **PLAN.md's "Story status (re-entry checkpoint)"** pointer plus `git log` —
**trust git over any memory or handoff summary.** A stale pointer re-enters the wrong epic;
if PLAN.md and git disagree, git wins and the pointer gets fixed. Update the pointer on
every merge (one line).

## Story protocol

Stories build one at a time, decision-first:

1. **Commit-one is paper** — `docs/S<story>-decisions.md` records the decisions (decide-items
   dispositioned explicitly) *before* product code. Dispositions are folded back into the paper;
   the paper is the record.
2. **Slices** — build in reviewable slices on the story branch (`story/S<n>-<slug>`).
3. **Review** — self-review + `/code-review`; dispositions come BEFORE folding findings.
   A mid-fold redesign (e.g. of a security test) is a decide-item, not a fold.
   Story-end = a multi-finder review. Findings are presented RANKED and HELD for
   disposition (the user brings dispositions back); fold only what's dispositioned.
   A feature-sized fold RE-EARNS a review of the folded code. Budget rule: repeated
   fold-induced defects in the same component = HALT, paper its state model, reduce
   not patch (the S7.5.1 JSONL arc — six rounds → deferred to S7.5.1b rather than
   shipped). A session-limited/incomplete review is INCONCLUSIVE, never clean —
   re-run it.
4. **Box-walk** — prove the story on a live wire (docs/S*-boxwalk.md / -box-walk.md);
   unit tests SUBSTITUTE for a wire proof but never SATISFY it (see ledger conventions).
   Walk evidence is COMMITTED during the walk session (walk-artifacts/), not after.
   Walk-time scratch credentials (WG configs etc.) contain private keys — gitignore
   them at creation, never commit.
5. **Both-green** — CI required checks (`gates` + `client (macos-latest)` + `client (windows-latest)`)
   must pass; run the gate targets locally first.
6. **⛔ THE POINTER NAMES THE CONTENT TIP, NOT `main`'s HEAD** (ruled S14.11, from archaeology).
   The re-entry checkpoint records the **last non-pointer commit of the story** — the branch tip *before*
   the PLAN commit — never the post-merge head sha.
   **WHY: a commit cannot contain its own hash.** The post-merge head is unknowable before the merge, for a
   fast-forward exactly as much as for a rebase, so the old rule forced a direct-to-`main` push **after every
   merge** to fill it in — bypassing all three required checks. Measured across EPIC 14: **8 such pushes,
   8 forced, 0 avoidable.**
   The content tip is knowable while the PR is open, so **the checkpoint lands inside the PR and the bypass
   disappears permanently** instead of being counted.

   ⛔ **AND WRITE THE CHECKPOINT LAST — THE FINAL COMMIT BEFORE THE MERGE.** Twice now the pointer has named a
   commit with content behind it, because more work landed after the checkpoint was written and it had to be
   re-pointed (S14.14, then S14.17–19). **Both times the rule was fine and the SEQUENCING was wrong.** A
   procedure gap, not a rule gap, and the fix costs nothing: nothing goes in after the checkpoint except the
   merge itself. If something must, re-point it in the same breath rather than at merge time. It is one commit
   behind `main`'s literal head **by construction, and that is the point, not a defect**.
   ⛔ **THE PR NUMBER IS THE IDENTIFIER; THE SHA IS AN ANNOTATION** (ruled S14.20, from the first merge under
   this rule). Merge commits are DISABLED on this repo for linear history, so **rebase-merge is the only
   method available and it re-parents every commit** — the sha written inside the PR is *guaranteed* not to be
   the sha that lands on `main`. Trees stay byte-identical; shas do not survive. So write the checkpoint as
   **`PR #<n>`, content tip `<post-merge sha>` (`<pre-merge sha>` pre-merge)** — the pre-merge sha is all that
   is knowable while the PR is open, and it is recorded AS a pre-merge sha rather than passed off as the
   merged one. Filling in the post-merge sha is a **docs correction on `main`, never a story commit**, and it
   is NOT a check bypass: the content it points at was already green under all three required checks.
   ⚠ **And the check that missed this was correctly run at the wrong subject** — three prior PRs' head shas
   were confirmed present on `main` unchanged, without confirming those PRs were merged by the same method.
   A preservation result from an unknown method predicts nothing.

7. ⛔ **`--match-head-commit` IS MANDATORY ON EVERY MERGE, AND THE SHA MUST BE READ, NEVER TYPED** (ruled
   S13.1, from a self-catch). A fabricated sha — a short form padded out with invented hex — was passed to that
   flag and GitHub refused. **A verification argument you constructed is not a verification**: the check was
   real, the input was fiction, and from the command line the two are indistinguishable. Without the flag,
   `--squash`/`--rebase` merges whatever is at head, including a head that moved after CI went green.
   Read it: `gh pr view <n> --json headRefOid -q .headRefOid`. Never expand a short sha by hand.

8. **Merge only on explicit in-session sign-off.** A merge instruction executes in the session
   that receives it, or is RE-CONFIRMED at re-entry — a sign-off read out of a summary/handoff
   is NOT authorization to merge. Never merge without the user's word. Merges to `main` are
   PR → ff-only, linear history. `git push --force-with-lease` is pre-authorized for `story/*`
   branches only; `main` is never force-pushed.

Where a commit lives: product code ALWAYS on the story branch. A process/docs correction whose
value is immediate lands on `main` directly; then rebase the active story branch onto main.
⛔ **BUT NOT THE RE-ENTRY CHECKPOINT — it was the example here and is now the counter-example.** Under
rule 6 the pointer names the CONTENT TIP, which is knowable while the PR is open, so the checkpoint goes
INSIDE the PR and needs no `main` push at all. That example is what made the bypass look like an exception
when it was a standing mechanism: **8 pushes, one per merge, every one of them forced by this sentence.**
Before taking the direct-to-`main` path for anything, ask whether it is genuinely unknowable inside the PR —
if it is knowable, the bypass is a choice, not a necessity.

## The absence questions (a UI section pass asks these, not only "does it match the design")

⛔ **A DESIGN CAN ONLY BE WRONG ABOUT WHAT IT DEPICTS; IT CANNOT BE WRONG ABOUT WHAT IT OMITS.** A wireframe
diff and a panel-by-panel test both ask *does this match the source* — so anything the source is silent about
is invisible to both. Two questions, answered from the **spec and schema**, never from the design:

1. **What can an operator NOT do on this screen that the API allows?** For every mutating endpoint, name its
   call site; one with no caller is either dead or missing a surface. (S14.12: 80 mutating operations, 19
   with no web call site, 12 genuinely unreachable — a capability the product has and nobody can reach.)
2. **What happens after each destructive verb, and is the operator told?** Read the FK actions and the
   handler's response body. (S14.12: `ON DELETE CASCADE` on three columns — deleting a group silently deleted
   every rule referencing it, and the 204 said nothing.)

Both findings were the best of that section and neither appeared in the wireframe.

## ⛔ LOOK-AHEAD DEVELOPMENT — do not block on CI (founder-directed, conditional)

**Push, then keep building.** If CI comes back red, fix it then — **a red on a branch costs one fix; an
idle session costs the whole session.** Never sit on a check-runs poll waiting for green.

**CONDITIONS — it applies only when the next work does not depend on the CI result.**
⛔ **IT DOES NOT APPLY TO A MERGE.** A merge still waits for green **on the exact sha**, because that is
the one place a red costs more than a fix (see the merge standard).

Report the CI result whenever it lands, alongside whatever was built in the meantime.

⛔ **AND REPORT THE LATEST SHA, NOT THE ONE YOU NAMED.** Pushing while CI runs CANCELS the prior run, so a sha
you promised a result for may never produce one. **A cancelled `gates` is not evidence of anything** — never
count it as green, and never count it as red. Re-point the report at the head that actually ran.

## Gates (run before declaring a slice/story done)

The CI `gates` job is the composite; locally that means:

```bash
make generate-check    # codegen drift guard (OpenAPI → Go/TS/RBAC/sqlc)
make migrate           # apply migrations (stack's postgres must be up)
make test-editions     # Go API tests in BOTH editions (open + enterprise build tags)
make build-editions    # both editions compile (catches edition rot)
make test-node         # node-agent data-plane tests
make test-helper       # privilege-helper vet + test
make helper-crosscompile
pnpm --filter @tunnex/web typecheck && pnpm --filter @tunnex/web test && pnpm --filter @tunnex/web build
```

**Both editions, always** — every API change must build and test with and without
`-tags enterprise`. Go builds/tests use `GOFLAGS=-mod=readonly` deliberately so dependency
resolution cannot silently rewrite go.mod/go.sum (see the GUARD notes in Makefile and each go.mod).

Other commands: `make up` / `make up-enterprise` / `make down` (compose stack),
`make e2e` (Playwright + API integration), `make seed` / `make seed-enterprise`,
`make migrate-create name=<snake_case>`, `make sqlc`, `make generate`.

## Decisions & ledger conventions

- **`docs/S*-decisions.md`** is the decision record per story: decide-items listed, each
  dispositioned (locked / rejected-with-rationale / deferred-to-named-story). Rejected
  alternatives stay in the paper so they're findable later.
- **SUBSTITUTES ≠ SATISFIES:** when a proof can't run (no hardware, no desktop, no cert),
  the substitute (unit tests, paper sign-off) is recorded as a SUBSTITUTE with a NAMED
  trigger for the real proof — deferred, never dropped. Triggers are named events
  (e.g. "public-beta readiness"), never calendar clocks.
- **Mid-build forks halt-and-surface:** discovering a fork in the road mid-build (a new
  decide-item, a scope change, an unexpected design constraint) halts the build and surfaces
  it for disposition — do not pick a branch silently. This applies to review findings too:
  decide-items and named stop-conditions/tripwires go to the user; never resolve one
  unilaterally.
- **Enterprise features are UNLOCK-THEN-OPT-IN, never unlock-and-enforce** (founder-directed):
  org-level opt-in, default OFF. Unlocking (edition/license) makes a capability available;
  it never turns enforcement on.

## Architecture

Monorepo (pnpm workspaces + turbo for TS; independent Go modules per app):

- **`apps/api`** — Go control plane (chi, sqlc, PostgreSQL, Redis sessions). The API NEVER
  touches WireGuard directly. Open-core split: `internal/enterprise/` + anything behind the
  `enterprise` build tag is proprietary (own LICENSE); the rest is Apache-2.0. Never let the
  two bleed together — `make test-editions` is the guard. Migrations: `apps/api/db/migrations`
  (numbered pairs); typed queries via sqlc from `db/queries`.
- **`apps/node`** — data-plane agent owning WireGuard via wgctrl. Desired-state reconcile
  loop: data-plane state is continuously reconciled against control-plane desired state,
  never assumed in sync.
- **`apps/web`** — React + Vite + Tailwind SPA; same bundle reused by the Electron renderer.
  RBAC mirror is generated (`src/lib/rbac-policy.json`), never hand-edited.
- **`apps/client`** — Electron desktop app. Renderer never holds tokens (main-process
  webRequest injector); preload exposes a verb allowlist, no generic invoke. Client unit
  tests must import NO electron at runtime (CI sets ELECTRON_SKIP_BINARY_DOWNLOAD) — pure
  view-models live in electron-free modules.
- **`apps/helper`** — root privilege helper (typed protocol, canonicalized caller auth,
  version handshake) + kill-switches: macOS pf, Windows WFP. `internal/wfp/` is a PINNED,
  DIVERGED fork of wireguard/windows tunnel/firewall — on any wireguard/windows bump,
  re-diff and re-apply the deltas (see its VENDOR.md).
- **`apps/cli`** — `tunnex` CLI (Go client generated from the spec).
- **`packages/shared`** — generated TS API types + shared client transport.

**OpenAPI-first:** `openapi/openapi.yaml` is the single source of truth. Handlers, the Go CLI
client, TS types, and the RBAC mirror are all generated (`make generate`); CI fails on drift
(`make generate-check`). Never hand-sync types.

Cross-cutting invariants (established, don't regress):
- Identity ↔ credential binding: a device credential is only valid for its owning user; no
  floating credentials. Revocation is a FULL sweep (peer slot + pool address + telemetry).
- Default-deny policy model; policy compiler is pure/deterministic (`policyspec.Compiled`).
- RBAC: permissions are named per feature (never reuse an existing perm for a new capability);
  the grant table is generated and drift-guarded.
- Audit logs record system actors first-class (`actor_system`) with a cause.
- No-oracle 401s; one-time-secret hygiene; keyed proof-of-secret; keyset pagination;
  edition gating = 403 `edition_required`.
