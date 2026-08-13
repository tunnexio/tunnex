#!/usr/bin/env bash
# mutate.sh — apply ONE mutation, PROVE it landed, run a test command, restore.
#
# WHY THIS EXISTS. Three mutation rounds in one session reported `ok` because the patch never applied:
# twice from shell escaping mangling the replacement, once from a Python syntax error in a heredoc. Each time the
# green was read as "the fix is unnecessary" — a false proof, and exactly the could-this-check-have-failed class
# the repo already has a law for. Verifying the OUTCOME was never the gap; verifying the APPLICATION was.
#
# Three assertions, in order, before any test runs:
#   1. the anchor EXISTS in the file (a mutation that matches nothing is not a mutation)
#   2. the file CHANGED on disk (proves the write happened, not just that the script ran)
#   3. the package still BUILDS (a build failure is indistinguishable from a pass — the mutation-must-compile law)
#
# COMPANION: scripts/prove-fix.sh applies the SAME assertions to a FIX — plus "the red must fail BEFORE the edit",
# which is the gate WF-S13-3 needed and did not have. Use mutate.sh to prove a guard rejects; use prove-fix.sh to
# prove an edit landed and that its red depended on it.
#
# Usage:
#   scripts/mutate.sh <file> <anchor-file> <replacement-file> <test-command...>
# The anchor and replacement are read from FILES, never from argv, so no shell escaping can corrupt them.
set -euo pipefail

# ---------------------------------------------------------------------------------------------------------------
# DIRTY-FILE REFUSAL (added 2026-08-01 after a near-miss). If the target has UNCOMMITTED changes, then the fix
# under test is not in git — and `git checkout <file>` would discard the FIX along with the mutation. That is
# exactly what happened while proving #43's golden vector: two test files were left calling a function that no
# longer existed. Restoration is FROM THE BACKUP, never from git, and this states so where it will be read.
# ---------------------------------------------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
  exec bash "$(dirname "$0")/toolselftest.sh" mutate
fi

# ORDERING FIX (2026-08-01). This block used to sit ABOVE the assignment below and referenced $file before it
# existed — with `set -u` that is an unbound-variable abort, so the script exited on line 1 of its real work
# EVERY TIME IT WAS INVOKED. The mechanization added to make mutation proofs safe could not run at all. It is the
# same class it was written to prevent: a guard that cannot execute is indistinguishable from a guard that passes.
# Run `scripts/mutate.sh --self-test` to prove it works — that is the guard this defect earned.
file=$1; anchor_f=$2; repl_f=$3; shift 3
[ -f "$file" ] || { echo "MUTATE: no such file: $file" >&2; exit 2; }

if ! git diff --quiet -- "$file" 2>/dev/null; then
  echo "NOTE: $file has UNCOMMITTED changes — the fix under test is not in git."
  echo "      Restore is from this script's backup copy ONLY. Do NOT run 'git checkout $file': it would discard"
  echo "      the uncommitted fix together with the mutation and leave callers referencing removed code."
fi

backup=$(mktemp); cp "$file" "$backup"
restore() { cp "$backup" "$file"; rm -f "$backup"; }
trap restore EXIT

python3 - "$file" "$anchor_f" "$repl_f" <<'PY'
import sys
target, anchor_f, repl_f = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(target).read()
anchor = open(anchor_f).read().rstrip('\n')
repl = open(repl_f).read().rstrip('\n')
if anchor not in src:
    sys.exit("MUTATE: ANCHOR NOT FOUND — the mutation would have applied nothing and the test would have passed "
             "for the wrong reason. This is the failure this script exists to make impossible.")
if src.count(anchor) > 1:
    sys.exit("MUTATE: anchor matches %d times — ambiguous; narrow it." % src.count(anchor))
open(target, 'w').write(src.replace(anchor, repl, 1))
print("MUTATE: anchor found once, replacement written")
PY

# (2) the file actually changed
if cmp -s "$backup" "$file"; then
  echo "MUTATE: FILE UNCHANGED after the write — refusing to run the test." >&2
  exit 3
fi
echo "MUTATE: file changed ($(diff <(cat "$backup") "$file" | grep -c '^[<>]') lines)"

# (3) it still compiles — a build failure reads exactly like a pass
if ! bash -c "${BUILD_CMD:-go build ./...}" >/dev/null 2>&1; then
  echo "MUTATE: THE MUTATION DOES NOT COMPILE. A build failure is indistinguishable from a passing test — " >&2
  echo "        rewrite it so it compiles (orphaned variables are the usual cause), then re-run." >&2
  exit 4
fi
echo "MUTATE: compiles — running the test; it MUST fail"

set +e
"$@"; rc=$?
set -e
# (3b) THE MISSING ASSERTION, added 2026-08-01 after it cost a false verdict.
#
# A RED PROVES NOTHING UNLESS THE TEST WAS GREEN BEFORE THE MUTATION. This script asserted "the test failed"
# and concluded "the guard bites" — but a test command that is BROKEN fails identically. It happened for real:
# the command was invoked from the repo root as `vitest run --root apps/web test/x.test.tsx`, which broke the
# relative path in `vi.mock("../src/lib/api")`, so nothing was mocked and ALL FOUR tests failed — including two
# the mutation cannot possibly affect. mutate.sh printed "test failed under the mutation, as required".
#
# That is the sixth vacuous-check mechanism (ASSERTS-A-DIFFERENT-EVENT-THAN-IT-WAITS-ON, docs/laws.md) applied
# to the TOOL: it waits on "the command exited non-zero" and asserts "the guard rejected the mutation".
#
# prove-fix.sh has always had the mirror of this ("the red must FAIL before the edit"). mutate.sh never did.
if [ $rc -ne 0 ]; then
  restore_pre_baseline() { cp "$backup" "$file"; }
  restore_pre_baseline
  set +e; "$@" >/dev/null 2>&1; base_rc=$?; set -e
  # re-apply the mutation for the restore path below to undo symmetrically
  python3 - "$file" "$anchor_f" "$repl_f" <<'PY' >/dev/null
import sys
t,a,r = sys.argv[1], sys.argv[2], sys.argv[3]
s=open(t).read(); anchor=open(a).read().rstrip('\n'); repl=open(r).read().rstrip('\n')
open(t,'w').write(s.replace(anchor,repl,1))
PY
  if [ $base_rc -ne 0 ]; then
    echo "MUTATE: *** THE TEST ALSO FAILS WITHOUT THE MUTATION *** — the red says nothing about the guard." >&2
    echo "        Fix the test command (a wrong cwd, an unresolved mock path, a missing dep) and re-run." >&2
    exit 6
  fi
  echo "MUTATE: baseline confirmed — the test PASSES unmutated, so the failure above is the mutation's."
fi
if [ $rc -eq 0 ]; then
  echo "MUTATE: *** THE TEST PASSED UNDER THE MUTATION *** — the guard does not cover this behaviour." >&2
  exit 5
fi

# POST-RESTORE VERIFICATION. A restore that silently failed leaves a mutated tree that later reads as green, and
# `go test` will serve a CACHED pass for content it has seen before — so the check must be forced.
restore_and_verify() {
  cp "$backup" "$file"
  if ! cmp -s "$backup" "$file"; then
    echo "RESTORE FAILED — $file does not match the pristine copy at $backup. Do not commit." >&2
    exit 7
  fi
  echo "RESTORE: file matches the pristine copy"
  echo "RESTORE: re-running the test UNCACHED (-count=1) to prove the tree is green again —"
  if ! GOFLAGS="${GOFLAGS:-} -count=1" "$@" >/dev/null 2>&1; then
    echo "RESTORE: the test does NOT pass on the restored tree. The restore is incomplete or the tree was" >&2
    echo "         already broken before this run. Do not commit." >&2
    exit 8
  fi
  echo "RESTORE: verified green, uncached."
}

echo "MUTATE: test failed under the mutation, as required. Restoring."
restore_and_verify "$@"
