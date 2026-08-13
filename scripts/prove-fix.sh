#!/usr/bin/env bash
# prove-fix.sh — apply a FIX and prove the whole claim, in one command.
#
# scripts/mutate.sh proves a guard REJECTS. This proves the other half: that the fix was APPLIED and that its red
# actually depended on it. Four assertions, in order — the middle two are the ones WF-S13-3 needed:
#
#   1. the test FAILS BEFORE the edit          (the red is real, not already-green)
#   2. the anchor EXISTS, exactly once          (the edit cannot silently match nothing)
#   3. the file CHANGED and still COMPILES      (the write happened; a build failure ≠ a pass)
#   4. the test PASSES AFTER                    (the fix is what closed it)
#
# WHY. On 2026-07-31 a fix "landed" via a bare python s.replace whose anchor missed by ONE SPACE. It changed
# nothing and reported success. Its red passed anyway, because the same edit taught the TEST FIXTURE to do what
# the production query was supposed to do — so the red asserted against a simulation of a fix that did not exist.
# Four gates, a review pass and a mutation round all missed it; the box-walk found it in one query.
#
# Assertion 1 is what that incident actually needed: had the red been required to FAIL FIRST, the fixture's
# simulation would have made it pass before the edit and the script would have stopped.
#
# STILL NOT SUFFICIENT ON ITS OWN. A red whose fixture RESTATES production instead of CALLING it can satisfy all
# four gates and prove nothing. See the fixture-fidelity law: reds substitute for review only where the fixture
# calls production.
#
# Usage:
#   scripts/prove-fix.sh <file> <anchor-file> <replacement-file> <test-command...>
# Anchor and replacement come from FILES, never argv, so no shell escaping can corrupt them.
set -euo pipefail

# ---------------------------------------------------------------------------------------------------------------
# DIRTY-FILE REFUSAL (added 2026-08-01 after a near-miss). If the target has UNCOMMITTED changes, then the fix
# under test is not in git — and `git checkout <file>` would discard the FIX along with the mutation. That is
# exactly what happened while proving #43's golden vector: two test files were left calling a function that no
# longer existed. Restoration is FROM THE BACKUP, never from git, and this states so where it will be read.
# ---------------------------------------------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
  exec bash "$(dirname "$0")/toolselftest.sh" prove-fix
fi

# ORDERING FIX (2026-08-01) — SAME DEFECT AS mutate.sh, from the same copy-pasted block. This referenced $file
# ABOVE the assignment below; with `set -u` that aborts before any work, so this script has never run since the
# dirty-file refusal was added. Run `scripts/prove-fix.sh --self-test` to prove it works.
file=$1; anchor_f=$2; repl_f=$3; shift 3
[ -f "$file" ] || { echo "PROVE-FIX: no such file: $file" >&2; exit 2; }

if ! git diff --quiet -- "$file" 2>/dev/null; then
  echo "NOTE: $file has UNCOMMITTED changes — the fix under test is not in git."
  echo "      Restore is from this script's backup copy ONLY. Do NOT run 'git checkout $file': it would discard"
  echo "      the uncommitted fix together with the mutation and leave callers referencing removed code."
fi

echo "PROVE-FIX (1/4): the red must FAIL before the fix —"
set +e; "$@" >/dev/null 2>&1; pre=$?; set -e
if [ $pre -eq 0 ]; then
  echo "PROVE-FIX: *** THE TEST ALREADY PASSES *** — it does not depend on this fix." >&2
  echo "           Either the red is vacuous, or its fixture simulates what production is supposed to do." >&2
  exit 5
fi
echo "PROVE-FIX: red fails as required (exit $pre)"

backup=$(mktemp); cp "$file" "$backup"
python3 - "$file" "$anchor_f" "$repl_f" <<'PY'
import sys
target, anchor_f, repl_f = sys.argv[1:4]
src = open(target).read()
anchor = open(anchor_f).read().rstrip('\n')
repl = open(repl_f).read().rstrip('\n')
if anchor not in src:
    sys.exit("PROVE-FIX: ANCHOR NOT FOUND — this edit would have changed NOTHING and reported success. "
             "That is the WF-S13-3 failure, and it is what this script exists to make impossible.")
if src.count(anchor) > 1:
    sys.exit("PROVE-FIX: anchor matches %d times — ambiguous; narrow it." % src.count(anchor))
open(target, 'w').write(src.replace(anchor, repl, 1))
print("PROVE-FIX (2/4): anchor found exactly once, replacement written")
PY

if cmp -s "$backup" "$file"; then
  echo "PROVE-FIX: FILE UNCHANGED after the write — refusing to continue." >&2
  cp "$backup" "$file"; rm -f "$backup"; exit 3
fi
echo "PROVE-FIX (3/4): file changed on disk"

if ! bash -c "${BUILD_CMD:-go build ./...}" >/dev/null 2>&1; then
  echo "PROVE-FIX: the fix DOES NOT COMPILE — reverting." >&2
  cp "$backup" "$file"; rm -f "$backup"; exit 4
fi
echo "PROVE-FIX (3/4): compiles"

echo "PROVE-FIX (4/4): the red must PASS after the fix —"
set +e; "$@"; post=$?; set -e
if [ $post -ne 0 ]; then
  echo "PROVE-FIX: the test STILL FAILS after the fix — the fix does not close it. Reverting." >&2
  cp "$backup" "$file"; rm -f "$backup"; exit 6
fi
rm -f "$backup"
echo "PROVE-FIX: PROVEN — red failed without it, anchor matched once, file changed, compiles, red passes with it."
