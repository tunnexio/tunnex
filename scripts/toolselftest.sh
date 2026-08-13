#!/usr/bin/env bash
# toolselftest.sh — run mutate.sh / prove-fix.sh against a KNOWN-GOOD and a KNOWN-BAD case and assert the verdict.
#
# WHY THIS EXISTS. Twice in one day the tooling written to catch vacuous proofs was itself vacuous, and NEITHER
# FAILURE ANNOUNCED ITSELF:
#
#   1. mutate.sh printed "Restoring." and did not restore (3c9c16f). Every run left the mutated file in the tree
#      while claiming it had been put back.
#   2. The fix for (1) added a DIRTY-FILE REFUSAL block that referenced $file above the line assigning it. Under
#      `set -euo pipefail` that is an unbound-variable abort, so BOTH scripts exited before doing anything, on
#      every invocation, from the moment the safety feature landed. Copy-pasted into prove-fix.sh, so both died.
#
# THE PATTERN THIS GUARD ANSWERS: **a script's own execution is an unchecked assumption.** A tool that has only
# ever been INVOKED cannot be distinguished from one that WORKS — the shell reports the exit status of the last
# thing that ran, and a script that aborts at line 30 and a script that completes both "ran". The verdict has to
# be asserted against cases whose answer is known in advance.
#
# Usage:  scripts/toolselftest.sh {mutate|prove-fix}
#         scripts/mutate.sh --self-test        (same thing)
set -euo pipefail

# NOTE the message carries NO braces: `${1:?...}` ends its word at the FIRST unescaped `}`, so a usage string
# containing "{mutate|prove-fix}" appends a stray "}" to the VALUE and every dispatch misses. Cost: two runs.
which=${1:?usage: toolselftest.sh mutate OR prove-fix}
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fails=0

ok()  { echo "  PASS  $1"; }
bad() { echo "  FAIL  $1" >&2; fails=$((fails+1)); }

# A target OUTSIDE the repo, so `git diff` on it is a no-op and the self-test never touches tracked files.
seed() { printf 'line one\nORIGINAL_TOKEN\nline three\n' > "$tmp/target.txt"; }
printf 'ORIGINAL_TOKEN\n' > "$tmp/anchor.txt"
printf 'MUTATED_TOKEN\n'  > "$tmp/repl.txt"
printf 'NO_SUCH_ANCHOR_EXISTS_HERE\n' > "$tmp/badanchor.txt"

# BUILD_CMD=true: this repo is multi-module, so the scripts' default `go build ./...` cannot run from the root.
# The self-test is about the SCRIPT's control flow, not about Go.
export BUILD_CMD=true

case "$which" in
mutate)
  echo "SELF-TEST: scripts/mutate.sh"

  # (1) KNOWN-GOOD: mutate.sh's contract is that the test MUST FAIL under the mutation — that is what "the guard
  #     rejects this" means. So the known-good red is one that asserts the ORIGINAL behaviour: green normally,
  #     red once the token is mutated away.
  #     (The first draft of this self-test asserted MUTATED_TOKEN, which PASSES under the mutation, and the tool
  #     correctly refused it. The self-test caught its own author — which is the argument for having one.)
  seed
  if bash "$here/mutate.sh" "$tmp/target.txt" "$tmp/anchor.txt" "$tmp/repl.txt" \
       grep -q ORIGINAL_TOKEN "$tmp/target.txt" >"$tmp/out1" 2>&1
  then ok "known-good: the guard REJECTED the mutation (test went red under it)"
  else bad "known-good: script exited non-zero — see $tmp/out1"; cat "$tmp/out1" >&2
  fi

  # (1b) KNOWN-BAD: a test that passes REGARDLESS of the mutation proves nothing, and must be refused loudly.
  seed
  if bash "$here/mutate.sh" "$tmp/target.txt" "$tmp/anchor.txt" "$tmp/repl.txt" true >"$tmp/out1b" 2>&1
  then bad "known-bad: a test that PASSES under the mutation was accepted — vacuous guards would read as proven"
  else ok "known-bad: test passing under the mutation refused"
  fi

  # (2) RESTORE: the whole point of (1) is worthless if the file stays mutated. This is instance-1's defect.
  if grep -q ORIGINAL_TOKEN "$tmp/target.txt" && ! grep -q MUTATED_TOKEN "$tmp/target.txt"
  then ok "restore: target is byte-restored after the run"
  else bad "restore: target still MUTATED after the run — the 3c9c16f defect has returned"
  fi

  # (3) KNOWN-BAD: an anchor that matches nothing must REFUSE, not silently run a test against unmutated code.
  seed
  if bash "$here/mutate.sh" "$tmp/target.txt" "$tmp/badanchor.txt" "$tmp/repl.txt" true >"$tmp/out3" 2>&1
  then bad "known-bad: a non-matching anchor was ACCEPTED — mutations could prove nothing and report success"
  else ok "known-bad: non-matching anchor refused"
  fi
  ;;

prove-fix)
  echo "SELF-TEST: scripts/prove-fix.sh"

  # (1) KNOWN-GOOD: the red FAILS before the edit and PASSES after — the whole four-assertion claim.
  seed
  if bash "$here/prove-fix.sh" "$tmp/target.txt" "$tmp/anchor.txt" "$tmp/repl.txt" \
       grep -q MUTATED_TOKEN "$tmp/target.txt" >"$tmp/out1" 2>&1
  then ok "known-good: red failed before the edit and passed after"
  else bad "known-good: script exited non-zero — see $tmp/out1"; cat "$tmp/out1" >&2
  fi

  # (2) KNOWN-BAD: a red that is ALREADY GREEN must be refused. This is assertion 1, the one WF-S13-3 needed —
  #     a test that passes before the fix proves nothing about the fix.
  seed
  if bash "$here/prove-fix.sh" "$tmp/target.txt" "$tmp/anchor.txt" "$tmp/repl.txt" true >"$tmp/out2" 2>&1
  then bad "known-bad: an ALREADY-GREEN red was accepted — assertion 1 is not enforced"
  else ok "known-bad: already-green red refused"
  fi
  ;;
*) echo "unknown tool: $which" >&2; exit 2;;
esac

[ "$fails" -eq 0 ] || { echo "SELF-TEST FAILED ($fails)"; exit 1; }
echo "SELF-TEST OK"
