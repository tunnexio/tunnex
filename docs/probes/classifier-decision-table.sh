#!/usr/bin/env bash
# The classifier's logic, transcribed VERBATIM from .github/workflows/ci.yml's `scope` step.
classify() {
  local CHANGED="$1" PATTERN="$2" RUN_GO=true
  if [ -n "$(printf '%s' "$CHANGED" | tr -d '[:space:]')" ]; then
    if ! printf '%s\n' "$CHANGED" | grep -qE "$PATTERN"; then RUN_GO=false; fi
  fi
  echo "$RUN_GO"
}

OLD='(\.go$|go\.(mod|sum)$|Dockerfile|\.github/|openapi/|apps/api/db/)'
NEW='(\.go$|go\.(mod|sum)$|\.sql$|Dockerfile|\.github/|openapi/|apps/api/db/)'

# ⛔ The NEW pattern is not typed twice: assert it is the one CI actually runs, or this whole table is
# a proof about a string that exists only in this file.
if grep -qF "$NEW" .github/workflows/ci.yml; then
  echo "NEW pattern CONFIRMED present in .github/workflows/ci.yml"
else
  echo "⛔ NEW pattern NOT FOUND in ci.yml — this table would prove nothing. Aborting."; exit 1
fi
echo

printf '%-52s %-9s %-9s %s\n' "diff (what the PR touched)" "BEFORE" "AFTER" "verdict"
printf '%-52s %-9s %-9s %s\n' "----" "------" "-----" "-------"
fails=0
run() {
  local label="$1" d="$2" want="$3"
  local b a v
  b=$(classify "$d" "$OLD"); a=$(classify "$d" "$NEW")
  if [ "$a" = "$want" ]; then v="ok"; else v="WRONG (wanted go=$want)"; fails=$((fails+1)); fi
  printf '%-52s %-9s %-9s %s\n' "$label" "go=$b" "go=$a" "$v"
}

run "fixtures.sql ONLY  <- THE HOLE"          "apps/api/cmd/seed-fixtures/fixtures.sql" true
run "migrations ONLY (was already covered)"   "apps/api/db/migrations/0057_x.up.sql"    true
run "web src ONLY (the split MUST survive)"   "apps/web/src/pages/Users.tsx"            false
run "docs ONLY"                                "docs/laws.md"                            false
run "web + fixtures (mixed)"                   "apps/web/src/pages/Users.tsx
apps/api/cmd/seed-fixtures/fixtures.sql"                                                 true
run "EMPTY diff (fail-closed arm)"             ""                                        true
run "a .go file"                               "apps/api/internal/http/x.go"             true
run "openapi spec"                             "openapi/openapi.yaml"                    true

echo
if [ "$fails" -eq 0 ]; then echo "8/8 arms correct"; else echo "$fails ARM(S) WRONG"; exit 1; fi
