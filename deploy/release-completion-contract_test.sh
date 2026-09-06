#!/usr/bin/env bash
# Execute the real workflow completion step against a closed GitHub fixture.
# No release, network request, credential, or repository mutation is performed.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
CI="$ROOT/.github/workflows/ci.yml"
STEP='      - name: Publish only the completed source-ledger release'
test "$(grep -Fxc "$STEP" "$CI")" = 1
awk -v step="$STEP" '
  $0 == step { selected = 1; next }
  selected && /^        run: \|$/ { body = 1; next }
  body && /^          / { sub(/^          /, ""); print; next }
  body { exit }
' "$CI" > "$STAGE/completion.bash"
test -s "$STAGE/completion.bash"
bash -n "$STAGE/completion.bash"

export GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export GITHUB_REPOSITORY=tunnexio/fixture
export GITHUB_REF_NAME=v1.2.3
export GITHUB_REF=refs/tags/v1.2.3
TEST_RELEASE_SHA=$GITHUB_SHA
TEST_DRAFT=true
TEST_LEDGER_SHA=$GITHUB_SHA
TEST_EXPECTED_TAG=$GITHUB_REF_NAME

gh() {
  case "$1 $2" in
    'api repos/'*)
      test "$*" = "api repos/$GITHUB_REPOSITORY/commits/$TEST_EXPECTED_TAG --jq .sha"
      printf '%s\n' "$TEST_RELEASE_SHA"
      ;;
    'release view')
      test "$*" = "release view $TEST_EXPECTED_TAG --json isDraft --jq .isDraft"
      printf '%s\n' "$TEST_DRAFT"
      ;;
    'release download')
      test "$*" = "release download $TEST_EXPECTED_TAG --pattern Tunnex-release-source.json --output -"
      jq -cn --arg tag "$TEST_EXPECTED_TAG" --arg source_sha "$TEST_LEDGER_SHA" \
        '{schema_version:1,tag:$tag,source_sha:$source_sha}'
      ;;
    'release edit')
      printf '%s\n' "$*" >> "$STAGE/edits"
      ;;
    *) printf 'unexpected fixture GitHub command\n' >&2; return 1 ;;
  esac
}

run_step() {
  : > "$STAGE/edits"
  # An independent shell preserves errexit inside the workflow even when the
  # parent is observing an expected refusal in an if statement.
  export -f gh
  export STAGE TEST_RELEASE_SHA TEST_DRAFT TEST_LEDGER_SHA TEST_EXPECTED_TAG
  bash "$STAGE/completion.bash" > "$STAGE/output" 2>&1
}

run_step
test "$(cat "$STAGE/edits")" = 'release edit v1.2.3 --draft=false --latest'

GITHUB_REF=refs/heads/main
GITHUB_REF_NAME=main
TEST_EXPECTED_TAG="tunnex-build-$GITHUB_SHA"
run_step
test "$(cat "$STAGE/edits")" = "release edit $TEST_EXPECTED_TAG --draft=false --prerelease --latest=false"

GITHUB_REF=refs/tags/v1.2.3
GITHUB_REF_NAME=v1.2.3
TEST_EXPECTED_TAG=v1.2.3
for refusal in moved-source published-release wrong-ledger; do
  TEST_RELEASE_SHA=$GITHUB_SHA
  TEST_DRAFT=true
  TEST_LEDGER_SHA=$GITHUB_SHA
  case "$refusal" in
    moved-source) TEST_RELEASE_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    published-release) TEST_DRAFT=false ;;
    wrong-ledger) TEST_LEDGER_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
  esac
  if run_step; then
    printf 'release completion accepted %s\n' "$refusal" >&2
    exit 1
  fi
  test ! -s "$STAGE/edits"
done

printf 'release completion contract: PASS\n'
