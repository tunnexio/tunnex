#!/usr/bin/env bash
# Execute the actual workflow script with offline GitHub/GHCR substitutes.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
ruby -ryaml -e 'puts YAML.load_file(ARGV[0]).fetch("jobs").fetch("release-version-guard").fetch("steps").first.fetch("run")' "${1:-$ROOT/.github/workflows/ci.yml}" >"$TMP/guard.sh"
mkdir "$TMP/bin"
cat >"$TMP/bin/curl" <<'SH'
#!/usr/bin/env bash
set -eu
out=/dev/null
previous=
for arg in "$@"; do
  if [[ "$previous" == -o ]]; then out=$arg; fi
  previous=$arg
done
case "${!#}" in
  https://ghcr.io/token) printf '%s\n' '{"token":"offline-fixture"}' ;;
  https://ghcr.io/v2/*) printf 404 ;;
  */git/ref/tags/*)
    if [[ -f "$MOCK_STATE/ref" ]]; then printf 200; else printf 404; fi ;;
  */releases/tags/*)
    if [[ "$MOCK_CASE" == published ]]; then
      printf '%s\n' '{"draft":false,"assets":[]}' >"$out"; printf 200
    else printf 404; fi ;;
  *) exit 90 ;;
esac
SH
cat >"$TMP/bin/gh" <<'SH'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >>"$MOCK_STATE/calls"
case "$*" in
  'release create '*) : ;; # Real draft creation does NOT create a Git ref.
  'api --method POST '*'/git/refs '*)
    [[ ! -f "$MOCK_STATE/ref" ]] || exit 92
    [[ "$*" == *"ref=refs/tags/tunnex-build-${GITHUB_SHA}"* ]] || exit 93
    [[ "$*" == *"sha=${GITHUB_SHA}"* ]] || exit 94
    printf '%s\n' "$GITHUB_SHA" >"$MOCK_STATE/ref" ;;
  'api '*'/commits/'*)
    if [[ -f "$MOCK_STATE/ref" ]]; then cat "$MOCK_STATE/ref"; else echo 'HTTP 422: draft has no Git ref' >&2; exit 1; fi ;;
  *) exit 91 ;;
esac
SH
chmod +x "$TMP/bin/curl" "$TMP/bin/gh"
export GITHUB_REPOSITORY=tunnexio/tunnex GITHUB_REPOSITORY_OWNER=tunnexio
export GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export GITHUB_REF=refs/heads/main GITHUB_REF_NAME=main GITHUB_ACTOR=fixture GH_TOKEN=fixture
for scenario in missing matching moved published; do
  mkdir "$TMP/$scenario"
  case "$scenario" in
    matching) printf '%s\n' "$GITHUB_SHA" >"$TMP/$scenario/ref" ;;
    moved) printf '%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >"$TMP/$scenario/ref" ;;
  esac
  if PATH="$TMP/bin:$PATH" MOCK_STATE="$TMP/$scenario" MOCK_CASE="$scenario" bash "$TMP/guard.sh" >"$TMP/$scenario/output" 2>&1; then
    [[ "$scenario" == missing || "$scenario" == matching ]] || { echo "unexpected acceptance: $scenario"; exit 1; }
    [[ $(cat "$TMP/$scenario/ref") == "$GITHUB_SHA" ]]
  else
    [[ "$scenario" == moved || "$scenario" == published ]] || { cat "$TMP/$scenario/output"; exit 1; }
  fi
  if [[ "$scenario" == missing ]]; then
    grep -q 'api --method POST .*git/refs' "$TMP/$scenario/calls"
  elif [[ -f "$TMP/$scenario/calls" ]]; then
    ! grep -q 'api --method POST .*git/refs' "$TMP/$scenario/calls"
  fi
done
echo 'Release source-ref lifecycle passed: draft without tag, existing exact tag, moved tag, published release'
