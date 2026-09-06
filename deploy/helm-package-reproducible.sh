#!/usr/bin/env bash
# One build-only seam shared by signed releases and private walk candidates.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# != 4 ]]; then
  echo 'usage: helm-package-reproducible.sh CHART VERSION APP_VERSION EXISTING_DESTINATION' >&2
  exit 1
fi
chart=$1 version=$2 app_version=$3 destination=$4
test -d "$chart"
test -d "$destination"
destination=$(cd "$destination" && pwd -P)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
helm package "$chart" --version "$version" --app-version "$app_version" --destination "$stage" >/dev/null
shopt -s nullglob
archives=("$stage"/*.tgz)
test "${#archives[@]}" -eq 1
archive=${archives[0]}
(
  # This helper has standard-library imports only. Build it outside the CLI
  # module graph so chart packaging cannot resolve unrelated CLI dependencies.
  cd "$stage"
  GOCACHE="${GOCACHE:-$stage/go-cache}" GOENV=off GOTOOLCHAIN=local GOWORK=off \
    GOFLAGS=-mod=readonly go run "$ROOT/apps/cli/cmd/chartarchive/main.go" \
    -input "$archive" -output "$destination/$(basename "$archive")"
)
