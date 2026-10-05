#!/bin/sh
# Build a candidate only; does not register or activate a provider template.
set -eu
arch=${1:?pass amd64 or arm64}
tag=${2:?pass task-owned tunnex-sandbox-* tag}
profile=${3:-minimal}
case "$profile" in minimal|python|node) ;; *) exit 2 ;; esac
case "$arch" in amd64|arm64) ;; *) exit 2 ;; esac
case "$tag" in tunnex-sandbox-*) ;; *) exit 2 ;; esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
git -C "$root" diff --quiet
git -C "$root" diff --cached --quiet
sha=$(git -C "$root" rev-parse HEAD)
context=$(mktemp -d)
source_copy=$(mktemp -d)
trap 'rm -rf -- "$context" "$source_copy"' EXIT HUP INT TERM
mkdir "$context/runtime"
git -C "$root" show "$sha:deploy/sandbox/alpine/Containerfile" > "$context/Dockerfile"
git -C "$root" show "$sha:deploy/sandbox/alpine/entrypoint.sh" > "$context/entrypoint.sh"
git -C "$root" archive "$sha" apps/cli | tar -x -C "$source_copy"
(cd "$source_copy/apps/cli"; CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOFLAGS=-mod=readonly go build -p=2 -trimpath -ldflags='-s -w' -o "$context/runtime/tunnex-sandbox-bootstrap" ./cmd/tunnex-sandbox-bootstrap)
# Alpine's signed official repositories are used here, never on launch.
docker build --target="$profile" --platform="linux/$arch" --build-arg "SOURCE_SHA=$sha" --tag "$tag" "$context"
