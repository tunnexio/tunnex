#!/bin/sh
# Offline final-layer build. Use a locally preloaded, qualified Ubuntu base.
set -eu
base_image=${1:?pass approved Ubuntu base image by digest}
target_arch=${2:?pass amd64 or arm64}
image_tag=${3:?pass task-owned output image tag}
case "$target_arch" in amd64|arm64) ;; *) exit 2 ;; esac
case "$base_image" in *@sha256:*) ;; *) exit 2 ;; esac
base_digest=${base_image##*@sha256:}
test "${#base_digest}" = 64
case "$base_digest" in *[!a-f0-9]*) exit 2 ;; esac
case "$image_tag" in tunnex-sandbox-*) ;; *) exit 2 ;; esac
command -v podman >/dev/null
command -v go >/dev/null
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
# Build only committed tracked source. Context below contains no repository,
# credentials, dependency tree or user workspace; only this recipe and binary.
git -C "$source_dir" diff --quiet
git -C "$source_dir" diff --cached --quiet
source_sha=$(git -C "$source_dir" rev-parse HEAD)
context_dir=$(mktemp -d)
source_copy=$(mktemp -d)
trap 'rm -rf -- "$context_dir" "$source_copy"' EXIT HUP INT TERM
mkdir "$context_dir/runtime"
git -C "$source_dir" show "$source_sha:deploy/sandbox/Containerfile" > "$context_dir/Containerfile"
git -C "$source_dir" show "$source_sha:deploy/sandbox/sandbox-entrypoint.py" > "$context_dir/sandbox-entrypoint.py"
# An archive of committed CLI source excludes ignored/untracked credentials and
# scratch code. Keep it outside the image context, and remove after compilation.
git -C "$source_dir" archive "$source_sha" apps/cli | tar -x -C "$source_copy"
(
 cd "$source_copy/apps/cli"
 CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" GOFLAGS=-mod=readonly \
 go build -trimpath -ldflags='-s -w' -o "$context_dir/runtime/tunnex-sandbox-bootstrap" ./cmd/tunnex-sandbox-bootstrap
)
# Refuse pull/network during image assembly; base/tool qualification is separate.
podman build --pull=never --network=none --platform="linux/$target_arch" \
 --build-arg "BASE_IMAGE=$base_image" --build-arg "SOURCE_SHA=$source_sha" \
 --tag "$image_tag" "$context_dir"
