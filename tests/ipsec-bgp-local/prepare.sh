#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p .runtime/bin
stage=
cleanup() {
 [ -z "$stage" ] || rm -rf "$stage"
 rm -f .runtime/bin/tunnex-api.next .runtime/bin/tunnex-node.next .runtime/env.next .runtime/build.next
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
if [ ! -f .runtime/env ]; then
 token=$(openssl rand -hex 32)
 hash=$(printf '%s' "$token" | shasum -a 256 | awk '{print $1}')
 password=$(openssl rand -hex 24)
 printf 'BGPLOCAL_JOIN_TOKEN=%s\nBGPLOCAL_JOIN_HASH=%s\nBGPLOCAL_DB_PASSWORD=%s\n' "$token" "$hash" "$password" > .runtime/env
fi
./ownership.py
arch=$(./docker-local.sh info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) exit 1 ;; esac
root=$(cd ../.. && pwd)
. ./toolchain.sh
python3 ./source-manifest.py --output .runtime/source-before.json
(cd "$root/apps/api" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$local_go" build -trimpath -o "$root/tests/ipsec-bgp-local/.runtime/bin/tunnex-api.next" ./cmd/server)
(cd "$root/apps/node" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$local_go" build -trimpath -o "$root/tests/ipsec-bgp-local/.runtime/bin/tunnex-node.next" ./cmd/agent)
stage=$(mktemp -d /private/tmp/tunnex-bgp-build.XXXXXX)
mkdir -p "$stage/apps" "$stage/packages" "$stage/deploy/docker"
cp -R "$root/apps/node" "$stage/apps/node"
cp -R "$root/packages/apptransport" "$stage/packages/apptransport"
cp -R "$root/deploy/ipsec" "$stage/deploy/ipsec"
if [ -d "$root/deploy/bgp" ]; then
 cp -R "$root/deploy/bgp" "$stage/deploy/bgp"
fi
cp "$root/deploy/docker/node.Dockerfile" "$stage/deploy/docker/node.Dockerfile"
find "$stage" -type d -name node_modules -prune -exec rm -rf {} +
tag=tunnexs2sbgplocal1007:node
./docker-local.sh build --platform "linux/$arch" --label com.docker.compose.project=tunnexs2sbgplocal1007 -f "$stage/deploy/docker/node.Dockerfile" -t "$tag" "$stage" > .runtime/node-build.log 2>&1
image=$(./docker-local.sh image inspect --format '{{.Id}}' "$tag")
# This reads the image's internal binary, independently of the serving bind mount.
internal_binary=$(./docker-local.sh run --rm --network none --cap-drop ALL --read-only --security-opt no-new-privileges --label com.docker.compose.project=tunnexs2sbgpbuild1007 --entrypoint /usr/bin/sha256sum "$image" /usr/local/bin/tunnex-node | awk '{print $1}')
[ "${#internal_binary}" -eq 64 ] || { echo 'Image internal node hash unavailable' >&2; exit 1; }
python3 ./source-manifest.py --output .runtime/source-after.json
cmp -s .runtime/source-before.json .runtime/source-after.json || { echo 'Product source changed during preparation; serving binaries retained' >&2; exit 1; }
mounted_api_binary=$(shasum -a 256 .runtime/bin/tunnex-api.next | awk '{print $1}')
mounted_node_binary=$(shasum -a 256 .runtime/bin/tunnex-node.next | awk '{print $1}')
# All compile/image qualification commands above must succeed before publishing
# either mounted executable, resource metadata or the Compose image selection.
python3 ./prepare-resources.py
# Compose always runs the captured immutable image, not the mutable tag.
sed '/^BGPLOCAL_NODE_IMAGE=/d' .runtime/env > .runtime/env.next
printf 'BGPLOCAL_NODE_IMAGE=%s\n' "$image" >> .runtime/env.next
{ git -C "$root" rev-parse HEAD; git -C "$root" branch --show-current; printf 'architecture=%s\nnode_image=%s\ntoolchain=%s\nimage_internal_node_sha256=%s\nserving_node_path=/binaries/tunnex-node\nserving_mounted_api_sha256=%s\nserving_mounted_node_sha256=%s\n' "$arch" "$image" "$local_go_version" "$internal_binary" "$mounted_api_binary" "$mounted_node_binary"; python3 -c 'import json; m=json.load(open(".runtime/source-after.json")); print("\n".join(k+"="+v for k,v in m.items() if k!="source_files"))'; } > .runtime/build.next
mv .runtime/bin/tunnex-api.next .runtime/bin/tunnex-api
mv .runtime/bin/tunnex-node.next .runtime/bin/tunnex-node
mv .runtime/env.next .runtime/env
mv .runtime/build.next .runtime/build.txt
