#!/bin/sh
set -eu
cd "$(dirname "$0")"
# run.sh checks the project belongs to this checkout before inspecting its target.
target=$(./run.sh ps -q ssh-target)
[ -n "$target" ] || { echo 'Owned SSH fixture is unavailable' >&2; exit 1; }
image=$(./docker-local.sh inspect --format '{{.Image}}' "$target")
exec ./docker-local.sh run --rm --name "tunnex-sa0-recording-review-$$" \
 --label tunnex.sa0.review=recording --network none --read-only \
 --tmpfs /tmp:rw,size=1048576,mode=1777 --tmpfs /capture:rw,size=65536,mode=0700 \
 --mount "type=bind,src=$(pwd -P)/primitive-probe.py,dst=/probe.py,readonly" \
 --env SA0_FULL_DISK_DIR=/capture --entrypoint python3 "$image" /probe.py
