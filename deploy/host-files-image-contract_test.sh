#!/bin/sh
# UPG-2 packaging contract: the signed API image carries exactly the host files
# that upgrade.sh extracts and hands off to, at /usr/share/tunnex/host, plus the
# hand-off ABI marker. Set TUNNEX_TEST_DOCKER_RUNTIME=1 to also build those
# layers on a local daemon and extract them the way upgrade.sh does.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DOCKERFILE="$ROOT/deploy/docker/api.Dockerfile"
SCRIPT="$ROOT/deploy/upgrade.sh"
fail() { echo "host files contract: $*" >&2; exit 1; }

list=$(sed -n "s/^HOST_FILE_LIST='\(.*\)'\$/\1/p" "$SCRIPT")
[ -n "$list" ] || fail 'upgrade.sh does not declare HOST_FILE_LIST'
abi=$(sed -n "s/^HOST_ABI=\([0-9]*\)\$/\1/p" "$SCRIPT")
[ "$abi" = "$(cat "$ROOT/deploy/HOST_ABI")" ] || fail 'deploy/HOST_ABI differs from the ABI upgrade.sh speaks'
grep -Fqx "HOST_IMAGE_DIR=/usr/share/tunnex/host" "$SCRIPT" || fail 'upgrade.sh extracts from a different image path'

# Expected "source destination-directory" pairs, one per file.
expected=$(
  printf '%s %s\n' deploy/HOST_ABI /usr/share/tunnex/host/
  for f in $list; do
    d=$(dirname "$f"); [ "$d" = . ] && d= || d="$d/"
    [ -f "$ROOT/deploy/$f" ] || fail "listed host file deploy/$f does not exist"
    printf '%s %s\n' "deploy/$f" "/usr/share/tunnex/host/$d"
  done | sort
)
# Actual pairs from the Dockerfile COPY instructions into the host directory.
actual=$(awk '$1 == "COPY" && $NF ~ /^\/usr\/share\/tunnex\/host\// {
  for (i = 2; i < NF; i++) if ($i !~ /^--/) print $i, $NF }' "$DOCKERFILE" | sort)
[ "$expected" = "$(printf '%s\n' "$actual" | sort | uniq)" ] || {
  printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
  fail 'api.Dockerfile does not copy exactly the host files upgrade.sh requires'
}
[ "$(printf '%s\n' "$actual" | wc -l)" -eq "$(printf '%s\n' "$expected" | wc -l)" ] || fail 'duplicate host file COPY'
# The files belong to the final (runtime) stage, not the Go build stage.
last_from=$(grep -n '^FROM ' "$DOCKERFILE" | tail -1 | cut -d: -f1)
first_copy=$(grep -n '/usr/share/tunnex/host/' "$DOCKERFILE" | head -1 | cut -d: -f1)
[ "$first_copy" -gt "$last_from" ] || fail 'host files are not in the runtime stage'
# The build context must not exclude them.
! grep -Eq '^(deploy|deploy/\*|deploy/upgrade\.sh)$' "$ROOT/.dockerignore" || fail '.dockerignore excludes host files'

if [ "${TUNNEX_TEST_DOCKER_RUNTIME:-}" = 1 ]; then
  TMP=$(mktemp -d)
  tag=tunnex-upg2-host-files-contract:local
  cid=
  cleanup() {
    [ -z "$cid" ] || docker rm "$cid" >/dev/null 2>&1 || true
    docker rmi "$tag" >/dev/null 2>&1 || true
    rm -rf "$TMP"
  }
  trap cleanup EXIT HUP INT TERM
  base=$(sed -n "$last_from"'s/^FROM \([^ ]*\).*/\1/p' "$DOCKERFILE")
  {
    printf 'FROM %s\n' "$base"
    grep '^COPY .*/usr/share/tunnex/host/' "$DOCKERFILE"
    printf '%s\n' 'ENTRYPOINT ["/bin/false"]'
  } >"$TMP/Dockerfile"
  docker build -q -f "$TMP/Dockerfile" -t "$tag" "$ROOT" >/dev/null
  image=$(docker image inspect --format '{{.Id}}' "$tag")
  # Exactly the extraction upgrade.sh performs: create (never start), copy, remove.
  cid=$(docker create --pull never --network none "$image")
  mkdir "$TMP/host"
  docker cp "$cid:/usr/share/tunnex/host/." "$TMP/host"
  [ "$(docker inspect --format '{{.State.Status}}' "$cid")" = created ] || fail 'extraction started the image'
  cmp -s "$ROOT/deploy/HOST_ABI" "$TMP/host/HOST_ABI" || fail 'HOST_ABI differs in the image'
  for f in $list; do
    cmp -s "$ROOT/deploy/$f" "$TMP/host/$f" || fail "image copy of $f differs from deploy/$f"
  done
  echo 'host files extracted from a locally built image layer match the source'
fi
echo 'host files image contract passed'
