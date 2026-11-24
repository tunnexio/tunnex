#!/bin/sh
# UPG-2 contract: the installed upgrade.sh verifies the signed release, refuses
# downgrade/replay, extracts the target release's host files from the
# digest-pinned API image without running it, and execs the target script
# through the frozen hand-off interface (ABI 1). Everything external is faked:
# no network, Docker daemon or root is required.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
API_IMAGE=ghcr.io/tunnexio/tunnex-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export API_IMAGE

# The image carries exactly the files the helper lists, at deploy/<path>.
HOST_FILE_LIST=$(sed -n "s/^HOST_FILE_LIST='\(.*\)'\$/\1/p" "$ROOT/deploy/upgrade.sh")
[ -n "$HOST_FILE_LIST" ] || { echo 'upgrade.sh does not declare HOST_FILE_LIST' >&2; exit 1; }
stage_host_files() {
  mkdir -p "$1"
  cp "$ROOT/deploy/HOST_ABI" "$1/HOST_ABI"
  for f in $HOST_FILE_LIST; do
    mkdir -p "$1/$(dirname "$f")"
    cp "$ROOT/deploy/$f" "$1/$f"
  done
}

mkdir -p "$TMP/bin" "$TMP/tmpbase"
cat >"$TMP/bin/curl" <<'SH'
#!/bin/sh
set -eu
[ "$1" = -fsSL ] && [ "$3" = -o ]
case "$2" in
  https://updates.example.test/release.json) cp "$MOCK_CATALOG" "$4" ;;
  *) echo "unexpected network fetch: $2" >&2; exit 1 ;;
esac
SH
# The fake verifier authenticates any fixture and reports the identity written
# into it, so each test controls the target and the installed descriptor.
cat >"$TMP/bin/releaseverify" <<'SH'
#!/bin/sh
set -eu
[ "$1" = -manifest ] && [ "$3" = -public-key ] && [ "$4" = test-public-key ]
grep -Fq '"signed":true' "$2" || exit 1
case " $* " in *' -print-env '*)
  seq=$(sed -n 's/.*"sequence":\([0-9]*\).*/\1/p' "$2")
  sha=$(sed -n 's/.*"source_sha":"\([0-9a-f]*\)".*/\1/p' "$2")
  api=$(sed -n 's/.*"api":"\([^"]*\)".*/\1/p' "$2")
  printf 'TUNNEX_RELEASE_SOURCE_SHA=%s\nTUNNEX_RELEASE_VERSION=v%s\nTUNNEX_RELEASE_SEQUENCE=%s\n' "$sha" "$seq" "$seq"
  printf 'TUNNEX_API_IMAGE=%s\n' "${api:-$API_IMAGE}"
;; esac
SH
cat >"$TMP/bin/docker" <<'SH'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$MOCK_DOCKER_LOG"
case "$*" in
  "pull $API_IMAGE") [ "${MOCK_PULL_FAIL:-}" != 1 ] || exit 1 ;;
  "create --pull never --network none $API_IMAGE") echo fixture-cid ;;
  "cp fixture-cid:/usr/share/tunnex/host/. "*) cp -R "$MOCK_HOST_FILES/." "$3/" ;;
  'rm fixture-cid') ;;
  'ps -a --filter '*) ;;
  *) echo "unexpected docker call: $*" >&2; exit 1 ;;
esac
SH
chmod 0755 "$TMP/bin/curl" "$TMP/bin/releaseverify" "$TMP/bin/docker"

# A recording target stands in for the target release's upgrade.sh. It proves
# what the trampoline handed over and that it replaced itself via exec.
make_recording_target() {
  stage_host_files "$1"
  cat >"$1/upgrade.sh" <<'SH'
#!/bin/sh
set -eu
{
  printf 'args=%s\n' "$*"
  for v in TUNNEX_DIR TUNNEX_ENV_FILE TUNNEX_COMPOSE_FILE TUNNEX_RELEASE_PUBLIC_KEY \
    TUNNEX_UPGRADE_STATUS_FILE TUNNEX_UPGRADE_REQUEST_ID TUNNEX_UPGRADE_PRIVILEGED \
    TUNNEX_UPGRADE_HANDOFF TUNNEX_UPGRADE_HANDOFF_ABI TUNNEX_UPGRADE_HANDOFF_DIR; do
    eval "printf '%s=%s\n' $v \"\${$v-UNSET}\""
  done
  printf 'script=%s\n' "$0"
} >"$MOCK_TARGET_RECORD"
# The manifest handed over must be the exact verified bytes.
cmp -s "$2" "$MOCK_CATALOG"
if [ -n "$TUNNEX_UPGRADE_STATUS_FILE" ]; then
  printf 'request_id=%s\nstate=%s\n' "$TUNNEX_UPGRADE_REQUEST_ID" "${MOCK_TARGET_STATE:-healthy}" >"$TUNNEX_UPGRADE_STATUS_FILE"
fi
rm -rf "$TUNNEX_UPGRADE_HANDOFF_DIR"
exit "${MOCK_TARGET_EXIT:-0}"
SH
  chmod 0755 "$1/upgrade.sh"
}

new_install() {
  dir="$TMP/install-$1"
  mkdir -p "$dir"
  dir=$(CDPATH= cd -- "$dir" && pwd -P)
  cp "$ROOT/deploy/upgrade.sh" "$dir/upgrade.sh"
  chmod 0755 "$dir/upgrade.sh"
  printf '%s\n' '# installed deployment' >"$dir/tunnex.yml"
  cat >"$dir/.env" <<'ENV'
TUNNEX_RELEASE_PUBLIC_KEY=test-public-key
TUNNEX_RELEASE_CATALOG_URL=https://updates.example.test/release.json
ENV
  # installed: sequence 98 at SHA_B unless a case says otherwise
  printf '{"signed":true,"sequence":%s,"source_sha":"%s"}\n' "${2:-98}" "${3:-$SHA_B}" >"$dir/release.json"
  printf '{"signed":true,"sequence":%s,"source_sha":"%s"%s}\n' "${4:-99}" "${5:-$SHA_A}" "${6:-}" >"$TMP/catalog-$1.json"
  make_recording_target "$TMP/image-$1"
  : >"$TMP/docker-$1.log"
}
run_trampoline() (
  name=$1; shift
  cd "$TMP/install-$name"
  PATH="$TMP/bin:$PATH" MOCK_CATALOG="$TMP/catalog-$name.json" MOCK_HOST_FILES="$TMP/image-$name" \
    MOCK_DOCKER_LOG="$TMP/docker-$name.log" MOCK_TARGET_RECORD="$TMP/record-$name" \
    TUNNEX_RELEASEVERIFY="$TMP/bin/releaseverify" \
    TUNNEX_UPGRADE_STATUS_FILE="$TMP/install-$name/status" \
    TUNNEX_UPGRADE_REQUEST_ID=12345678-1234-1234-1234-123456789abc TMPDIR="$TMP/tmpbase" \
    "${SHELL_UNDER_TEST:-sh}" ./upgrade.sh "$@"
)
record() { sed -n "s/^$2=//p" "$TMP/record-$1"; }
refused() {
  # name reason message
  [ ! -e "$TMP/record-$1" ] || { echo "$1: target ran although the hand-off was refused" >&2; exit 1; }
  grep -Fxq 'state=failed' "$TMP/install-$1/status"
  grep -Fxq "reason_code=$2" "$TMP/install-$1/status" || { cat "$TMP/install-$1/status" >&2; exit 1; }
  grep -Fq -- "$3" "$TMP/out-$1" || { cat "$TMP/out-$1" >&2; exit 1; }
  ! grep -Eq '^(ps|compose|start|run|exec) ' "$TMP/docker-$1.log"
}

for SHELL_UNDER_TEST in sh dash; do
  command -v "$SHELL_UNDER_TEST" >/dev/null 2>&1 || continue
  export SHELL_UNDER_TEST
  rm -rf "$TMP"/install-* "$TMP"/image-* "$TMP"/record-* "$TMP"/out-* "$TMP"/catalog-* "$TMP"/docker-*

  # 1. Newer target: verified, extracted from the pinned image, exec'd with ABI 1
  #    before any admission or backup, in apply mode.
  new_install newer
  run_trampoline newer --apply --expected-source-sha "$SHA_A" --expected-sequence 99 >"$TMP/out-newer" 2>&1 ||
    { cat "$TMP/out-newer" >&2; exit 1; }
  [ "$(record newer args)" = "--manifest $(record newer TUNNEX_UPGRADE_HANDOFF_DIR)/release.json --apply --expected-source-sha $SHA_A --expected-sequence 99" ]
  [ "$(record newer TUNNEX_DIR)" = "$TMP/install-newer" ]
  [ "$(record newer TUNNEX_ENV_FILE)" = "$TMP/install-newer/.env" ]
  [ "$(record newer TUNNEX_COMPOSE_FILE)" = "$TMP/install-newer/tunnex.yml" ]
  [ "$(record newer TUNNEX_RELEASE_PUBLIC_KEY)" = test-public-key ]
  [ "$(record newer TUNNEX_UPGRADE_STATUS_FILE)" = "$TMP/install-newer/status" ]
  [ "$(record newer TUNNEX_UPGRADE_REQUEST_ID)" = 12345678-1234-1234-1234-123456789abc ]
  [ "$(record newer TUNNEX_UPGRADE_PRIVILEGED)" = '' ]
  [ "$(record newer TUNNEX_UPGRADE_HANDOFF)" = 1 ]
  [ "$(record newer TUNNEX_UPGRADE_HANDOFF_ABI)" = 1 ]
  [ "$(record newer script)" = "$(record newer TUNNEX_UPGRADE_HANDOFF_DIR)/host/upgrade.sh" ]
  # The status the target wrote is final: the old helper's EXIT trap is gone.
  grep -Fxq 'request_id=12345678-1234-1234-1234-123456789abc' "$TMP/install-newer/status"
  grep -Fxq 'state=healthy' "$TMP/install-newer/status"
  # The image is pulled by digest, created without pulling or starting, copied
  # from, and removed; nothing about admission or backup happened first.
  [ "$(cat "$TMP/docker-newer.log")" = "pull $API_IMAGE
create --pull never --network none $API_IMAGE
cp fixture-cid:/usr/share/tunnex/host/. $(record newer TUNNEX_UPGRADE_HANDOFF_DIR)/host
rm fixture-cid" ]
  # Installed files are untouched by the trampoline.
  cmp -s "$ROOT/deploy/upgrade.sh" "$TMP/install-newer/upgrade.sh"

  # 2. A target failure after exec keeps the target's own status and exit code.
  new_install target-fails
  if MOCK_TARGET_EXIT=7 MOCK_TARGET_STATE=failed run_trampoline target-fails --apply >"$TMP/out-target-fails" 2>&1; then
    echo 'target failure was masked' >&2; exit 1
  fi
  unset MOCK_TARGET_EXIT MOCK_TARGET_STATE # POSIX sh keeps assignments made before a function call
  grep -Fxq 'state=failed' "$TMP/install-target-fails/status"
  ! grep -Fq 'reason_code=' "$TMP/install-target-fails/status"

  # 3. Dry runs hand off too; the target decides what it would do.
  new_install dry
  run_trampoline dry >"$TMP/out-dry" 2>&1 || { cat "$TMP/out-dry" >&2; exit 1; }
  [ "$(record dry args)" = "--manifest $(record dry TUNNEX_UPGRADE_HANDOFF_DIR)/release.json" ]

  # 4. Same release and same source: a forward-fix re-run is allowed.
  new_install rerun 99 "$SHA_A"
  run_trampoline rerun --apply >"$TMP/out-rerun" 2>&1 || { cat "$TMP/out-rerun" >&2; exit 1; }
  [ -e "$TMP/record-rerun" ]

  # 5. Same sequence, different source: refused.
  new_install conflict 99 "$SHA_B"
  if run_trampoline conflict --apply >"$TMP/out-conflict" 2>&1; then echo 'release conflict accepted' >&2; exit 1; fi
  refused conflict release_conflict 'same sequence as the installed release but a different source'

  # 6. Older target: refused, and there is no override.
  new_install downgrade 100 "$SHA_B"
  if run_trampoline downgrade --apply >"$TMP/out-downgrade" 2>&1; then echo 'downgrade accepted' >&2; exit 1; fi
  refused downgrade downgrade_refused 'older than the installed release'
  ! grep -Fq 'pull ' "$TMP/docker-downgrade.log"

  # 7. Missing or unverifiable installed descriptor: refused by default.
  for broken in missing unsigned; do
    new_install "unknown-$broken"
    case "$broken" in
      missing) rm "$TMP/install-unknown-$broken/release.json" ;;
      unsigned) printf '%s\n' '{"sequence":1}' >"$TMP/install-unknown-$broken/release.json" ;;
    esac
    if run_trampoline "unknown-$broken" --apply >"$TMP/out-unknown-$broken" 2>&1; then
      echo "installed descriptor ($broken) accepted" >&2; exit 1
    fi
    refused "unknown-$broken" installed_release_unknown '--accept-installed-unknown'
  done
  # ...the command-line override proceeds and is passed to the target...
  new_install accept
  rm "$TMP/install-accept/release.json"
  run_trampoline accept --apply --accept-installed-unknown >"$TMP/out-accept" 2>&1 || { cat "$TMP/out-accept" >&2; exit 1; }
  grep -Fq 'installed release could not be verified' "$TMP/out-accept"
  case " $(record accept args) " in *' --accept-installed-unknown '*) ;; *) echo 'override not handed to target' >&2; exit 1 ;; esac
  # ...but never from the privileged dashboard runner.
  new_install accept-runner
  rm "$TMP/install-accept-runner/release.json"
  if TUNNEX_UPGRADE_PRIVILEGED=1 run_trampoline accept-runner --apply --accept-installed-unknown >"$TMP/out-accept-runner" 2>&1; then
    echo 'runner accepted --accept-installed-unknown' >&2; exit 1
  fi
  unset TUNNEX_UPGRADE_PRIVILEGED
  grep -Fq 'command line only' "$TMP/out-accept-runner"
  [ ! -e "$TMP/record-accept-runner" ]

  # 8. The API image must be pinned by digest.
  new_install mutable 98 "$SHA_B" 99 "$SHA_A" ',"api":"ghcr.io/tunnexio/tunnex-api:v9.9.9"'
  if run_trampoline mutable --apply >"$TMP/out-mutable" 2>&1; then echo 'mutable API image accepted' >&2; exit 1; fi
  refused mutable handoff_failed 'does not pin the API image by digest'
  [ ! -s "$TMP/docker-mutable.log" ]

  # 9. Pull or extraction failures and incomplete or unknown-ABI images refuse.
  new_install pull-fails
  if MOCK_PULL_FAIL=1 run_trampoline pull-fails --apply >"$TMP/out-pull-fails" 2>&1; then echo 'pull failure accepted' >&2; exit 1; fi
  unset MOCK_PULL_FAIL
  refused pull-fails handoff_failed 'could not extract'
  new_install incomplete
  rm "$TMP/image-incomplete/app-access/restore.py"
  if run_trampoline incomplete --apply >"$TMP/out-incomplete" 2>&1; then echo 'incomplete host files accepted' >&2; exit 1; fi
  refused incomplete handoff_failed 'incomplete'
  grep -Fxq 'rm fixture-cid' "$TMP/docker-incomplete.log"
  new_install abi
  printf '%s\n' 2 >"$TMP/image-abi/HOST_ABI"
  if run_trampoline abi --apply >"$TMP/out-abi" 2>&1; then echo 'unknown hand-off ABI accepted' >&2; exit 1; fi
  refused abi handoff_unsupported 'hand-off interface'
  # No temporary hand-off directory survives a refusal or a completed hand-off.
  [ -z "$(ls -A "$TMP/tmpbase")" ] || { ls -A "$TMP/tmpbase" >&2; echo 'hand-off directory leaked' >&2; exit 1; }

  # 10. The approved-release binding is still checked before anything is pulled.
  new_install approved
  if run_trampoline approved --apply --expected-source-sha "$SHA_B" >"$TMP/out-approved" 2>&1; then echo 'approval mismatch accepted' >&2; exit 1; fi
  refused approved approved_release_changed 'no longer matches the release approved in the UI'
  [ ! -s "$TMP/docker-approved.log" ]

  # 11. A target invoked with an unknown hand-off ABI refuses before admission.
  new_install target-abi
  stage_host_files "$TMP/handoff-target-abi/host"
  if (cd "$TMP/install-target-abi" && PATH="$TMP/bin:$PATH" MOCK_DOCKER_LOG="$TMP/docker-target-abi.log" \
    TUNNEX_UPGRADE_HANDOFF=1 TUNNEX_UPGRADE_HANDOFF_ABI=2 TUNNEX_UPGRADE_HANDOFF_DIR="$TMP/handoff-target-abi" \
    TUNNEX_UPGRADE_STATUS_FILE="$TMP/install-target-abi/status" TUNNEX_UPGRADE_REQUEST_ID=target-abi \
    "$SHELL_UNDER_TEST" ./upgrade.sh --apply --manifest "$TMP/catalog-target-abi.json") >"$TMP/out-target-abi" 2>&1; then
    echo 'target accepted an unknown hand-off ABI' >&2; exit 1
  fi
  grep -Fxq 'reason_code=handoff_unsupported' "$TMP/install-target-abi/status"
  [ ! -s "$TMP/docker-target-abi.log" ]
  rm -rf "$TMP/handoff-target-abi"
done

# ---------------------------------------------------------------------------
# U8: a previous release's trampoline hands off to the current target. The
# current target runs for real (dry run, nothing mutated). Every released
# upgrade.sh that declares a hand-off ABI is exercised; until such a release
# exists, the current trampoline stands in for it.
compat_case() {
  label=$1 previous=$2
  dir="$TMP/compat-$label"
  mkdir -p "$dir"
  dir=$(CDPATH= cd -- "$dir" && pwd -P)
  cp "$previous" "$dir/upgrade.sh"
  printf '%s\n' '# installed deployment' >"$dir/tunnex.yml"
  printf '%s\n' TUNNEX_RELEASE_PUBLIC_KEY=test-public-key TUNNEX_RELEASE_CATALOG_URL=https://updates.example.test/release.json >"$dir/.env"
  printf '{"signed":true,"sequence":98,"source_sha":"%s"}\n' "$SHA_B" >"$dir/release.json"
  printf '{"signed":true,"sequence":99,"source_sha":"%s"}\n' "$SHA_A" >"$TMP/compat-catalog.json"
  stage_host_files "$TMP/compat-image-$label"
  (cd "$dir" && PATH="$TMP/bin:$PATH" MOCK_CATALOG="$TMP/compat-catalog.json" MOCK_HOST_FILES="$TMP/compat-image-$label" \
    MOCK_DOCKER_LOG="$dir/docker.log" TUNNEX_RELEASEVERIFY="$TMP/bin/releaseverify" \
    TUNNEX_UPGRADE_STATUS_FILE="$dir/status" TUNNEX_UPGRADE_REQUEST_ID=compat sh ./upgrade.sh) >"$dir/output" 2>&1 ||
    { echo "hand-off from $label to the current target failed" >&2; cat "$dir/output" >&2; exit 1; }
  grep -Fq 'dry run: re-run with --apply' "$dir/output"
  grep -Fxq 'request_id=compat' "$dir/status"
}
compat_case current "$ROOT/deploy/upgrade.sh"
compat_tags=0
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  for tag in $(git -C "$ROOT" tag --list 'v*' --sort=-v:refname 2>/dev/null | head -20); do
    git -C "$ROOT" cat-file -e "$tag:deploy/HOST_ABI" 2>/dev/null || continue
    [ "$(git -C "$ROOT" show "$tag:deploy/HOST_ABI")" = 1 ] || continue
    git -C "$ROOT" show "$tag:deploy/upgrade.sh" >"$TMP/upgrade-$tag.sh"
    compat_case "$tag" "$TMP/upgrade-$tag.sh"
    compat_tags=$((compat_tags + 1))
  done
fi
echo "hand-off compatibility: current trampoline plus $compat_tags released ABI-1 trampoline(s)"

echo 'upgrade hand-off contract passed'
