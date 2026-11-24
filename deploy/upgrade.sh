#!/bin/sh
# Tunnex host-side upgrade gate. No mutation occurs without --apply.
set -eu

# The installer places this helper next to tunnex.yml and .env. Resolve defaults
# from that installation directory so the customer command stays portable.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DIR=${TUNNEX_DIR:-$SCRIPT_DIR}
ENV_FILE=${TUNNEX_ENV_FILE:-$DIR/.env}
COMPOSE=${TUNNEX_COMPOSE_FILE:-$DIR/tunnex.yml}

# Read only updater settings from dotenv. Never source deployment configuration as
# shell code: it is operator-controlled input.
dotenv_value() {
  _name=$1
  [ -r "$ENV_FILE" ] || return 0
  sed -n "s/^${_name}=//p" "$ENV_FILE" | head -1
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# An explicit file is the air-gapped/import path. Online installations discover
# the next candidate from the signed catalog; neither path ever falls back to a
# mutable image tag.
MANIFEST=${TUNNEX_RELEASE_MANIFEST:-}
MANIFEST_EXPLICIT=false
if [ -n "$MANIFEST" ]; then MANIFEST_EXPLICIT=true; fi
PUBLIC_KEY=${TUNNEX_RELEASE_PUBLIC_KEY:-}
[ -n "$PUBLIC_KEY" ] || PUBLIC_KEY=$(dotenv_value TUNNEX_RELEASE_PUBLIC_KEY)
CATALOG_URL=${TUNNEX_RELEASE_CATALOG_URL:-}
[ -n "$CATALOG_URL" ] || CATALOG_URL=$(dotenv_value TUNNEX_RELEASE_CATALOG_URL)
COMPOSE_SHA256=${TUNNEX_COMPOSE_SHA256:-}
[ -n "$COMPOSE_SHA256" ] || COMPOSE_SHA256=$(dotenv_value TUNNEX_COMPOSE_SHA256)
PROJECT=${TUNNEX_COMPOSE_PROJECT:-${COMPOSE_PROJECT_NAME:-}}
[ -n "$PROJECT" ] || PROJECT=$(dotenv_value COMPOSE_PROJECT_NAME)
# BEGIN APP ACCESS COMPOSITION CLASSIFIER
# Inspect labels, mounts and port bindings only; never read or emit container
# environment secrets. Sets AA_* facts; refusal decisions are made by the caller.
AA_MARKER_DIR=/var/lib/tunnex/app-restore
AA_PROXY_SECRETS_TARGET=/etc/tunnex/app-proxy
classify_existing_app_access() {
  _aa_project=$1 _aa_directory=$2
  AA_API_COUNT=0 AA_PROXY_COUNT=0 AA_PROJECT_FOUND= AA_API_MARKER= AA_PROXY_MARKER=
  AA_PROXY_SECRETS= AA_PROXY_PORTS= AA_CONFIG_FILES= AA_CONFIG_CONFLICT=false
  AA_API_FILES= AA_PROXY_FILES= AA_FILES_SPLIT=false
  if [ -n "$_aa_project" ]; then
    _aa_filter="label=com.docker.compose.project=$_aa_project"
  else
    # Compose top-level name and first-file directory can override basename.
    # With no explicit project, scope inspection to the actual Compose checkout.
    _aa_filter="label=com.docker.compose.project.working_dir=$_aa_directory"
  fi
  _aa_ids=$(docker ps -a --filter "$_aa_filter" --format '{{.ID}}' 2>/dev/null) || {
    echo 'error: existing installation inspection failed; upgrade refused' >&2; return 1;
  }
  for _aa_id in $_aa_ids; do
    _aa_info=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.project.working_dir"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{range .Mounts}}{{if eq .Destination "/var/lib/tunnex/app-restore"}}{{.Type}}:{{.Name}};{{end}}{{end}}|{{range .Mounts}}{{if eq .Destination "/etc/tunnex/app-proxy"}}{{.Source}};{{end}}{{end}}|{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{$p}}={{.HostIp}}:{{.HostPort}};{{end}}{{end}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}|{{index .Config.Labels "com.docker.compose.oneoff"}}' "$_aa_id" 2>/dev/null) || {
      echo 'error: existing installation inspection failed; upgrade refused' >&2; return 1;
    }
    case "$_aa_info" in
      *'|'*'|'*'|'*'|'*'|'*'|'*'|'*'|'*) echo 'error: existing installation inspection failed; upgrade refused' >&2; return 1 ;;
      *'|'*'|'*'|'*'|'*'|'*'|'*) ;;
      *) echo 'error: existing installation inspection failed; upgrade refused' >&2; return 1 ;;
    esac
    _aa_saved_ifs=$IFS
    IFS='|' read -r _aa_found_project _aa_found_directory _aa_service _aa_marker _aa_secrets _aa_ports _aa_files _aa_oneoff <<EOF
$_aa_info
EOF
    IFS=$_aa_saved_ifs
    [ "$_aa_found_directory" = "$_aa_directory" ] || continue
    [ -z "$_aa_project" ] || [ "$_aa_found_project" = "$_aa_project" ] || continue
    [ -n "$_aa_found_project" ] && [ "$_aa_found_project" != '<no value>' ] || {
      echo 'error: existing installation inspection failed; upgrade refused' >&2; return 1;
    }
    # One-off helper containers (compose run) are not serving participants.
    [ "$_aa_oneoff" != True ] || continue
    case "$_aa_service" in
      api) [ -n "$_aa_marker" ] || continue
        AA_API_COUNT=$((AA_API_COUNT + 1)); AA_API_MARKER=$_aa_marker ;;
      app-proxy)
        AA_PROXY_COUNT=$((AA_PROXY_COUNT + 1)); AA_PROXY_MARKER=$_aa_marker
        AA_PROXY_SECRETS=$_aa_secrets AA_PROXY_PORTS=$_aa_ports ;;
      *) continue ;;
    esac
    [ -z "$AA_PROJECT_FOUND" ] || [ "$AA_PROJECT_FOUND" = "$_aa_found_project" ] || AA_CONFIG_CONFLICT=true
    AA_PROJECT_FOUND=$_aa_found_project
    # Same-service participants must agree. The API and the proxy may differ only
    # in one case the caller checks: an upgrade recreated the API from the managed
    # files and then failed while the stopped proxy kept the adopted file list.
    if [ "$_aa_service" = api ]; then
      [ -z "$AA_API_FILES" ] || [ "$AA_API_FILES" = "$_aa_files" ] || AA_CONFIG_CONFLICT=true
      AA_API_FILES=$_aa_files
    else
      [ -z "$AA_PROXY_FILES" ] || [ "$AA_PROXY_FILES" = "$_aa_files" ] || AA_CONFIG_CONFLICT=true
      AA_PROXY_FILES=$_aa_files
    fi
  done
  AA_CONFIG_FILES=${AA_API_FILES:-$AA_PROXY_FILES}
  [ -z "$AA_API_FILES" ] || [ -z "$AA_PROXY_FILES" ] || [ "$AA_API_FILES" = "$AA_PROXY_FILES" ] || AA_FILES_SPLIT=true
}
# END APP ACCESS COMPOSITION CLASSIFIER

# AA-EN-1: true when the running composition is exactly the one that
# tunnex-app-access adopt recorded (tunnex.yml, the now-managed app-access.yml,
# then the hand-written overlays in order) and every hand-written overlay still
# has the hash recorded at adoption. Anything else is unknown drift.
aa_adopted_composition() {
  _aad_running=${2:-$AA_CONFIG_FILES}
  _aad_files=$(dotenv_value TUNNEX_APP_ACCESS_ADOPTED_CONFIG_FILES)
  _aad_hashes=$(dotenv_value TUNNEX_APP_ACCESS_ADOPTED_OVERLAYS_SHA256)
  [ -n "$_aad_files" ] && [ -n "$_aad_hashes" ] && [ "$_aad_files" = "$_aad_running" ] || return 1
  [ -f "$AA_OVERLAY" ] || return 1
  _aad_rest=${_aad_running#*,}
  case "$_aad_rest" in
    "$AA_OVERLAY",*|"$1/app-access.yml",*) _aad_rest=${_aad_rest#*,} ;;
    *) return 1 ;;
  esac
  _aad_actual=
  _aad_saved_ifs=$IFS; IFS=,
  for _aad_file in $_aad_rest; do
    IFS=$_aad_saved_ifs
    case "$_aad_file" in /*) ;; *) return 1 ;; esac
    [ -f "$_aad_file" ] && [ ! -L "$_aad_file" ] || return 1
    _aad_actual="${_aad_actual:+$_aad_actual,}$(file_sha256 "$_aad_file")"
  done
  IFS=$_aad_saved_ifs
  [ "$_aad_actual" = "$_aad_hashes" ]
}

# App Access is an optional overlay owned by this upgrade once present. Every
# check below is a refusal before any temporary state, backup or mutation.
AA_PRESENT=false
AA_PROXY=false
AA_OVERLAY="$DIR/app-access.yml"
AA_COMPOSE_ACTIVE=false
AA_PROFILE_ON=false
AA_PROJECT=
AA_PROXY_PIN=
AA_MUTATION_STARTED=false
AA_AUTHORITY_CHANGED=false
aa_refuse() {
  echo "error: upgrade blocked; App Access $*. Nothing was changed." >&2
  exit 13
}
admit_app_access() {
  _aa_dir_real=$1
  classify_existing_app_access "$PROJECT" "$_aa_dir_real" || exit 13
  if [ "$AA_API_COUNT" -eq 0 ] && [ "$AA_PROXY_COUNT" -eq 0 ] && [ ! -f "$AA_OVERLAY" ]; then
    return 0
  fi
  AA_PRESENT=true
  [ "$AA_CONFIG_CONFLICT" = false ] ||
    aa_refuse 'participants were created from different projects or composition files; inspect them before upgrading'
  if [ "$AA_FILES_SPLIT" = true ]; then
    # Re-running a failed upgrade of an adopted layout: the API already runs from
    # the managed files and the stopped proxy still carries the recorded adopted
    # composition (hash-bound). Anything else is unknown drift.
    case "$AA_API_FILES" in
      "$COMPOSE,$AA_OVERLAY"|"$_aa_dir_real/${COMPOSE##*/},$_aa_dir_real/app-access.yml") ;;
      *) aa_refuse 'participants were created from different projects or composition files; inspect them before upgrading' ;;
    esac
    aa_adopted_composition "$_aa_dir_real" "$AA_PROXY_FILES" ||
      aa_refuse 'participants were created from different projects or composition files; inspect them before upgrading'
  fi
  [ "$AA_API_COUNT" -le 1 ] && [ "$AA_PROXY_COUNT" -le 1 ] ||
    aa_refuse 'upgrade supports exactly one API and one proxy on this host; HA participants need a separately fenced procedure'
  if [ "$AA_PROXY_COUNT" -eq 1 ] && [ "$AA_API_COUNT" -eq 0 ]; then
    aa_refuse 'proxy exists but the API does not mount the external restore barrier; restore the reviewed composition first'
  fi
  AA_PROJECT=${AA_PROJECT_FOUND:-${PROJECT:-tunnex}}
  [ -z "$PROJECT" ] || [ "$AA_PROJECT" = "$PROJECT" ] ||
    aa_refuse "containers belong to Compose project $AA_PROJECT; set COMPOSE_PROJECT_NAME in .env to match"
  if [ -z "$PROJECT" ] && [ "$AA_PROJECT" != tunnex ]; then
    aa_refuse "containers belong to Compose project $AA_PROJECT; set COMPOSE_PROJECT_NAME=$AA_PROJECT in .env"
  fi
  _aa_volume="volume:${AA_PROJECT}_app_restore;"
  for _aa_found_marker in "$AA_API_MARKER" "$AA_PROXY_MARKER"; do
    [ -z "$_aa_found_marker" ] || [ "$_aa_found_marker" = "$_aa_volume" ] ||
      aa_refuse "restore barrier is not the dedicated volume ${AA_PROJECT}_app_restore; it was preserved, migrate it with the reviewed procedure first"
  done
  [ "$AA_PROXY_COUNT" -eq 0 ] || [ -n "$AA_PROXY_MARKER" ] ||
    aa_refuse 'proxy does not mount the external restore barrier'
  if [ -n "$AA_CONFIG_FILES" ]; then
    _aa_base=${AA_CONFIG_FILES%%,*}
    _aa_overlay=${AA_CONFIG_FILES#*,}
    case "$_aa_base" in
      "$COMPOSE"|"$_aa_dir_real/${COMPOSE##*/}") ;;
      *) aa_refuse 'composition is not based on this installation tunnex.yml' ;;
    esac
    if [ "$AA_CONFIG_FILES" != "$_aa_base" ] && aa_adopted_composition "$_aa_dir_real"; then
      # AA-EN-1: tunnex-app-access adopt recorded exactly this running
      # composition and its hand-written overlays; this upgrade recreates it
      # from the managed files. The recorded overlays must be unchanged.
      :
    else
      case "$_aa_overlay" in
        "$AA_CONFIG_FILES"|*,*|'') aa_refuse 'composition must be tunnex.yml plus exactly one App Access overlay (a hand-written multi-file layout must be converted first with tunnex-app-access adopt)' ;;
      esac
      case "$_aa_overlay" in
        "$AA_OVERLAY"|"$_aa_dir_real/app-access.yml") ;;
        *) [ ! -f "$AA_OVERLAY" ] ||
             aa_refuse 'composition uses a different overlay than the managed app-access.yml' ;;
      esac
    fi
  elif [ "$AA_API_COUNT" -gt 0 ] || [ "$AA_PROXY_COUNT" -gt 0 ]; then
    aa_refuse 'composition files are unknown'
  fi
  if [ "$AA_PROXY_COUNT" -eq 1 ]; then
    AA_PROXY=true
  elif [ -f "$AA_OVERLAY" ]; then
    case ",$(dotenv_value COMPOSE_PROFILES)," in *,app-access,*) AA_PROXY=true ;; esac
  fi
  [ -n "$(dotenv_value TUNNEX_APP_ACCESS_BASE_DOMAIN)" ] ||
    aa_refuse 'requires TUNNEX_APP_ACCESS_BASE_DOMAIN in .env'
  if [ "$AA_PROXY" = true ]; then
    _aa_secrets=$(dotenv_value TUNNEX_APP_PROXY_SECRETS_DIR)
    [ -n "$_aa_secrets" ] || aa_refuse 'requires TUNNEX_APP_PROXY_SECRETS_DIR in .env'
    [ "$AA_PROXY_COUNT" -eq 0 ] || [ "$AA_PROXY_SECRETS" = "$_aa_secrets;" ] ||
      aa_refuse 'proxy credential directory differs from TUNNEX_APP_PROXY_SECRETS_DIR in .env'
    _aa_bind=$(dotenv_value TUNNEX_APP_PROXY_BIND_IP); _aa_port=$(dotenv_value TUNNEX_APP_PROXY_PUBLIC_PORT)
    _aa_gbind=$(dotenv_value TUNNEX_APP_PROXY_GATEWAY_BIND_IP); _aa_gport=$(dotenv_value TUNNEX_APP_PROXY_GATEWAY_PORT)
    _aa_public="8443/tcp=${_aa_bind:-127.0.0.1}:${_aa_port:-443};"
    # Exactly the managed port set: the public listener alone (overlays before
    # AA-EN-1), or the public listener plus the gateway listener (AA-EN-1 E6).
    [ "$AA_PROXY_COUNT" -eq 0 ] || [ "$AA_PROXY_PORTS" = "$_aa_public" ] ||
      [ "$AA_PROXY_PORTS" = "${_aa_public}8444/tcp=${_aa_gbind:-0.0.0.0}:${_aa_gport:-8444};" ] ||
      aa_refuse 'proxy port bindings differ from TUNNEX_APP_PROXY_BIND_IP/TUNNEX_APP_PROXY_PUBLIC_PORT and TUNNEX_APP_PROXY_GATEWAY_BIND_IP/TUNNEX_APP_PROXY_GATEWAY_PORT in .env'
  fi
  if [ -f "$AA_OVERLAY" ]; then
    _aa_sha=$(dotenv_value TUNNEX_APP_ACCESS_COMPOSE_SHA256)
    [ -n "$_aa_sha" ] && [ "$(file_sha256 "$AA_OVERLAY")" = "$_aa_sha" ] || {
      echo "error: update blocked; installed deployment files changed after provisioning" >&2
      exit 13
    }
    AA_COMPOSE_ACTIVE=true
    AA_PROFILE_ON=$AA_PROXY
  fi
}

VERIFY=${TUNNEX_RELEASEVERIFY:-}
APPLY=false
AIRGAP=
EXPECTED_SOURCE_SHA=${TUNNEX_UPGRADE_EXPECTED_SOURCE_SHA:-}
EXPECTED_SEQUENCE=${TUNNEX_UPGRADE_EXPECTED_SEQUENCE:-}
STATUS_FILE=${TUNNEX_UPGRADE_STATUS_FILE:-}
REQUEST_ID=${TUNNEX_UPGRADE_REQUEST_ID:-manual}
TARGET_SOURCE_SHA=
TARGET_VERSION=
BACKUP_DUMP=
BACKUP_MANIFEST=
CURRENT_STAGE=
TERMINAL_STATUS=false
AI_SNAPSHOT_STOPPED=false
ACCEPT_INSTALLED_UNKNOWN=false
usage() { echo "usage: upgrade.sh [--manifest FILE] [--public-key KEY] [--apply] [--airgap DIR] [--expected-source-sha SHA] [--expected-sequence N] [--accept-installed-unknown]" >&2; exit 2; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest) MANIFEST=${2:-}; MANIFEST_EXPLICIT=true; shift 2;;
    --public-key) PUBLIC_KEY=${2:-}; shift 2;;
    --airgap) AIRGAP=${2:-}; shift 2;;
    --expected-source-sha) EXPECTED_SOURCE_SHA=${2:-}; shift 2;;
    --expected-sequence) EXPECTED_SEQUENCE=${2:-}; shift 2;;
    --apply) APPLY=true; shift;;
    --accept-installed-unknown) ACCEPT_INSTALLED_UNKNOWN=true; shift;;
    *) usage;;
  esac
done
case "$EXPECTED_SOURCE_SHA" in ''|*[!0-9a-f]*) [ -z "$EXPECTED_SOURCE_SHA" ] || usage ;; esac
[ -z "$EXPECTED_SOURCE_SHA" ] || [ "${#EXPECTED_SOURCE_SHA}" -eq 40 ] || usage
case "$EXPECTED_SEQUENCE" in ''|*[!0-9]*) [ -z "$EXPECTED_SEQUENCE" ] || usage ;; esac
[ -n "$PUBLIC_KEY" ] || { echo "error: trusted release public key is not configured in the deployment environment" >&2; exit 1; }
[ -f "$COMPOSE" ] && [ -f "$ENV_FILE" ] || { echo "error: deployment files not found" >&2; exit 1; }
TARGET_SOURCE_SHA=$EXPECTED_SOURCE_SHA
write_status() {
  [ -n "$STATUS_FILE" ] || return 0
  _state=$1 _reason=${2:-} _next="${STATUS_FILE}.next"
  umask 077
  {
    printf 'request_id=%s\n' "$REQUEST_ID"
    printf 'state=%s\n' "$_state"
    printf 'target_source_sha=%s\n' "$TARGET_SOURCE_SHA"
    printf 'target_version=%s\n' "$TARGET_VERSION"
    printf 'backup_dump=%s\n' "${BACKUP_DUMP##*/}"
    printf 'backup_manifest=%s\n' "${BACKUP_MANIFEST##*/}"
    printf 'reason_code=%s\n' "$_reason"
    printf 'updated_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } >"$_next"
  chmod 0644 "$_next"
  mv "$_next" "$STATUS_FILE"
  CURRENT_STAGE=$_state
  case "$_state" in failed|healthy) TERMINAL_STATUS=true ;; esac
}
# BEGIN UPG-2 TARGET HAND-OFF
# The installed helper is only a trampoline: it verifies the signed release
# with the installed key, refuses downgrade/replay against the installed signed
# descriptor, copies the target release's host files out of the digest-pinned
# API image (never running it) and execs the target's upgrade.sh. All admission,
# backup and apply logic belongs to the target, so an old guard can never trap
# a host again (UPG-2, rulings U1-U8). The hand-off interface (ABI 1) is frozen:
#   args: --manifest <handoff>/release.json [--apply] [--expected-source-sha S]
#         [--expected-sequence N] [--accept-installed-unknown]
#   env:  TUNNEX_DIR TUNNEX_ENV_FILE TUNNEX_COMPOSE_FILE TUNNEX_RELEASE_PUBLIC_KEY
#         TUNNEX_UPGRADE_STATUS_FILE TUNNEX_UPGRADE_REQUEST_ID
#         TUNNEX_UPGRADE_PRIVILEGED TUNNEX_UPGRADE_HANDOFF=1
#         TUNNEX_UPGRADE_HANDOFF_ABI=1 TUNNEX_UPGRADE_HANDOFF_DIR
#   dir:  <handoff>/release.json (verified bytes), <handoff>/host/ (image files)
HOST_ABI=1
HOST_IMAGE_DIR=/usr/share/tunnex/host
HOST_FILE_LIST='upgrade.sh upgrade-runner.sh tunnex.yml ai-bootstrap.sh ai-gateway/config-managed.json app-access/compose.yml app-access/restore.py app-access/tunnex-app-access.py'
HANDOFF=${TUNNEX_UPGRADE_HANDOFF:-}
HOST_FILES=
handoff_refuse() {
  _ho_reason=$1; shift
  write_status failed "$_ho_reason"
  echo "error: upgrade blocked; $*" >&2
  exit 13
}
# 0 = complete, 2 = unknown hand-off ABI, 1 = incomplete or invalid.
host_files_check() {
  [ "$(cat "$1/HOST_ABI" 2>/dev/null)" = "$HOST_ABI" ] || return 2
  for _ho_file in $HOST_FILE_LIST; do
    [ -f "$1/$_ho_file" ] && [ ! -L "$1/$_ho_file" ] && [ -s "$1/$_ho_file" ] || return 1
  done
  sh -n "$1/upgrade.sh" && sh -n "$1/upgrade-runner.sh" && sh -n "$1/ai-bootstrap.sh" || return 1
}
# Verify FILE with the installed verifier and the installed key; print env.
release_env_of() {
  if [ -n "$VERIFY" ]; then
    "$VERIFY" -manifest "$1" -public-key "$PUBLIC_KEY" -print-env
  elif command -v releaseverify >/dev/null 2>&1; then
    releaseverify -manifest "$1" -public-key "$PUBLIC_KEY" -print-env
  else
    set -- "$1" --env-file "$ENV_FILE" -f "$COMPOSE" exec -T api sh -c \
      'cat > /tmp/tunnex-release.json && releaseverify -manifest /tmp/tunnex-release.json -public-key "$1" -print-env' \
      sh "$PUBLIC_KEY"
    _ho_manifest=$1; shift
    [ -z "$PROJECT" ] || set -- --project-name "$PROJECT" "$@"
    docker compose "$@" <"$_ho_manifest"
  fi
}
env_value_of() { printf '%s\n' "$2" | sed -n "s/^$1=//p" | head -1; }
# U4/U5: only a strictly newer release, or a re-run of the installed one.
check_release_order() {
  _ho_installed="$DIR/release.json"
  _ho_env=
  [ -s "$_ho_installed" ] && _ho_env=$(release_env_of "$_ho_installed" 2>/dev/null) || _ho_env=
  _ho_seq=$(env_value_of TUNNEX_RELEASE_SEQUENCE "$_ho_env")
  _ho_sha=$(env_value_of TUNNEX_RELEASE_SOURCE_SHA "$_ho_env")
  case "$_ho_seq" in ''|*[!0-9]*) _ho_seq= ;; esac
  case "$_ho_sha" in *[!0-9a-f]*) _ho_sha= ;; esac
  if [ -z "$_ho_seq" ] || [ "${#_ho_sha}" -ne 40 ]; then
    if [ "$ACCEPT_INSTALLED_UNKNOWN" = true ]; then
      echo "warning: the installed release could not be verified ($_ho_installed); continuing because --accept-installed-unknown was given. Downgrade protection was skipped for this run." >&2
      return 0
    fi
    handoff_refuse installed_release_unknown "the installed release descriptor $_ho_installed is missing or does not verify with the installed release key, so this upgrade cannot prove it is not a downgrade. Restore that file from the last upgrade (it is also kept in backups), or, after confirming the installed version yourself, re-run ./upgrade.sh on the command line with --accept-installed-unknown. Nothing was changed."
  fi
  if [ "$TARGET_SEQUENCE" -gt "$_ho_seq" ]; then
    return 0
  elif [ "$TARGET_SEQUENCE" -eq "$_ho_seq" ] && [ "$TARGET_SOURCE_SHA" = "$_ho_sha" ]; then
    echo "re-running the installed release $TARGET_VERSION (sequence $TARGET_SEQUENCE); this is the supported forward fix after a failed upgrade"
  elif [ "$TARGET_SEQUENCE" -eq "$_ho_seq" ]; then
    handoff_refuse release_conflict "the signed release has the same sequence as the installed release but a different source ($TARGET_SOURCE_SHA, installed $_ho_sha). Nothing was changed."
  else
    handoff_refuse downgrade_refused "the signed release $TARGET_VERSION (sequence $TARGET_SEQUENCE) is older than the installed release (sequence $_ho_seq). Upgrades only move forward; to return to an earlier release, restore its pre-upgrade backup. Nothing was changed."
  fi
}
if [ "$ACCEPT_INSTALLED_UNKNOWN" = true ] && [ "${TUNNEX_UPGRADE_PRIVILEGED:-}" = 1 ]; then
  echo 'error: --accept-installed-unknown is command line only; the dashboard upgrade cannot skip downgrade protection' >&2
  exit 2
fi
if [ "$HANDOFF" = 1 ]; then
  # Target side: accept only the frozen interface and a complete file set.
  [ "${TUNNEX_UPGRADE_HANDOFF_ABI:-}" = "$HOST_ABI" ] ||
    handoff_refuse handoff_unsupported "the installed upgrade helper used hand-off interface '${TUNNEX_UPGRADE_HANDOFF_ABI:-none}', but this release speaks interface $HOST_ABI. Run the one-time step for older hosts in docs/upgrade.md. Nothing was changed."
  HOST_FILES="${TUNNEX_UPGRADE_HANDOFF_DIR:-}/host"
  [ -n "${TUNNEX_UPGRADE_HANDOFF_DIR:-}" ] && host_files_check "$HOST_FILES" ||
    handoff_refuse handoff_failed 'the hand-off directory is missing or incomplete. Nothing was changed.'
  [ "$MANIFEST_EXPLICIT" = true ] || handoff_refuse handoff_failed 'the hand-off did not include the verified release descriptor. Nothing was changed.'
  trap 'rm -rf "$TUNNEX_UPGRADE_HANDOFF_DIR"' EXIT INT TERM
else
  HO_DIR=
  HO_CID=
  HO_TMPBASE=${TMPDIR:-/tmp}
  HO_UMASK=$(umask)
  ho_finish() {
    _ho_status=$?
    trap - EXIT INT TERM
    [ -z "$HO_CID" ] || docker rm "$HO_CID" >/dev/null 2>&1 || true
    [ -z "$HO_DIR" ] || rm -rf "$HO_DIR"
    if [ "$_ho_status" -ne 0 ] && [ "$APPLY" = true ] && [ "$TERMINAL_STATUS" = false ]; then
      write_status failed handoff_failed
    fi
    exit "$_ho_status"
  }
  trap ho_finish EXIT INT TERM
  umask 077
  HO_DIR=$(mktemp -d "$HO_TMPBASE/tunnex-handoff.XXXXXX")
  mkdir "$HO_DIR/host"
  # The descriptor that is verified is the exact file handed to the target.
  if [ "$MANIFEST_EXPLICIT" = true ]; then
    [ -n "$MANIFEST" ] && [ -r "$MANIFEST" ] || { echo "error: signed manifest is required" >&2; exit 1; }
    cp "$MANIFEST" "$HO_DIR/release.json"
  else
    [ -n "$CATALOG_URL" ] || { echo "error: signed release catalog is not configured; use --manifest for an air-gapped bundle" >&2; exit 1; }
    curl -fsSL "$CATALOG_URL" -o "$HO_DIR/release.json" || { echo "error: could not fetch the signed release catalog" >&2; exit 1; }
  fi
  RELEASE_ENV=$(release_env_of "$HO_DIR/release.json") || {
    echo "error: update blocked; installation verification failed (tampered or incomplete release metadata)" >&2
    exit 13
  }
  TARGET_SOURCE_SHA=$(env_value_of TUNNEX_RELEASE_SOURCE_SHA "$RELEASE_ENV")
  TARGET_VERSION=$(env_value_of TUNNEX_RELEASE_VERSION "$RELEASE_ENV")
  TARGET_SEQUENCE=$(env_value_of TUNNEX_RELEASE_SEQUENCE "$RELEASE_ENV")
  case "$TARGET_SEQUENCE" in ''|*[!0-9]*) echo 'error: signed release verifier omitted TUNNEX_RELEASE_SEQUENCE' >&2; exit 13 ;; esac
  [ "${#TARGET_SOURCE_SHA}" -eq 40 ] || { echo 'error: signed release verifier omitted TUNNEX_RELEASE_SOURCE_SHA' >&2; exit 13; }
  [ -z "$EXPECTED_SOURCE_SHA" ] || [ "$TARGET_SOURCE_SHA" = "$EXPECTED_SOURCE_SHA" ] ||
    handoff_refuse approved_release_changed 'the signed release no longer matches the release approved in the UI'
  [ -z "$EXPECTED_SEQUENCE" ] || [ "$TARGET_SEQUENCE" = "$EXPECTED_SEQUENCE" ] ||
    handoff_refuse approved_release_changed 'the signed release sequence no longer matches the release approved in the UI'
  check_release_order
  HO_IMAGE=$(env_value_of TUNNEX_API_IMAGE "$RELEASE_ENV")
  printf '%s\n' "$HO_IMAGE" | grep -Eqx 'ghcr\.io/tunnexio/tunnex-api@sha256:[0-9a-f]{64}' ||
    handoff_refuse handoff_failed 'the verified release does not pin the API image by digest, so its upgrade helper cannot be trusted. Nothing was changed.'
  if [ -n "$AIRGAP" ]; then
    [ -d "$AIRGAP" ] || { echo "error: air-gap bundle directory not found" >&2; exit 1; }
    for image in "$AIRGAP"/*.tar; do [ -f "$image" ] || continue; docker load -i "$image"; done
  fi
  # A loaded archive may not be addressable by registry digest (classic image
  # store); then the digest is pulled, as the rest of the upgrade does today.
  if [ -z "$AIRGAP" ] || ! docker image inspect "$HO_IMAGE" >/dev/null 2>&1; then
    docker pull "$HO_IMAGE" >/dev/null ||
      handoff_refuse handoff_failed "could not extract the target release's upgrade helper: pulling the verified API image $HO_IMAGE failed. Nothing was changed."
  fi
  # Create (never start) a container from the pinned digest and copy the host
  # files out of it. No code from the target release runs to obtain them.
  HO_CID=$(docker create --pull never --network none "$HO_IMAGE") && [ -n "$HO_CID" ] ||
    handoff_refuse handoff_failed "could not extract the target release's upgrade helper from the verified API image. Nothing was changed."
  docker cp "$HO_CID:$HOST_IMAGE_DIR/." "$HO_DIR/host" ||
    handoff_refuse handoff_failed "could not extract the target release's upgrade helper from the verified API image. Nothing was changed."
  docker rm "$HO_CID" >/dev/null 2>&1 || true
  HO_CID=
  _ho_check=0
  host_files_check "$HO_DIR/host" || _ho_check=$?
  case "$_ho_check" in
    0) ;;
    2) handoff_refuse handoff_unsupported "the target release's upgrade helper uses hand-off interface '$(cat "$HO_DIR/host/HOST_ABI" 2>/dev/null || echo none)', which this installed helper does not support. Upgrade through each intermediate release named in the release notes. Nothing was changed." ;;
    *) handoff_refuse handoff_failed "the target release's host files in the verified API image are incomplete or invalid. Nothing was changed." ;;
  esac
  write_status verifying
  # Hand over: the target owns the status file from here; this process (and its
  # EXIT trap) is replaced, so it can never overwrite the target's result.
  trap - EXIT INT TERM
  set -- --manifest "$HO_DIR/release.json"
  [ "$APPLY" != true ] || set -- "$@" --apply
  [ -z "$EXPECTED_SOURCE_SHA" ] || set -- "$@" --expected-source-sha "$EXPECTED_SOURCE_SHA"
  [ -z "$EXPECTED_SEQUENCE" ] || set -- "$@" --expected-sequence "$EXPECTED_SEQUENCE"
  [ "$ACCEPT_INSTALLED_UNKNOWN" != true ] || set -- "$@" --accept-installed-unknown
  echo "release $TARGET_VERSION verified; handing off to its upgrade helper"
  umask "$HO_UMASK" # the target starts with the caller's file-creation mask
  exec env TMPDIR="$HO_TMPBASE" TUNNEX_DIR="$DIR" TUNNEX_ENV_FILE="$ENV_FILE" TUNNEX_COMPOSE_FILE="$COMPOSE" \
    TUNNEX_RELEASE_PUBLIC_KEY="$PUBLIC_KEY" TUNNEX_UPGRADE_STATUS_FILE="$STATUS_FILE" \
    TUNNEX_UPGRADE_REQUEST_ID="$REQUEST_ID" TUNNEX_UPGRADE_PRIVILEGED="${TUNNEX_UPGRADE_PRIVILEGED:-}" \
    TUNNEX_UPGRADE_HANDOFF=1 TUNNEX_UPGRADE_HANDOFF_ABI="$HOST_ABI" TUNNEX_UPGRADE_HANDOFF_DIR="$HO_DIR" \
    /bin/sh "$HO_DIR/host/upgrade.sh" "$@"
fi
# END UPG-2 TARGET HAND-OFF
# Match Compose's first-file project directory, including an explicit file
# outside the installation directory. Do not guess a top-level project name.
_aa_upgrade_directory=$(CDPATH= cd -- "$(dirname -- "$COMPOSE")" && pwd -P) || exit 13
admit_app_access "$_aa_upgrade_directory"
TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/tunnex-upgrade.XXXXXX")
trap 'rm -rf "$TMPDIR"; [ "$HANDOFF" != 1 ] || rm -rf "$TUNNEX_UPGRADE_HANDOFF_DIR"' EXIT INT TERM
finish_upgrade() {
  _status=$?
  trap - EXIT INT TERM
  if [ "$AI_SNAPSHOT_STOPPED" = true ]; then
    compose start bifrost >/dev/null 2>&1 || true
  fi
  if [ "$_status" -ne 0 ] && [ "$AA_MUTATION_STARTED" = true ]; then
    # Never leave the public App Access listener serving on an unverified stack.
    AA_PROFILE_ON=true
    compose stop app-proxy >/dev/null 2>&1 || true
    aa_rollback_guidance
  fi
  rm -rf "$TMPDIR"
  [ -z "${TUNNEX_UPGRADE_HANDOFF_DIR:-}" ] || rm -rf "$TUNNEX_UPGRADE_HANDOFF_DIR"
  if [ "$_status" -ne 0 ] && [ "$APPLY" = true ] && [ "$TERMINAL_STATUS" = false ]; then
    case "$CURRENT_STAGE" in
      verifying|backing_up|preflight|pulling|restarting|health_check) write_status failed "${CURRENT_STAGE}_failed" ;;
      *) write_status failed upgrade_failed ;;
    esac
  fi
  exit "$_status"
}
aa_rollback_guidance() {
  _aa_compose_files="--compose-file $COMPOSE --compose-file $AA_OVERLAY"
  {
    echo 'App Access: the public app proxy was left stopped. The database may already be migrated forward.'
    if [ "$AA_AUTHORITY_CHANGED" = true ]; then
      echo '  Installation authority changed or a restore marker appeared during the upgrade: a restore or recovery'
      echo '  may have run concurrently. Do not re-run this upgrade or start the proxy. Inspect the restore marker and'
      echo '  complete the App Access restore runbook (fresh proxy credential, logins and republish) first.'
    else
      echo '  Preferred: fix the reported cause and run this upgrade again (it is safe to repeat).'
    fi
    echo '  To return to the previous release instead, restore the verified pre-upgrade backup with the App Access'
    echo '  restore runner. It performs fresh-authority recovery: users sign in again, the proxy credential is'
    echo '  reprovisioned and applications are rechecked and republished. Review the dry run, then add --apply:'
    echo "    python3 $DIR/app-access-restore.py --docker-socket /run/docker.sock --project $AA_PROJECT --directory $DIR $_aa_compose_files --dump $BACKUP_DUMP --manifest $BACKUP_MANIFEST --operator NAME"
    echo '  Do not use raw pg_restore or a down migration for an App Access installation.'
  } >&2
}
trap finish_upgrade EXIT INT TERM
if [ "$MANIFEST_EXPLICIT" = true ]; then
  [ -n "$MANIFEST" ] && [ -r "$MANIFEST" ] || { echo "error: signed manifest is required" >&2; exit 1; }
else
  [ -n "$CATALOG_URL" ] || { echo "error: signed release catalog is not configured; use --manifest for an air-gapped bundle" >&2; exit 1; }
  MANIFEST="$TMPDIR/release.json"
  curl -fsSL "$CATALOG_URL" -o "$MANIFEST" || { echo "error: could not fetch the signed release catalog" >&2; exit 1; }
fi
verify_release() {
  fail_verification() {
    # Keep this deliberately generic: the host log may contain the exact parser
    # or signature reason, while operators and the UI should get one safe action.
    echo "error: update blocked; installation verification failed (tampered or incomplete release metadata)" >&2
    exit 13
  }
  if [ -n "$VERIFY" ]; then
    "$VERIFY" -manifest "$MANIFEST" -public-key "$PUBLIC_KEY" || fail_verification
  elif command -v releaseverify >/dev/null 2>&1; then
    releaseverify -manifest "$MANIFEST" -public-key "$PUBLIC_KEY" || fail_verification
  else
    # releaseverify ships in every API image, so no architecture-specific host
    # binary needs to be downloaded or trusted by the installer.
    # Stream the host manifest into the container because the compose file does
    # not mount the deployment directory into the API service.
    compose exec -T api sh -c \
      'cat > /tmp/tunnex-release.json && releaseverify -manifest /tmp/tunnex-release.json -public-key "$1"' \
      sh "$PUBLIC_KEY" < "$MANIFEST" || fail_verification
  fi
}
verify_release_env() {
  fail_verification() {
    echo "error: update blocked; installation verification failed (tampered or incomplete release metadata)" >&2
    exit 13
  }
  if [ -n "$VERIFY" ]; then
    "$VERIFY" -manifest "$MANIFEST" -public-key "$PUBLIC_KEY" -print-env
  elif command -v releaseverify >/dev/null 2>&1; then
    releaseverify -manifest "$MANIFEST" -public-key "$PUBLIC_KEY" -print-env
  else
    compose exec -T api sh -c \
      'cat > /tmp/tunnex-release.json && releaseverify -manifest /tmp/tunnex-release.json -public-key "$1" -print-env' \
      sh "$PUBLIC_KEY" < "$MANIFEST"
  fi || fail_verification
}
base_profile() {
  case "$(dotenv_value TUNNEX_DATABASE_MODE)" in external) printf external-db ;; *) printf bundled-db ;; esac
}
compose() {
  COMPOSE_PROFILES=$(base_profile)
  if [ "$AA_COMPOSE_ACTIVE" = true ]; then
    [ "$AA_PROFILE_ON" != true ] || COMPOSE_PROFILES="$COMPOSE_PROFILES,app-access"
    set -- -f "$COMPOSE" -f "$AA_OVERLAY" "$@"
  else
    set -- -f "$COMPOSE" "$@"
  fi
  export COMPOSE_PROFILES
  if [ -n "$PROJECT" ]; then
    docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" "$@"
  else
    docker compose --env-file "$ENV_FILE" "$@"
  fi
}
# Offline, read-only authority admission. backupctl takes the shared restore
# lock in the marker directory, which serving containers mount read-only, so a
# one-off helper gets only that exact named volume writable; ports, other mounts
# and secrets are unchanged and nothing is pulled.
aa_preflight() {
  _aa_helper="$TMPDIR/app-access-preflight.yml"
  [ -f "$_aa_helper" ] || cat >"$_aa_helper" <<'YAML'
services:
  api:
    volumes:
      - type: volume
        source: app_restore
        target: /var/lib/tunnex/app-restore
        read_only: false
YAML
  COMPOSE_PROFILES=$(base_profile)
  export COMPOSE_PROFILES
  set -- --env-file "$ENV_FILE" -f "$COMPOSE" -f "$1" -f "$_aa_helper" \
    run --rm --no-deps --pull never -T --entrypoint backupctl api app-preflight
  [ -z "$PROJECT" ] || set -- --project-name "$PROJECT" "$@"
  TUNNEX_APP_PROXY_IMAGE=$AA_PROXY_PIN docker compose "$@"
}
aa_field() {
  printf '%s\n' "$2" | sed -n "s/.*\"$1\":\"\{0,1\}\([0-9a-f-]*\)\"\{0,1\}[,}].*/\1/p" | head -1
}
# Prints "generation version schema" for a clean, completed authority.
aa_authority() {
  _aa_json=$(aa_preflight "$1" 2>/dev/null) || return 1
  _aa_schema=$(aa_field schema_version "$_aa_json")
  _aa_ceiling=$(aa_field supported_schema_version "$_aa_json")
  _aa_generation=$(aa_field generation "$_aa_json")
  _aa_version=$(aa_field authority_version "$_aa_json")
  case "$_aa_json" in *'"recovery_completed":true'*) ;; *) return 1 ;; esac
  case "$_aa_generation" in ''|00000000-0000-0000-0000-000000000000) return 1 ;; esac
  [ -n "$_aa_schema" ] && [ "$_aa_schema" = "$_aa_ceiling" ] && [ -n "$_aa_version" ] || return 1
  printf '%s %s %s\n' "$_aa_generation" "$_aa_version" "$_aa_schema"
}
compose_up() {
  if [ "$(dotenv_value TUNNEX_GATEWAY_PLACEMENT)" = separate ]; then
    compose up "$@" --scale node-agent=0
    return
  fi
  case "$(dotenv_value TUNNEX_PORTABLE_CONTROL_PLANE)" in
    true) compose up "$@" --scale node-agent=0 ;;
    *) compose up "$@" ;;
  esac
}
healthcheck() {
  i=0
  while [ "$i" -lt 30 ]; do
    if compose exec -T api wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  return 1
}
[ -z "$COMPOSE_SHA256" ] || {
  [ "$(file_sha256 "$COMPOSE")" = "$COMPOSE_SHA256" ] || {
    echo "error: update blocked; installed deployment files changed after provisioning" >&2
    exit 13
  }
}
verify_release
RELEASE_ENV=$(verify_release_env)
release_value() {
  _key=$1
  _value=$(printf '%s\n' "$RELEASE_ENV" | sed -n "s/^${_key}=//p" | head -1)
  [ -n "$_value" ] || { echo "error: signed release verifier omitted ${_key}" >&2; exit 13; }
  printf '%s' "$_value"
}
TARGET_SOURCE_SHA=$(release_value TUNNEX_RELEASE_SOURCE_SHA)
TARGET_VERSION=$(release_value TUNNEX_RELEASE_VERSION)
TARGET_SEQUENCE=$(release_value TUNNEX_RELEASE_SEQUENCE)
[ -z "$EXPECTED_SOURCE_SHA" ] || [ "$TARGET_SOURCE_SHA" = "$EXPECTED_SOURCE_SHA" ] || {
  write_status failed approved_release_changed
  echo "error: update blocked; the signed release no longer matches the release approved in the UI" >&2
  exit 13
}
[ -z "$EXPECTED_SEQUENCE" ] || [ "$TARGET_SEQUENCE" = "$EXPECTED_SEQUENCE" ] || {
  write_status failed approved_release_changed
  echo "error: update blocked; the signed release sequence no longer matches the release approved in the UI" >&2
  exit 13
}
# The target re-checks downgrade/replay itself; it trusts nothing it was handed.
check_release_order
write_status verifying
# Air-gap archives were loaded by the installed helper before the hand-off.
if [ "$AA_PRESENT" = true ]; then
  # The installed verifier must authenticate the signed proxy image itself; a
  # release without one cannot upgrade an App Access installation.
  _aa_env=$(
    if [ -n "$VERIFY" ]; then
      "$VERIFY" -manifest "$MANIFEST" -public-key "$PUBLIC_KEY" -require-app-proxy -print-env
    elif command -v releaseverify >/dev/null 2>&1; then
      releaseverify -manifest "$MANIFEST" -public-key "$PUBLIC_KEY" -require-app-proxy -print-env
    else
      compose exec -T api sh -c \
        'cat > /tmp/tunnex-release.json && releaseverify -manifest /tmp/tunnex-release.json -public-key "$1" -require-app-proxy -print-env' \
        sh "$PUBLIC_KEY" < "$MANIFEST"
    fi 2>/dev/null
  ) || _aa_env=
  AA_PROXY_PIN=$(printf '%s\n' "$_aa_env" | sed -n 's/^TUNNEX_APP_PROXY_IMAGE=//p' | head -1)
  [ "$(printf '%s\n' "$_aa_env" | sed -n 's/^TUNNEX_RELEASE_SOURCE_SHA=//p' | head -1)" = "$TARGET_SOURCE_SHA" ] || AA_PROXY_PIN=
  printf '%s\n' "$AA_PROXY_PIN" | grep -Eqx 'ghcr\.io/tunnexio/tunnex-app-proxy@sha256:[0-9a-f]{64}' || {
    write_status failed app_access_admission_failed
    aa_refuse 'requires a target release with a signed App Access proxy image (verified with -require-app-proxy)'
  }
  for _aa_asset in compose.yml restore.py tunnex-app-access.py; do
    cp "$HOST_FILES/app-access/${_aa_asset}" "$TMPDIR/app-access-${_aa_asset}" || {
      write_status failed app_access_admission_failed
      echo 'error: the App Access composition of the signed release is missing from its host files' >&2; exit 13;
    }
  done
  echo "App Access: upgrade will snapshot authority, back up, stop app-proxy, migrate the API, verify unchanged authority, then start the signed proxy $AA_PROXY_PIN"
fi
echo "release verified; preflight and backup are required before mutation"
compose_prefix="docker compose"
[ -z "$PROJECT" ] || compose_prefix="$compose_prefix --project-name $PROJECT"
echo "  a PostgreSQL dump and matching key-bound manifest will be retained under $DIR/backups"
echo "  $compose_prefix --env-file $ENV_FILE -f $COMPOSE exec -T -e TUNNEX_PREFLIGHT_BACKUP_CONFIRMED=yes api preflight"
[ "$APPLY" = true ] || { echo "dry run: re-run with --apply after reviewing the commands above"; exit 0; }
if [ "$AA_PRESENT" = true ]; then
  AA_BEFORE=$(aa_authority "$TMPDIR/app-access-compose.yml") || {
    write_status failed app_access_admission_failed
    aa_refuse 'authority preflight refused: a restore marker is pending, the schema is dirty or not this release, or installation authority is incomplete. Finish or inspect the restore with the App Access restore runner (deploy/app-access/restore.py of the installed release)'
  }
fi
BACKUP_DIR=${TUNNEX_UPGRADE_BACKUP_DIR:-$DIR/backups}
umask 077
mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"
BACKUP_STAMP=$(date -u '+%Y%m%dT%H%M%SZ')
BACKUP_BASE="tunnex-${BACKUP_STAMP}-${REQUEST_ID}"
_backup_base=$BACKUP_BASE
_backup_suffix=0
while [ -e "$BACKUP_DIR/${BACKUP_BASE}.dump" ] || [ -e "$BACKUP_DIR/${BACKUP_BASE}.ai.tar.gz" ]; do
  _backup_suffix=$((_backup_suffix + 1))
  BACKUP_BASE="${_backup_base}-${_backup_suffix}"
done
BACKUP_DUMP="$BACKUP_DIR/${BACKUP_BASE}.dump"
BACKUP_MANIFEST="$BACKUP_DIR/${BACKUP_BASE}.manifest.json"
write_status backing_up
database_dump() {
  if [ "$(dotenv_value TUNNEX_DATABASE_MODE)" = external ]; then
    compose exec -T api preflight --database-dump
  else
    compose exec -T postgres sh -c 'pg_dump --format=custom --no-owner --username "$POSTGRES_USER" "$POSTGRES_DB"'
  fi
}
database_verify_archive() {
  if [ "$(dotenv_value TUNNEX_DATABASE_MODE)" = external ]; then
    compose exec -T api preflight --database-verify-archive <"$BACKUP_DUMP"
  else
    # Validate with the same container/version that produced the dump; hosts
    # need not ship PostgreSQL client tools.
    compose exec -T postgres pg_restore --list <"$BACKUP_DUMP"
  fi
}
database_dump >"${BACKUP_DUMP}.next" || {
  rm -f "${BACKUP_DUMP}.next"
  write_status failed backup_failed
  echo "error: upgrade blocked; database backup failed" >&2
  exit 13
}
[ -s "${BACKUP_DUMP}.next" ] || {
  rm -f "${BACKUP_DUMP}.next"
  write_status failed backup_failed
  echo "error: upgrade blocked; database backup was empty" >&2
  exit 13
}
mv "${BACKUP_DUMP}.next" "$BACKUP_DUMP"
database_verify_archive >/dev/null 2>&1 || {
  write_status failed backup_verification_failed
  echo "error: upgrade blocked; database backup is not a valid PostgreSQL archive" >&2
  exit 13
}
DUMP_SHA256=$(file_sha256 "$BACKUP_DUMP")
compose exec -T -e TUNNEX_BACKUP_DUMP_SHA256="$DUMP_SHA256" api backupctl manifest pre-upgrade >"${BACKUP_MANIFEST}.next" || {
  rm -f "${BACKUP_MANIFEST}.next"
  write_status failed backup_failed
  echo "error: upgrade blocked; backup manifest creation failed" >&2
  exit 13
}
compose exec -T api backupctl verify --dump-sha256 "$DUMP_SHA256" <"${BACKUP_MANIFEST}.next" >/dev/null || {
  rm -f "${BACKUP_MANIFEST}.next"
  write_status failed backup_verification_failed
  echo "error: upgrade blocked; backup manifest verification failed" >&2
  exit 13
}
mv "${BACKUP_MANIFEST}.next" "$BACKUP_MANIFEST"
write_status preflight
compose exec -T -e TUNNEX_PREFLIGHT_BACKUP_CONFIRMED=yes api preflight
set_dotenv() {
  _key=$1 _value=$2 _tmp="$ENV_FILE.next"
  umask 077
  # Values originate in a verified descriptor. Reject newlines anyway: dotenv is
  # operator input on every subsequent run and must never become shell syntax.
  case "$_value" in *'\n'*|*'\r'*) echo "error: invalid verified release value" >&2; exit 13;; esac
  awk -F= -v key="$_key" -v value="$_value" '
    $1 == key { print key "=" value; seen=1; next }
    { print }
    END { if (!seen) print key "=" value }
  ' "$ENV_FILE" > "$_tmp"
  mv "$_tmp" "$ENV_FILE"
}
public_url_scheme() {
  case "$1" in https://*) printf '%s' https ;; http://*) printf '%s' http ;; *) return 1 ;; esac
}
public_url_is_ip() {
  _authority=${1#*://}
  case "$_authority" in
    \[*\]*) _host=${_authority%%]*}; _host="${_host}]" ;;
    *) _host=${_authority%%:*} ;;
  esac
  case "$_host" in
    \[*:*\]) return 0 ;;
    *[!0-9.]* | '') return 1 ;;
    *) return 0 ;;
  esac
  return 1
}
public_ipv4_ok() {
	printf '%s\n' "$1" | awk -F. '
		NF != 4 { exit 1 }
		{
			for (i = 1; i <= 4; i++) {
				if ($i !~ /^[0-9]+$/ || length($i) > 3 || $i ~ /^0[0-9]/ || $i + 0 > 255) exit 1
			}
			a = $1 + 0; b = $2 + 0; c = $3 + 0
			if (a == 0 || a == 10 || a == 127 || a >= 224 ||
			    (a == 100 && b >= 64 && b <= 127) ||
			    (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) ||
			    (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99))) ||
			    (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100))) ||
			    (a == 203 && b == 0 && c == 113)) exit 1
		}'
}
# BEGIN EXPLICIT EDGE PROXY VALIDATION
edge_trusted_proxies_ok() {
  printf '%s\n' "$1" | LC_ALL=C awk '
    function ipv4(ip, a,n,i) {
      n=split(ip,a,"."); if(n!=4) return 0
      for(i=1;i<=n;i++) if(a[i]!~/^[0-9]+$/ || length(a[i])>3 || a[i]~/^0[0-9]/ || a[i]+0>255) return 0
      return 1
    }
    function groups(ip, a,n,i) {
      if(ip=="") return 0
      n=split(ip,a,":")
      for(i=1;i<=n;i++) if(a[i]!~/^[0-9a-fA-F]+$/ || length(a[i])>4) return -1
      return n
    }
    function ipv6(ip, a,n,l,r) {
      if(ip!~/^[0-9a-fA-F:]+$/) return 0
      n=split(ip,a,"::")
      if(n==1) return groups(ip)==8
      if(n!=2) return 0
      l=groups(a[1]); r=groups(a[2])
      return l>=0 && r>=0 && l+r<8
    }
    NR!=1 || length($0)>4096 || /[^0-9a-fA-F.:\/ ]/ || NF<1 || NF>64 { exit 1 }
    {
      for(j=1;j<=NF;j++) {
        n=split($j,part,"/"); if(n>2) exit 1
        if(ipv4(part[1])) bits=32
        else if(ipv6(part[1])) bits=128
        else exit 1
        if(n==2 && (part[2]!~/^[1-9][0-9]*$/ || part[2]+0>bits)) exit 1
      }
    }'
}
# END EXPLICIT EDGE PROXY VALIDATION

prepare_edge_config() {
  # Validate the downloaded target before replacing any deployment settings.
  # A legacy target must not silently replace working public-IP ACME with
  # Caddy's default internal certificate issuer.
  EDGE_CONFIG_REQUIRED=false
  EDGE_PUBLIC_IP=
  _base=$(dotenv_value APP_BASE_URL)
  _mode=$(dotenv_value TUNNEX_TLS_MODE)
  if [ "$_mode" = direct ] && [ "${_base#https://}" != "$_base" ] && public_url_is_ip "$_base"; then
    _authority=${_base#https://}
    _host=${_authority%%:*}
    if ! public_ipv4_ok "$_host" || { [ "$_authority" != "$_host" ] && [ "$_authority" != "$_host:443" ]; }; then
      echo 'error: upgrade blocked; direct IP HTTPS requires a public IPv4 address on port 443' >&2
      exit 13
    fi
    EDGE_PUBLIC_IP=$_host
    grep -Fq 'TUNNEX_EDGE_PUBLIC_IP' "$1" && grep -Fq 'TUNNEX_EDGE_LISTEN' "$1" || {
      echo 'error: upgrade blocked; target release does not support the installed public-IP HTTPS endpoint' >&2
      exit 13
    }
  fi
  grep -Fq 'TUNNEX_EDGE_LISTEN' "$1" || return 0
  EDGE_CONFIG_REQUIRED=true
  _scheme=$(public_url_scheme "$_base") || {
    echo "error: upgrade blocked; APP_BASE_URL must be an http:// or https:// URL before the public edge can be configured" >&2
    exit 13
  }
  if [ -z "$_mode" ]; then
    case "$_scheme" in
      http) _mode=http ;;
      https) if public_url_is_ip "$_base"; then _mode=terminated; else _mode=direct; fi ;;
    esac
  fi
  case "$_mode" in
    direct) EDGE_LISTEN=$_base ;;
    terminated|http) EDGE_LISTEN=http://:80 ;;
    *) echo "error: upgrade blocked; TUNNEX_TLS_MODE must be direct, terminated, or http" >&2; exit 13 ;;
  esac
  if grep -Fq 'TUNNEX_EDGE_TRUSTED_PROXIES' "$1" && [ "$_mode" = terminated ]; then
    edge_trusted_proxies_ok "$(dotenv_value TUNNEX_EDGE_TRUSTED_PROXIES)" || {
      echo 'error: upgrade blocked; set TUNNEX_EDGE_TRUSTED_PROXIES in .env to explicit load-balancer IPs/CIDRs (space-separated, no /0) for externally terminated HTTPS' >&2
      exit 13
    }
  fi
  EDGE_MODE=$_mode
  case "$_scheme" in https) EDGE_COOKIE_SECURE=true ;; http) EDGE_COOKIE_SECURE=false ;; esac
}
ensure_edge_config() {
  [ "$EDGE_CONFIG_REQUIRED" = true ] || return 0
  set_dotenv TUNNEX_TLS_MODE "$EDGE_MODE"
  set_dotenv TUNNEX_EDGE_LISTEN "$EDGE_LISTEN"
  set_dotenv TUNNEX_EDGE_PUBLIC_IP "$EDGE_PUBLIC_IP"
  set_dotenv TUNNEX_COOKIE_SECURE "$EDGE_COOKIE_SECURE"
}
SOURCE_SHA=$(release_value TUNNEX_RELEASE_SOURCE_SHA)
VERSION=$(release_value TUNNEX_RELEASE_VERSION)
write_status pulling
# Every host file comes from the verified API image (UPG-2), never from a URL.
cp "$HOST_FILES/tunnex.yml" "$TMPDIR/tunnex.yml" || {
  echo "error: the deployment manifest of the signed release is missing from its host files" >&2; exit 13;
}
grep -q 'TUNNEX_ENV: production' "$TMPDIR/tunnex.yml" && ! grep -qi 'mailpit' "$TMPDIR/tunnex.yml" || {
  echo "error: signed release points to a non-production deployment manifest" >&2; exit 13;
}
if [ "$(dotenv_value TUNNEX_DATABASE_MODE)" = external ]; then
  grep -Fq 'TUNNEX_DATABASE_URL:' "$TMPDIR/tunnex.yml" && grep -Fq 'bundled-db' "$TMPDIR/tunnex.yml" || {
    echo 'error: upgrade blocked; target release does not support the existing external database' >&2; exit 13;
  }
fi
prepare_edge_config "$TMPDIR/tunnex.yml"
AI_BUNDLED=false
if grep -Fq '${TUNNEX_AI_ENGINE_IMAGE:' "$TMPDIR/tunnex.yml"; then
  AI_BUNDLED=true
  AI_IMAGE_PIN=$(printf '%s\n' "$RELEASE_ENV" | sed -n 's/^TUNNEX_AI_ENGINE_IMAGE=//p' | head -1)
  if [ -z "$AI_IMAGE_PIN" ]; then
    # Older installed verifiers authenticate the descriptor's extra images but
    # do not export their pins. Run the already-verified target API by digest;
    # never extract a runnable engine image from unverified JSON.
    _ai_verifier_image=$(release_value TUNNEX_API_IMAGE)
    docker pull "$_ai_verifier_image"
    # The systemd runner has PrivateTmp=true, so its host temporary path is
    # not visible to the Docker daemon. Stream into the verifier container's
    # own temporary file instead of asking the daemon to bind that path.
    RELEASE_ENV=$(docker run --rm -i --network none --entrypoint sh \
      "$_ai_verifier_image" -c \
      'cat > /tmp/tunnex-release.json && exec releaseverify -manifest /tmp/tunnex-release.json -public-key "$1" -expected-source-sha "$2" -print-env' \
      sh "$PUBLIC_KEY" "$SOURCE_SHA" < "$MANIFEST") || {
      echo 'error: update blocked; target release verification failed' >&2
      exit 13
    }
    [ "$(release_value TUNNEX_API_IMAGE)" = "$_ai_verifier_image" ] || {
      echo 'error: update blocked; target verifier image did not match the verified release' >&2
      exit 13
    }
    AI_IMAGE_PIN=$(release_value TUNNEX_AI_ENGINE_IMAGE)
  fi
  cp "$HOST_FILES/ai-bootstrap.sh" "$TMPDIR/ai-bootstrap.sh" || {
    echo 'error: the AI bootstrap helper of the signed release is missing from its host files' >&2; exit 13;
  }
  sh -n "$TMPDIR/ai-bootstrap.sh"
  cp "$HOST_FILES/ai-gateway/config-managed.json" "$TMPDIR/ai-engine.json" || {
    echo 'error: the managed AI configuration of the signed release is missing from its host files' >&2; exit 13;
  }
  AI_ENV_FILE=$ENV_FILE
  AI_COMPOSE_PROJECT=${PROJECT:-tunnex}
  ai_fail() { echo "error: update blocked; $*" >&2; exit 13; }
  ai_docker() { docker "$@"; }
  . "$TMPDIR/ai-bootstrap.sh"
  ai_validate_existing
  if [ -f "$DIR/ai-engine.json" ] && grep -Eq '"providers"[[:space:]]*:' "$DIR/ai-engine.json"; then
    ai_fail 'Existing file-managed AI configuration requires a reviewed migration; it was preserved.'
  fi
  if [ "$(dotenv_value TUNNEX_AI_BOOTSTRAP_VERSION)" = 1 ]; then
    # SQLite config/log volumes need a consistent snapshot, together with the
    # matching durable key. Preserve the old engine image for immediate restart.
    _ai_backup_image=$(dotenv_value TUNNEX_AI_ENGINE_IMAGE)
    [ -n "$_ai_backup_image" ] || ai_fail 'Existing AI storage has no recorded engine image.'
    for _ai_volume in ai_engine_config ai_engine_logs; do
      docker volume inspect "${AI_COMPOSE_PROJECT}_${_ai_volume}" >/dev/null || ai_fail 'Recorded AI storage is missing; restore it before upgrading.'
    done
    compose stop bifrost
    AI_SNAPSHOT_STOPPED=true
    _ai_snapshot="$BACKUP_DIR/${BACKUP_BASE}.ai.tar.gz"
    _ai_policy_backup="$BACKUP_DIR/${BACKUP_BASE}.ai-egress-policy.json"
    if ! docker run --rm --network none --user 0 --entrypoint sh \
      -v "${AI_COMPOSE_PROJECT}_ai_engine_config:/snapshot/config:ro" \
      -v "${AI_COMPOSE_PROJECT}_ai_engine_logs:/snapshot/logs:ro" \
      "$_ai_backup_image" -c 'tar -czf - -C /snapshot config logs' >"$_ai_snapshot" ||
      [ ! -s "$_ai_snapshot" ] ||
      ! cp "$ENV_FILE" "$BACKUP_DIR/${BACKUP_BASE}.ai.env" ||
      ! cp "$DIR/ai-engine.json" "$BACKUP_DIR/${BACKUP_BASE}.ai-engine.json" ||
      { [ -f "$_ai_policy_file" ] && ! cp "$_ai_policy_file" "$_ai_policy_backup"; }; then
      compose start bifrost
      AI_SNAPSHOT_STOPPED=false
      ai_fail 'AI storage snapshot failed; the original engine was restarted.'
    fi
    chmod 0600 "$_ai_snapshot" "$BACKUP_DIR/${BACKUP_BASE}.ai.env" "$BACKUP_DIR/${BACKUP_BASE}.ai-engine.json"
    [ ! -f "$_ai_policy_backup" ] || chmod 0600 "$_ai_policy_backup"
    compose start bifrost
    AI_SNAPSHOT_STOPPED=false
  fi
fi
# Online catalog downloads already land at this destination. Avoid copying a
# file onto itself; GNU cp exits non-zero for that case and would abort the
# upgrade after the preflight/backup gate has passed.
if [ "$MANIFEST" != "$TMPDIR/release.json" ]; then
  cp "$MANIFEST" "$TMPDIR/release.json"
fi
for key in TUNNEX_API_IMAGE TUNNEX_WEB_IMAGE TUNNEX_NGINX_IMAGE TUNNEX_NODE_AGENT_IMAGE TUNNEX_MIGRATE_IMAGE TUNNEX_RELEASE_SEQUENCE; do
  set_dotenv "$key" "$(release_value "$key")"
done
set_dotenv TUNNEX_RELEASE_VERSION "$VERSION"
set_dotenv TUNNEX_RELEASE_SOURCE_SHA "$SOURCE_SHA"
set_dotenv TUNNEX_VERSION "$VERSION"
set_dotenv TUNNEX_SOURCE_REF "$SOURCE_SHA"
case "$(dotenv_value TUNNEX_DATABASE_MODE)" in
  external) set_dotenv COMPOSE_PROFILES external-db ;;
  *) set_dotenv COMPOSE_PROFILES bundled-db ;;
esac
if [ "$AA_PRESENT" = true ]; then
  set_dotenv TUNNEX_APP_PROXY_IMAGE "$AA_PROXY_PIN"
  [ "$AA_PROXY" != true ] || set_dotenv COMPOSE_PROFILES "$(base_profile),app-access"
fi
set_dotenv TUNNEX_RELEASE_MANIFEST_PATH /var/lib/tunnex/release.json
mv "$TMPDIR/tunnex.yml" "$COMPOSE"
mv "$TMPDIR/release.json" "$DIR/release.json"
# The descriptor is public signed metadata, not a credential. Curl/mktemp commonly
# leave it at 0600, but the API runs as an unprivileged container user and must be
# able to verify this read-only bind mount at every boot.
chmod 0644 "$DIR/release.json"
ensure_edge_config
if [ "$AI_BUNDLED" = true ]; then
  mv "$TMPDIR/ai-bootstrap.sh" "$DIR/ai-bootstrap.sh"
  [ -f "$DIR/ai-engine.json" ] || mv "$TMPDIR/ai-engine.json" "$DIR/ai-engine.json"
  chmod 0644 "$DIR/ai-engine.json" "$DIR/ai-bootstrap.sh"
  ai_set_env() { set_dotenv "$@"; }
  ai_prepare_config
  if [ "${AI_HTTP_UI_POLICY:-false}" = true ]; then
    echo 'Private AI backend ready; saved HTTP policy is retained in Settings > AI Gateway transport. HTTPS remains available.'
  elif [ -z "$(ai_env_value TUNNEX_AI_GATEWAY_URL)" ]; then
    echo 'Private AI backend installed; AI configuration and access remain off until a real HTTPS public URL is configured.'
  elif [ "$(ai_env_value TUNNEX_AI_ALLOW_PRIVATE_HTTP)" = true ]; then
    echo 'Private HTTP AI is enabled by operator policy; keep the real control-plane endpoint private/VPN-only and network restrictions verified.'
  fi
fi
set_dotenv TUNNEX_COMPOSE_SHA256 "$(file_sha256 "$COMPOSE")"
if [ "$AA_PRESENT" = true ]; then
  # Signed-source overlay replaces any operator overlay (left on disk untouched);
  # identity (barrier volume, secrets, port, project) was verified above.
  mv "$TMPDIR/app-access-compose.yml" "$AA_OVERLAY"
  mv "$TMPDIR/app-access-restore.py" "$DIR/app-access-restore.py"
  # AA-EN-1: the host command (renew; adopt is run from the extracted release).
  mv "$TMPDIR/app-access-tunnex-app-access.py" "$DIR/tunnex-app-access"
  chmod 0644 "$AA_OVERLAY" "$DIR/app-access-restore.py"
  chmod 0755 "$DIR/tunnex-app-access"
  set_dotenv TUNNEX_APP_ACCESS_COMPOSE_SHA256 "$(file_sha256 "$AA_OVERLAY")"
  AA_COMPOSE_ACTIVE=true
  AA_PROFILE_ON=$AA_PROXY
fi
compose pull
write_status restarting
if [ "$AA_PRESENT" = true ]; then
  AA_MUTATION_STARTED=true
  # The old proxy must never talk to the new API; stop it before replacement.
  [ "$AA_PROXY" != true ] || compose stop app-proxy
  AA_PROFILE_ON=false
fi
compose_up -d --wait --wait-timeout 900
compose ps --all
if [ "$AA_PRESENT" = true ]; then
  # The API checked the barrier before migrating. Readback with the target
  # binary: clean schema at its ceiling and the very same completed authority.
  AA_AFTER=$(aa_authority "$AA_OVERLAY") || AA_AFTER=
  if [ -z "$AA_AFTER" ] || [ "${AA_AFTER% *}" != "${AA_BEFORE% *}" ]; then
    AA_AUTHORITY_CHANGED=true
    write_status failed app_access_authority_changed
    echo 'error: upgrade stopped; App Access authority readback after migration did not match the pre-upgrade authority (or a restore marker appeared).' >&2
    exit 13
  fi
  if [ "$AA_PROXY" = true ]; then
    AA_PROFILE_ON=true
    compose up -d --wait --wait-timeout 300 --no-deps app-proxy
  fi
  echo "App Access authority unchanged (generation ${AA_AFTER%% *}); schema ${AA_BEFORE##* } -> ${AA_AFTER##* }"
fi
write_status health_check
if ! healthcheck; then
  write_status failed health_check_failed
  if [ "$AA_PRESENT" = true ]; then
    echo "error: upgrade health check failed" >&2
  else
    echo "error: upgrade health check failed; restore the verified pre-upgrade backup before retrying" >&2
  fi
  exit 14
fi
write_status healthy
if [ "$AA_PRESENT" = true ] && [ -n "$(dotenv_value TUNNEX_APP_ACCESS_ADOPTED_CONFIG_FILES)" ]; then
  # The adopted layout now runs from the managed files; the record has done its job.
  awk -F= '$1 != "TUNNEX_APP_ACCESS_ADOPTED_CONFIG_FILES" && $1 != "TUNNEX_APP_ACCESS_ADOPTED_OVERLAYS_SHA256"' \
    "$ENV_FILE" >"$ENV_FILE.next" && mv "$ENV_FILE.next" "$ENV_FILE" ||
    echo 'warning: the App Access adoption record could not be removed from .env; it is harmless' >&2
fi
# U3: adopt this release's helper only now that it has completed an upgrade on
# this host. A failure here leaves the previous trampoline, which still hands off.
install_host_copies() {
  install -m 0755 "$HOST_FILES/upgrade.sh" "$DIR/upgrade.sh.next" &&
    mv -f "$DIR/upgrade.sh.next" "$DIR/upgrade.sh" || return 1
  [ "${TUNNEX_UPGRADE_PRIVILEGED:-}" = 1 ] || return 0
  ROOT_UPGRADE_DIR=${TUNNEX_ROOT_UPGRADE_DIR:-/usr/local/lib/tunnex}
  if [ "$(id -u)" = 0 ]; then set -- -o root -g root; else set --; fi
  install -d "$@" -m 0755 "$ROOT_UPGRADE_DIR" || return 1
  for _copy in upgrade.sh upgrade-runner.sh; do
    install -m 0755 "$@" "$HOST_FILES/$_copy" "$ROOT_UPGRADE_DIR/$_copy.next" &&
      mv -f "$ROOT_UPGRADE_DIR/$_copy.next" "$ROOT_UPGRADE_DIR/$_copy" || return 1
  done
}
if ! install_host_copies; then
  echo "warning: the upgrade succeeded, but the installed upgrade helper could not be updated; the next upgrade still works through the current helper" >&2
fi
echo "upgrade health check passed"
echo "upgrade applied; retain the backup manifest and dump for forward-only rollback"
