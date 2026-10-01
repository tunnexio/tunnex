#!/bin/sh
# Shared hosted-install/upgrade setup. Callers supply ai_fail, ai_docker and
# ai_set_env; configuration is parsed as data, never sourced as shell code.
# BEGIN HOSTED AI BOOTSTRAP
AI_HTTP_UI_POLICY=true
ai_env_value() {
  [ -f "$AI_ENV_FILE" ] || return 0
  sed -n "s/^$1=//p" "$AI_ENV_FILE" | head -1
}

ai_public_host() {
  case "$1" in
    http://*|https://*) _ai_authority=${1#*://} ;;
    *) ai_fail 'AI egress requires a valid public HTTP or HTTPS origin.' ;;
  esac
  case "$_ai_authority" in
    ''|*/*|*\?*|*\#*|*@*|*[[:space:]]*|*[![:alnum:].:\[\]-]*)
      ai_fail 'AI egress requires a valid public HTTP or HTTPS origin.' ;;
  esac
  case "$_ai_authority" in
    \[*\]*)
      _ai_host=${_ai_authority#\[}
      _ai_host=${_ai_host%%\]*}
      _ai_suffix=${_ai_authority#*\]}
      case "$_ai_host" in *[![:xdigit:].:]*|'') ai_fail 'AI egress public origin has an invalid host.' ;; esac
      case "$_ai_host" in *:*) ;; *) ai_fail 'AI egress public origin has an invalid IPv6 host.' ;; esac
      ;;
    *)
      _ai_host=${_ai_authority%%:*}
      _ai_suffix=${_ai_authority#"$_ai_host"}
      case "$_ai_host" in *[![:alnum:].-]*|'') ai_fail 'AI egress public origin has an invalid host.' ;; esac
      ;;
  esac
  case "$_ai_suffix" in
    '') ;;
    :*)
      _ai_port=${_ai_suffix#:}
      case "$_ai_port" in ''|*[!0-9]*) ai_fail 'AI egress public origin has an invalid port.' ;; esac
      [ "${#_ai_port}" -le 5 ] && [ "$_ai_port" -gt 0 ] && [ "$_ai_port" -le 65535 ] ||
        ai_fail 'AI egress public origin has an invalid port.'
      ;;
    *) ai_fail 'AI egress public origin has an invalid authority.' ;;
  esac
  printf '%s\n' "$_ai_host" | tr '[:upper:]' '[:lower:]'
}

ai_windows_paths() {
  case "${HOST_KERNEL:-${TUNNEX_HOST_KERNEL:-$(uname -s)}}" in
    MINGW*|MSYS*|CYGWIN*) command -v cygpath >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

ai_validate_egress() {
  _ai_proxy_present=0
  for _ai_key in TUNNEX_AI_CUSTOM_PROXY_USERNAME TUNNEX_AI_CUSTOM_PROXY_PASSWORD TUNNEX_AI_CUSTOM_PROXY_URL TUNNEX_AI_CUSTOM_ENDPOINTS_FILE; do
    _ai_count=$(grep -c "^${_ai_key}=" "$AI_ENV_FILE" 2>/dev/null || true)
    [ "${_ai_count:-0}" -le 1 ] || ai_fail 'AI egress configuration contains duplicate entries; restore the protected configuration before continuing.'
  done
  _ai_proxy_user=$(ai_env_value TUNNEX_AI_CUSTOM_PROXY_USERNAME)
  _ai_proxy_password=$(ai_env_value TUNNEX_AI_CUSTOM_PROXY_PASSWORD)
  [ -z "$_ai_proxy_user" ] || _ai_proxy_present=$((_ai_proxy_present + 1))
  [ -z "$_ai_proxy_password" ] || _ai_proxy_present=$((_ai_proxy_present + 1))
  case "$_ai_proxy_present" in
    0|2) ;;
    *) ai_fail 'AI egress credentials are incomplete; restore the protected configuration before continuing.' ;;
  esac
  if [ "$_ai_proxy_present" -eq 2 ]; then
    # These credentials are embedded in a URL and dotenv, so require URL-safe
    # characters instead of silently re-encoding an operator's saved value.
    case "$_ai_proxy_user$_ai_proxy_password" in
      *[![:alnum:]_.~-]*) ai_fail 'AI egress credentials need a reviewed migration to the bundled authenticated proxy.' ;;
    esac
  fi
  _ai_proxy_url=$(ai_env_value TUNNEX_AI_CUSTOM_PROXY_URL)
  if [ -n "$_ai_proxy_url" ]; then
    [ "$_ai_proxy_present" -eq 2 ] &&
      [ "$_ai_proxy_url" = "http://${_ai_proxy_user}:${_ai_proxy_password}@ai-egress:8190" ] ||
      ai_fail 'An operator-managed AI egress proxy is configured; preserve it and review migration before using the bundled proxy.'
  fi
  _ai_policy_dir=$(CDPATH= cd -- "$(dirname -- "$AI_ENV_FILE")" && pwd) || ai_fail 'Could not locate the protected AI configuration directory.'
  _ai_windows_paths=false
  if ai_windows_paths; then _ai_windows_paths=true; fi
  _ai_policy_file=$(ai_env_value TUNNEX_AI_CUSTOM_ENDPOINTS_FILE)
  if [ -n "$_ai_policy_file" ]; then
    case "$_ai_policy_file" in
      /*) ;;
      [[:alpha:]]:/*)
        [ "$_ai_windows_paths" = true ] || ai_fail 'The AI egress policy path requires a Windows host.'
        _ai_policy_file=$(cygpath -u -- "$_ai_policy_file") || ai_fail 'Could not resolve the Windows AI egress policy path.'
        case "$_ai_policy_file" in /*) ;; *) ai_fail 'The AI egress policy path must be absolute.' ;; esac
        ;;
      *) ai_fail 'The AI egress policy path must be absolute.' ;;
    esac
    [ -f "$_ai_policy_file" ] && [ -r "$_ai_policy_file" ] && [ -s "$_ai_policy_file" ] ||
      ai_fail 'The configured AI egress policy is missing or unreadable; restore it before continuing.'
  else
    _ai_policy_file="$_ai_policy_dir/ai-egress-policy.json"
    if [ -e "$_ai_policy_file" ]; then
      [ -f "$_ai_policy_file" ] && [ -r "$_ai_policy_file" ] && [ -s "$_ai_policy_file" ] ||
      ai_fail 'The existing AI egress policy is missing or unreadable; restore it before continuing.'
    fi
  fi
  _ai_policy_env=$_ai_policy_file
  if [ "$_ai_windows_paths" = true ]; then
    # Docker Compose reads dotenv itself; Git Bash cannot convert this bind
    # source as a command argument. Persist a native absolute source while
    # retaining the POSIX form for shell file operations and later reruns.
    _ai_policy_env=$(cygpath -m -- "$_ai_policy_file") || ai_fail 'Could not prepare the Windows AI egress policy mount.'
    case "$_ai_policy_env" in
      [[:alpha:]]:/*|//*) ;;
      *) ai_fail 'The Windows AI egress policy mount must be absolute.' ;;
    esac
  fi
  # A policy is data. JSON/schema validation belongs to the strict runtime
  # loader; setup never executes a policy or overwrites an operator's rules.
  if [ ! -e "$_ai_policy_file" ] && [ -n "$(ai_env_value APP_BASE_URL)" ]; then
    ai_public_host "$(ai_env_value APP_BASE_URL)" >/dev/null
  fi
}

ai_validate_existing() {
  _ai_present=0
  for _ai_key in TUNNEX_AI_GATEWAY_ADMIN_USER TUNNEX_AI_GATEWAY_ADMIN_PASSWORD TUNNEX_AI_ENGINE_ENCRYPTION_KEY; do
    _ai_count=$(grep -c "^${_ai_key}=" "$AI_ENV_FILE" 2>/dev/null || true)
    [ "${_ai_count:-0}" -le 1 ] || ai_fail 'AI configuration contains duplicate secret entries; restore the protected configuration before continuing.'
    [ -z "$(ai_env_value "$_ai_key")" ] || _ai_present=$((_ai_present + 1))
  done
  case "$_ai_present" in
    0)
      # A missing key must never be replaced against retained encrypted state.
      _ai_volumes=$(ai_docker volume ls --quiet --filter "name=^${AI_COMPOSE_PROJECT}_ai_engine_" ) ||
        ai_fail 'Could not inspect existing AI storage before preparing its durable key.'
      [ -z "$_ai_volumes" ] || ai_fail 'AI storage already exists but its protected credentials are missing. Restore the matching encryption key; no replacement key was generated.'
      ;;
    3) ;;
    *) ai_fail 'AI credentials are incomplete. Restore the matching protected configuration; no replacement key was generated.' ;;
  esac
  _ai_existing_url=$(ai_env_value TUNNEX_AI_GATEWAY_URL)
  case "$(ai_env_value TUNNEX_AI_ALLOW_PRIVATE_HTTP)" in
    ''|true|false) ;;
    *) ai_fail 'TUNNEX_AI_ALLOW_PRIVATE_HTTP must be true or false; no network restriction is inferred by setup.' ;;
  esac
  if [ -n "$_ai_existing_url" ]; then
    [ "$_ai_existing_url" = http://bifrost:8080 ] || ai_fail 'An operator-managed AI endpoint is configured. Preserve it and review migration before using the bundled backend.'
    [ "$(ai_env_value TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED)" = true ] || ai_fail 'File-managed AI providers require a reviewed transition before using the bundled managed backend.'
  fi
  ai_validate_egress
}

ai_prepare_policy() {
  [ ! -e "$_ai_policy_file" ] || return 0
  _ai_public_host=$(ai_public_host "$(ai_env_value APP_BASE_URL)") || ai_fail 'Could not prepare the AI egress public origin.'
  _ai_database_mode=$(ai_env_value TUNNEX_DATABASE_MODE)
  if [ -z "$_ai_database_mode" ]; then
    case ",$(ai_env_value COMPOSE_PROFILES)," in
      *,external-db,*) _ai_database_mode=external ;;
      *,bundled-db,*) _ai_database_mode=bundled ;;
      *) _ai_database_mode=${DB_MODE:-bundled} ;;
    esac
  fi
  case "$_ai_database_mode" in
    bundled) _ai_postgres=',"postgres"' ;;
    external) _ai_postgres='' ;;
    *) ai_fail 'AI egress requires a valid bundled or external database mode.' ;;
  esac
  _ai_policy_tmp=$(mktemp "$_ai_policy_dir/.ai-egress-policy.XXXXXX") || ai_fail 'Could not prepare the AI egress policy.'
  if ! printf '{"public_https":true,"endpoints":[],"protected_hosts":["api","bifrost","redis","web","nginx","caddy","ai-egress","%s"%s],"denied_cidrs":[]}\n' \
    "$_ai_public_host" "$_ai_postgres" >"$_ai_policy_tmp" ||
    ! chmod 0644 "$_ai_policy_tmp" || ! mv "$_ai_policy_tmp" "$_ai_policy_file"; then
    rm -f "$_ai_policy_tmp"
    ai_fail 'Could not publish the AI egress policy.'
  fi
}

ai_prepare_config() {
  ai_validate_existing
  ai_prepare_policy
  if [ "$_ai_present" -eq 0 ]; then
    command -v openssl >/dev/null 2>&1 || ai_fail 'OpenSSL is required to generate private AI bootstrap credentials.'
    _ai_user="tunnex-$(openssl rand -hex 8)" || ai_fail 'Could not generate AI administrator credentials.'
    _ai_password=$(openssl rand -hex 32) || ai_fail 'Could not generate AI administrator credentials.'
    _ai_encryption=$(openssl rand -hex 32) || ai_fail 'Could not generate the durable AI encryption key.'
    ai_set_env TUNNEX_AI_GATEWAY_ADMIN_USER "$_ai_user"
    ai_set_env TUNNEX_AI_GATEWAY_ADMIN_PASSWORD "$_ai_password"
    ai_set_env TUNNEX_AI_ENGINE_ENCRYPTION_KEY "$_ai_encryption"
    unset _ai_user _ai_password _ai_encryption
  fi
  if [ "$_ai_proxy_present" -eq 0 ]; then
    command -v openssl >/dev/null 2>&1 || ai_fail 'OpenSSL is required to generate private AI egress credentials.'
    _ai_proxy_user="tunnex-$(openssl rand -hex 8)" || ai_fail 'Could not generate AI egress credentials.'
    _ai_proxy_password=$(openssl rand -hex 32) || ai_fail 'Could not generate AI egress credentials.'
    ai_set_env TUNNEX_AI_CUSTOM_PROXY_USERNAME "$_ai_proxy_user"
    ai_set_env TUNNEX_AI_CUSTOM_PROXY_PASSWORD "$_ai_proxy_password"
  fi
  ai_set_env TUNNEX_AI_CUSTOM_PROXY_URL "http://${_ai_proxy_user}:${_ai_proxy_password}@ai-egress:8190"
  ai_set_env TUNNEX_AI_CUSTOM_ENDPOINTS_FILE "$_ai_policy_env"
  unset _ai_proxy_user _ai_proxy_password _ai_proxy_url
  ai_set_env TUNNEX_AI_ENGINE_IMAGE "$AI_IMAGE_PIN"
  ai_set_env TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED true
  ai_set_env TUNNEX_AI_BOOTSTRAP_VERSION 1
  _ai_private_http=$(ai_env_value TUNNEX_AI_ALLOW_PRIVATE_HTTP)
  [ -n "$_ai_private_http" ] || _ai_private_http=false
  ai_set_env TUNNEX_AI_ALLOW_PRIVATE_HTTP "$_ai_private_http"
  # Always prepare the internal backend. The persisted instance-admin policy
  # gates HTTP requests at the API; blanking this URL would make the UI opt-in
  # ineffective until an operator edits the host and restarts the application.
  ai_set_env TUNNEX_AI_GATEWAY_URL http://bifrost:8080
  chmod 0600 "$AI_ENV_FILE"
}
# END HOSTED AI BOOTSTRAP
