#!/usr/bin/env bash
set -euo pipefail

# Reusable, secret-free AWS DEV walk inventory for F08+ AI-agent stories.
# It never deploys, logs in, handles a bootstrap/runtime credential, changes a
# security group, or decides whether a story passes. Invoke `prepare` explicitly
# to create story-scoped 0700 scratch; every other action is read-only.

action=${1:-}
story=${TUNNEX_WALK_STORY:-}
cp_host=${TUNNEX_WALK_CP:-}
vm_host=${TUNNEX_WALK_VM:-}
compose_dir=${TUNNEX_WALK_COMPOSE_DIR:-/home/ubuntu/tunnex}
compose_file=${TUNNEX_WALK_COMPOSE_FILE:-tunnex.yml}
rollback_dir=${TUNNEX_WALK_ROLLBACK_DIR:-}
base_sha=${TUNNEX_WALK_BASE_SHA:-}

usage() {
  printf '%s\n' \
    'usage: TUNNEX_WALK_STORY=F08 TUNNEX_WALK_CP=ubuntu@host [TUNNEX_WALK_VM=ubuntu@host] scripts/ai-agent-dev-walk.sh <preflight|prepare|verify|cleanup-check>' \
    'optional: TUNNEX_WALK_BASE_SHA, TUNNEX_WALK_COMPOSE_DIR, TUNNEX_WALK_COMPOSE_FILE, TUNNEX_WALK_ROLLBACK_DIR'
}

if [[ -z "$story" || -z "$cp_host" ]]; then
  usage >&2
  exit 2
fi
case "$story" in
  *[!A-Za-z0-9_-]*|'') printf 'invalid story prefix\n' >&2; exit 2 ;;
esac
for remote_path in "$compose_dir" "$compose_file" "$rollback_dir"; do
  case "$remote_path" in
    *[!A-Za-z0-9_./-]*) printf 'invalid remote path\n' >&2; exit 2 ;;
  esac
done

ssh_cmd=(ssh -o BatchMode=yes -o ConnectTimeout=10)
head_sha=$(git rev-parse HEAD)
scratch="/home/ubuntu/tunnex-walk/${story}-${head_sha:0:12}"

cp_read() {
  "${ssh_cmd[@]}" "$cp_host" "$@"
}

vm_read() {
  [[ -n "$vm_host" ]] || return 0
  "${ssh_cmd[@]}" "$vm_host" "$@"
}

schema_read="cd '$compose_dir' && docker compose -f '$compose_file' exec -T postgres psql -U tunnex -d tunnex -At -F '|' -c 'SELECT version, dirty FROM schema_migrations LIMIT 1'"

case "$action" in
  preflight)
    printf 'source_sha=%s\n' "$head_sha"
    if [[ -n "$(git status --porcelain)" ]]; then
      printf 'worktree=dirty\n' >&2
      exit 1
    fi
    printf 'worktree=clean\n'
    if [[ -n "$base_sha" ]]; then
      printf 'changed_components='
      git diff --name-only "$base_sha...$head_sha" | awk -F/ '
        /^apps\/(api|web|node|cli)\// {seen[$1 "/" $2]=1}
        /^openapi\// {seen["openapi"]=1}
        END {sep=""; for (v in seen) {printf "%s%s", sep, v; sep=","}; print ""}'
    fi
    cp_read "df -Pk / | tail -1; docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}'"
    printf 'schema='; cp_read "$schema_read"
    if [[ -n "$rollback_dir" ]]; then
      cp_read "test -d '$rollback_dir' && stat -c 'rollback=%n|mode=%a' '$rollback_dir' && test -f '$rollback_dir/SHA256SUMS'"
    else
      printf 'rollback=not-declared\n'
    fi
    vm_read "df -Pk / | tail -1; test -c /dev/net/tun && echo tun=present; systemctl is-system-running || true"
    ;;
  prepare)
    cp_read "install -d -m 0700 '$scratch' && stat -c 'cp_scratch=%n|mode=%a' '$scratch'"
    if [[ -n "$vm_host" ]]; then
      vm_read "install -d -m 0700 '$scratch' && stat -c 'vm_scratch=%n|mode=%a' '$scratch'"
    fi
    ;;
  verify)
    printf 'expected_source_sha=%s\n' "$head_sha"
    cp_read "docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}'; docker inspect \$(docker ps -q) --format '{{.Name}}|{{index .Config.Labels \"org.opencontainers.image.revision\"}}|restarts={{.RestartCount}}'"
    printf 'schema='; cp_read "$schema_read"
    vm_read "systemctl is-active tunnex-agent-runtime.service 2>/dev/null || true; wg show interfaces 2>/dev/null || true"
    ;;
  cleanup-check)
    prefix=$(printf '%s' "$story" | tr '[:upper:]' '[:lower:]')
    cleanup_sql="SELECT 'devices=' || count(*) FROM devices WHERE name LIKE '${prefix}-%' AND deleted_at IS NULL; SELECT 'nodes=' || count(*) FROM nodes WHERE name LIKE '${prefix}-%'; SELECT 'resources=' || count(*) FROM resources WHERE name LIKE '${prefix}-%';"
    cp_read "cd '$compose_dir' && docker compose -f '$compose_file' exec -T postgres psql -v ON_ERROR_STOP=1 -U tunnex -d tunnex -Atc \"$cleanup_sql\"; test ! -e '$scratch' && echo cp_scratch=absent || echo cp_scratch=present"
    if [[ -n "$vm_host" ]]; then
      vm_read "for p in /usr/local/bin/tunnex-agent-runtime /etc/systemd/system/tunnex-agent-runtime.service /etc/wireguard/runtime.conf /etc/tunnex-agent/runtime-credential /var/lib/tunnex-agent/runtime-state.json; do test ! -e \"\$p\" || echo \"managed_path_present=\$p\"; done; test -z \"\$(wg show interfaces 2>/dev/null)\" && echo runtime_interface=absent; test ! -e '$scratch' && echo vm_scratch=absent || echo vm_scratch=present"
    fi
    ;;
  *) usage >&2; exit 2 ;;
esac
