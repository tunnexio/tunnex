#!/usr/bin/env bash
set -euo pipefail

# F01 live gate only. This script never starts/stops the compose stack and never
# writes raw credentials into walk artifacts. It expects the approved disposable
# f01-browser enterprise stack and verified fixture credentials to already exist.

: "${F01_COMPOSE_PROJECT:?set F01_COMPOSE_PROJECT to the F03 disposable compose project name}"
: "${F01_BASE_URL:?set F01_BASE_URL to the F03 published HTTP endpoint}"
: "${F01_GATEWAY_CONTAINER:?set F01_GATEWAY_CONTAINER to the F03 disposable Linux gateway container}"

project="$F01_COMPOSE_PROJECT"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
artifact="${F01_ARTIFACT_ROOT:-walk-artifacts/F01}/$run_id"
scratch="$artifact/scratch"
runtime_name="${project}-agent-runtime-$run_id"
mkdir -p "$scratch/runtime" "$scratch/state"
printf 'scratch/\n' > "$artifact/.gitignore"
umask 077

blocked() {
  printf '%s\n' "$*" > "$artifact/data-plane-blocked.txt"
  printf 'BLOCKED: %s\n' "$*" >&2
  exit 2
}

cleanup() {
  docker rm -f "$runtime_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker version >/dev/null 2>&1 || blocked "Docker/Colima unavailable"
test "${TUNNEX_WG_BACKEND:-}" = wgctrl || blocked "TUNNEX_WG_BACKEND must be wgctrl"
gateway_container="$F01_GATEWAY_CONTAINER"
docker inspect "$gateway_container" >/dev/null 2>&1 || blocked "gateway container is absent: $gateway_container"
docker network inspect "${project}_default" >/dev/null 2>&1 || blocked "compose network ${project}_default is absent"
docker exec "$gateway_container" sh -eu -c '
  test -e /dev/net/tun
  command -v wg >/dev/null
  command -v wg-quick >/dev/null
  command -v resolvconf >/dev/null || command -v openresolv >/dev/null
  cap=$(awk "/^CapEff:/ {print \$2}" /proc/self/status)
  test -n "$cap" && test "$cap" != 0000000000000000
' || blocked "disposable Linux gateway lacks tun, wg/wg-quick, resolver, or capabilities"

runtime_image="${F01_RUNTIME_IMAGE-}"
test -n "$runtime_image" || blocked "F01_RUNTIME_IMAGE is required for the F03 approved runtime image"
docker image inspect "$runtime_image" >/dev/null 2>&1 || blocked "approved runtime image is absent: $runtime_image"
docker run --rm --privileged --entrypoint sh "$runtime_image" -eu -c '
  test -x /usr/local/bin/tunnex-agent-runtime
  test -d /etc/tunnex-agent && test -d /var/lib/tunnex-agent
  command -v wg >/dev/null
  command -v wg-quick >/dev/null
  command -v resolvconf >/dev/null || command -v openresolv >/dev/null
  test -e /dev/net/tun
  cap=$(awk "/^CapEff:/ {print \$2}" /proc/self/status)
  test -n "$cap" && test "$cap" != 0000000000000000
' || blocked "approved Linux runtime lacks binary, tun, wg/wg-quick, resolver, or capabilities"
test -s deploy/systemd/tunnex-agent-runtime.service || blocked "managed runtime systemd unit is absent"

: "${F01_OWNER_EMAIL:?set F01_OWNER_EMAIL to the verified owner fixture}"
: "${F01_OWNER_PASSWORD:?set F01_OWNER_PASSWORD to the verified owner fixture}"
: "${F01_MANAGER_EMAIL:?set F01_MANAGER_EMAIL to the verified member-management fixture}"
: "${F01_MANAGER_PASSWORD:?set F01_MANAGER_PASSWORD to the verified member-management fixture}"
: "${F01_ORG_ID:?set F01_ORG_ID to the disposable enterprise org}"
: "${F01_APPROVED_ISSUER:?set F01_APPROVED_ISSUER to the approved issuer URL}"
: "${F01_EXPECTED_ISSUER:?set F01_EXPECTED_ISSUER to the independently approved issuer URL}"
test "$F01_APPROVED_ISSUER" = "$F01_EXPECTED_ISSUER" || blocked "issuer does not match the approved disposable issuer"

docker exec "$gateway_container" wg show > "$scratch/peer-before.raw"
printf 'project=%s\ngateway_container=%s\nissuer=%s\n' "$project" "$gateway_container" "$F01_APPROVED_ISSUER" > "$artifact/preflight.txt"

cookie="$scratch/owner.cookie"
curl -fsS -c "$cookie" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg email "$F01_OWNER_EMAIL" --arg password "$F01_OWNER_PASSWORD" '{email:$email,password:$password}')" \
  "$base_url/api/v1/auth/login" > "$scratch/owner-login.json"

gateway_id="$(curl -fsS -b "$cookie" "$base_url/api/v1/organizations/$F01_ORG_ID/nodes" | jq -er 'map(select(.status == "active" and (.endpoint // "") != ""))[0].id')"
bootstrap_json="$scratch/bootstrap.json"
curl -fsS -b "$cookie" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg name "f01-connected-agent-$run_id" --arg gateway_id "$gateway_id" '{name:$name,gateway_id:$gateway_id}')" \
  "$base_url/api/v1/organizations/$F01_ORG_ID/agents/bootstrap-token" > "$bootstrap_json"
bootstrap_token="$(jq -er '.bootstrap_token' "$bootstrap_json")"

agent_private="$(docker run --rm --entrypoint sh "$runtime_image" -c 'wg genkey')"
agent_public="$(printf '%s\n' "$agent_private" | docker run --rm -i --entrypoint sh "$runtime_image" -c 'wg pubkey')"
agent_fp="$(printf '%s' "$agent_public" | sha256sum | awk '{print $1}')"
curl -fsS -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg token "$bootstrap_token" --arg key "$agent_public" '{bootstrap_token:$token,public_key:$key}')" \
  "$base_url/api/v1/agent/bootstrap" > "$scratch/bootstrap-response.json"
runtime_credential="$(jq -er '.runtime_credential' "$scratch/bootstrap-response.json")"
device_id="$(jq -er '.device.id' "$scratch/bootstrap-response.json")"
jq -n --arg server "${F01_RUNTIME_SERVER:-http://api:8080}" --arg credential "$runtime_credential" \
  '{server:$server,credential:$credential,applied_revision:0,client_version:"f01-live-walk"}' > "$scratch/state/runtime-state.json"
jq -er '.config' "$scratch/bootstrap-response.json" | sed "s/__TUNNEX_PRIVATE_KEY__/$agent_private/" > "$scratch/runtime/runtime.conf"

docker run -d --name "$runtime_name" --network "${project}_default" --privileged \
  --user "$(id -u):$(id -g)" -v "$PWD/$scratch/runtime:/etc/tunnex-agent" \
  -v "$PWD/$scratch/state:/var/lib/tunnex-agent" "$runtime_image" >/dev/null

for _ in $(seq 1 30); do
  if docker exec "$gateway_container" wg show | grep -Fq "$agent_public"; then break; fi
  sleep 1
done
docker exec "$gateway_container" wg show | grep -Fq "$agent_public" || blocked "runtime never published its peer"
printf 'agent_sha256=%s\n' "$agent_fp" > "$artifact/runtime-connected.txt"
docker logs "$runtime_name" 2>&1 | tail -n 30 | sed -E 's/(tnx_[A-Za-z0-9_-]+|[A-Za-z0-9+\/=]{40,})/[REDACTED]/g' > "$artifact/runtime-log-tail.txt"

manager_cookie="$scratch/manager.cookie"
curl -fsS -c "$manager_cookie" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg email "$F01_MANAGER_EMAIL" --arg password "$F01_MANAGER_PASSWORD" '{email:$email,password:$password}')" \
  "$base_url/api/v1/auth/login" > "$scratch/manager-login.json"

profile_before="$scratch/profile-before.json"
curl -fsS -b "$cookie" "$base_url/api/v1/organizations/$F01_ORG_ID/agents/$device_id" > "$profile_before"
before_status="$(jq -er '.status' "$profile_before")"
test "$before_status" = active || blocked "new agent did not begin active"

suspend_status="$(curl -sS -o "$scratch/suspend.json" -w '%{http_code}' -b "$manager_cookie" -X PATCH -H 'Content-Type: application/json' \
  -d '{"status":"suspended"}' "$base_url/api/v1/organizations/$F01_ORG_ID/agents/$device_id")"
test "$suspend_status" = 200 || blocked "manager suspend returned HTTP $suspend_status"
for _ in $(seq 1 30); do
  if ! docker exec "$gateway_container" wg show | grep -Fq "$agent_public"; then break; fi
  sleep 1
done
docker exec "$gateway_container" wg show > "$scratch/peer-suspended.raw"
grep -Fq "$agent_public" "$scratch/peer-suspended.raw" && blocked "suspended peer remained in wg show"
poll_status="$(curl -sS -o "$scratch/suspended-poll.json" -w '%{http_code}' -H "Authorization: Bearer $runtime_credential" \
  "$base_url/api/v1/agent/runtime/poll?applied_revision=0&client_version=f01-live-walk")"
test "$poll_status" = 401 || blocked "suspended runtime poll returned HTTP $poll_status, expected uniform refusal"
curl -fsS -b "$cookie" "$base_url/api/v1/organizations/$F01_ORG_ID/agents/$device_id" > "$scratch/profile-suspended.json"
jq -n --arg status "$(jq -er '.status' "$scratch/profile-suspended.json")" --arg poll "$poll_status" \
  --arg fp "$agent_fp" '{status:$status,poll_status:($poll|tonumber),peer_fingerprint_sha256:$fp,peer_present:false}' > "$artifact/suspended-absent-peer.txt"

resume_status="$(curl -sS -o "$scratch/resume.json" -w '%{http_code}' -b "$manager_cookie" -X PATCH -H 'Content-Type: application/json' \
  -d '{"status":"active"}' "$base_url/api/v1/organizations/$F01_ORG_ID/agents/$device_id")"
test "$resume_status" = 200 || blocked "manager resume returned HTTP $resume_status"
for _ in $(seq 1 30); do
  if docker exec "$gateway_container" wg show | grep -Fq "$agent_public"; then break; fi
  sleep 1
done
docker exec "$gateway_container" wg show > "$scratch/peer-resumed.raw"
grep -Fq "$agent_public" "$scratch/peer-resumed.raw" || blocked "resumed peer did not return to wg show"
curl -fsS -b "$cookie" "$base_url/api/v1/organizations/$F01_ORG_ID/agents/$device_id" > "$scratch/profile-resumed.json"
jq -n --arg status "$(jq -er '.status' "$scratch/profile-resumed.json")" --arg fp "$agent_fp" \
  '{status:$status,peer_fingerprint_sha256:$fp,peer_present:true}' > "$artifact/resumed-peer.txt"

printf 'PASS\n' > "$artifact/connected-agent-live-pass.txt"
printf 'PASS: suspend removed peer and refused poll; resume restored peer.\n'
