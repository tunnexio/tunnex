#!/usr/bin/env bash
# S3.2 WireGuard data-plane e2e: brings up the stack, enrolls a node agent with
# the real wgctrl backend, and PROVES the real path by reading the device back
# with `wg show` / `ip addr` — not by trusting the agent's own logs.
#
# Usage: e2e/wg_dataplane_e2e.sh
# Requires: docker compose, curl, jq.
set -euo pipefail

cd "$(dirname "$0")/.."

# API is reached from a curl container ON the compose network, so this e2e needs
# neither nginx/web nor a host-published api port.
API="http://api:8080"
NET="tunnex_default"
OWNER_EMAIL="owner@demo.tunnex.local"
OWNER_PASS="tunnex-demo-password"
DEMO_ORG="01900000-0000-7000-8000-000000000001"
CJAR="$(mktemp -d)"
trap 'rm -rf "$CJAR"' EXIT

say() { printf '\n>> %s\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }
# capi runs curl on the compose network with a persistent cookie jar at /j/cookies.
capi() { docker run --rm --network "$NET" -v "$CJAR":/j curlimages/curl:8.11.1 "$@"; }

[ -f .env ] || cp .env.example .env

say "Clean slate + build (postgres, redis, api)"
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build postgres redis api

say "Wait for API healthy"
for i in $(seq 1 60); do
  if [ "$(docker compose ps api --format '{{.Health}}' 2>/dev/null)" = "healthy" ]; then break; fi
  sleep 2
  [ "$i" = 60 ] && fail "api never became healthy"
done

say "Seed demo org/owner"
make seed

say "Login as demo owner"
code=$(capi -s -o /dev/null -w '%{http_code}' -c /j/cookies \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$OWNER_PASS\"}" \
  "$API/api/v1/auth/login")
[ "$code" = 200 ] || fail "login returned $code"

say "Mint a join token (unpinned: any node name may enroll)"
tok=$(capi -s -b /j/cookies -H 'X-Tunnex-CSRF: 1' -H 'Content-Type: application/json' \
  -d '{}' \
  "$API/api/v1/organizations/$DEMO_ORG/nodes/join-token" | jq -r '.join_token')
[ -n "$tok" ] && [ "$tok" != null ] || fail "no join token minted"

say "Start node-agent with the real wgctrl backend + the join token"
# Short reconcile interval so the stability check below spans several cycles fast.
TUNNEX_JOIN_TOKEN="$tok" TUNNEX_WG_BACKEND=wgctrl TUNNEX_AGENT_RECONCILE_INTERVAL=2s \
  docker compose up -d --build node-agent

say "Wait for agent readiness (enrolled + control session + backend converged)"
ready=""
for i in $(seq 1 45); do
  if docker compose exec -T node-agent wget -qO- http://127.0.0.1:9091/readyz 2>/dev/null | grep -q '"ready"'; then
    ready=1; break
  fi
  sleep 2
done
if [ -z "$ready" ]; then
  echo "--- node-agent logs ---"; docker compose logs --tail=40 node-agent
  fail "agent never became ready (see logs above — should be diagnosable, not a crash-loop)"
fi

say "READ-BACK: wg show wg0 (proves the real device, not agent self-report)"
wgout=$(docker compose exec -T node-agent wg show wg0)
echo "$wgout"
echo "$wgout" | grep -q "listening port: 51820" || fail "wg0 not listening on 51820"

say "READ-BACK: ip addr show wg0 (interface address from control plane)"
ipout=$(docker compose exec -T node-agent ip addr show wg0)
echo "$ipout"
echo "$ipout" | grep -q "10.99.0.1" || fail "wg0 missing control-plane address 10.99.0.1"

say "STABILITY: wg0 key + port must survive ≥2 reconcile intervals (WS1 regression)"
# The bug wiped the private key + randomized the port on the SECOND reconcile —
# invisible to a single post-enrollment read. Sample the interface line twice,
# > 2 reconcile intervals apart, and require the key + port to be byte-stable.
d1=$(docker compose exec -T node-agent wg show wg0 dump | head -1)
sleep 7 # > 3 × the 2s reconcile interval
d2=$(docker compose exec -T node-agent wg show wg0 dump | head -1)
k1=$(printf '%s' "$d1" | cut -f1); p1=$(printf '%s' "$d1" | cut -f3)
k2=$(printf '%s' "$d2" | cut -f1); p2=$(printf '%s' "$d2" | cut -f3)
printf 't0 : port=%s key_present=%s\n' "$p1" "$([ "$k1" != '(none)' ] && [ -n "$k1" ] && echo yes || echo NO)"
printf 't+7: port=%s key_present=%s\n' "$p2" "$([ "$k2" != '(none)' ] && [ -n "$k2" ] && echo yes || echo NO)"
[ "$k1" != "(none)" ] && [ -n "$k1" ] || fail "wg0 private key was wiped to (none) — syncconf regression"
[ "$k1" = "$k2" ]                    || fail "wg0 private key changed across reconciles"
[ "$p1" = "51820" ] && [ "$p2" = "51820" ] || fail "wg0 listen port not stable at 51820 ($p1 -> $p2)"

say "READ-BACK: control plane persisted the node-reported WG public key"
pk=$(docker compose exec -T -e PGPASSWORD=tunnex_dev_password postgres \
  psql -U tunnex -d tunnex -tAc \
  "SELECT wg_public_key FROM nodes WHERE status='active' ORDER BY enrolled_at DESC LIMIT 1;" | tr -d '[:space:]')
echo "stored wg_public_key: $pk"
[ -n "$pk" ] || fail "control plane did not persist the node-reported WG public key"

say "PASS — real WireGuard device converged to control-plane desired state, key reported."
