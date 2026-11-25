#!/bin/sh
# LS-UX-1 E.1: the console edge trusts a PROXY v2 client address only from the
# one configured edge address, in every direct-HTTPS Caddy mode, and refuses
# unsafe values. Renders the real Caddy script from tunnex.yml and validates
# each generated Caddyfile with the pinned Caddy image (no network listeners).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TUNNEX_DEPLOY_TEST_TMPDIR:-${TMPDIR:-/tmp}}/tunnex-edge-pp.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
fail() { echo "edge PROXY contract: $*" >&2; exit 1; }
COMPOSE="$ROOT/deploy/tunnex.yml"
grep -Fq 'TUNNEX_EDGE_PROXY_PROTOCOL_FROM: ${TUNNEX_EDGE_PROXY_PROTOCOL_FROM:-}' "$COMPOSE" || fail 'edge setting missing'
IMAGE=$(sed -n 's/^    image: \${TUNNEX_CADDY_IMAGE:-\(caddy@sha256:[0-9a-f]*\)}$/\1/p' "$COMPOSE")
[ -n "$IMAGE" ] || fail 'pinned Caddy image not found'
# Extract the caddy command block, unescape Compose's $$, and replace process
# start with printing and validating the generated configuration.
awk '/^  caddy:/{c=1} c&&/^      - \|$/{s=1;next} s&&/^    ports:/{exit} s{sub(/^        /,"");print}' "$COMPOSE" |
  sed 's/\$\$/$/g; s#exec caddy run --config /tmp/tunnex-Caddyfile --adapter caddyfile#cat /tmp/tunnex-Caddyfile; exec caddy validate --config /tmp/tunnex-Caddyfile --adapter caddyfile#; s#exec caddy reverse-proxy --from "$TUNNEX_EDGE_LISTEN" --to nginx:8080 \(.*\)$#echo "CLI-MODE \1"; exit 0#' >"$TMP/caddy.sh"
grep -q 'caddy validate' "$TMP/caddy.sh" || fail 'could not extract the Caddy script'
run() { docker run --rm --network none -e TUNNEX_HTTP_CONSOLE_ENABLED=false "$@" -v "$TMP/caddy.sh:/s.sh:ro" --entrypoint sh "$IMAGE" /s.sh 2>&1; }
out=$(run -e TUNNEX_EDGE_LISTEN=https://cp.example.com) || fail "default mode: $out"
echo "$out" | grep -q CLI-MODE || fail 'default mode changed without the edge'
# LS-UX-1 F: every mode hands nginx Caddy's client address, never the caller's.
echo "$out" | grep -Fq "X-Real-IP: {client_ip}" || fail 'CLI mode does not set X-Real-IP from Caddy'
for mode in "-e TUNNEX_EDGE_LISTEN=https://cp.example.com -e TUNNEX_HTTP_CONSOLE_ENABLED=true" \
  "-e TUNNEX_EDGE_LISTEN=https://203.0.113.10 -e TUNNEX_EDGE_PUBLIC_IP=203.0.113.10" \
  "-e TUNNEX_TLS_MODE=terminated -e TUNNEX_EDGE_LISTEN=http://:80 -e TUNNEX_EDGE_TRUSTED_PROXIES=10.0.0.5/32"; do
  # shellcheck disable=SC2086
  out=$(run $mode -e TUNNEX_EDGE_APP_PROXY_FROM=172.31.254.4/32) || fail "mode refused: $mode: $out"
  echo "$out" | grep -q 'Valid configuration' || fail "invalid Caddyfile: $mode: $out"
  echo "$out" | grep -Fq 'header_up X-Real-IP {client_ip}' || fail "X-Real-IP not set by Caddy: $mode"
  echo "$out" | grep -Fq 'header_up -True-Client-IP' || fail "True-Client-IP not removed: $mode"
  case "$mode" in
    *terminated*) ! echo "$out" | grep -q '172.31.254.4' || fail 'app-proxy trusted in terminated mode' ;;
    *) echo "$out" | grep -Fq 'trusted_proxies static 172.31.254.4/32' || fail "app-proxy not trusted: $mode" ;;
  esac
done
out=$(run -e TUNNEX_EDGE_LISTEN=https://cp.example.com -e TUNNEX_EDGE_APP_PROXY_FROM=172.31.254.4/32 -e TUNNEX_EDGE_PROXY_PROTOCOL_FROM=172.31.254.2/32) || fail "edge plus app-proxy: $out"
echo "$out" | grep -q 'Valid configuration' && echo "$out" | grep -Fq 'trusted_proxies static 172.31.254.4/32' && echo "$out" | grep -Fq 'allow 172.31.254.2/32' || fail 'edge and app-proxy trust do not combine'
if run -e TUNNEX_EDGE_LISTEN=https://cp.example.com -e TUNNEX_EDGE_APP_PROXY_FROM=0.0.0.0/0 >/dev/null; then fail 'accepted an all-address app-proxy trust'; fi
for mode in "-e TUNNEX_EDGE_LISTEN=https://cp.example.com" \
  "-e TUNNEX_EDGE_LISTEN=https://cp.example.com -e TUNNEX_HTTP_CONSOLE_ENABLED=true" \
  "-e TUNNEX_EDGE_LISTEN=https://203.0.113.10 -e TUNNEX_EDGE_PUBLIC_IP=203.0.113.10"; do
  # shellcheck disable=SC2086
  out=$(run $mode -e TUNNEX_EDGE_PROXY_PROTOCOL_FROM=172.31.254.2/32) || fail "edge mode refused: $mode: $out"
  echo "$out" | grep -q 'Valid configuration' || fail "edge Caddyfile invalid: $mode: $out"
  echo "$out" | grep -q 'allow 172.31.254.2/32' || fail "edge allow missing: $mode"
  echo "$out" | grep -q 'fallback_policy skip' || fail "untrusted sources would be parsed: $mode"
done
out=$(run -e TUNNEX_EDGE_LISTEN=https://203.0.113.10 -e TUNNEX_EDGE_PUBLIC_IP=203.0.113.10) || fail "public IP mode: $out"
! echo "$out" | grep -q proxy_protocol || fail 'PROXY trusted without the edge'
for bad in 0.0.0.0/0 172.31.254.0/29 172.31.254.2 '172.31.254.2/32 10.0.0.1/32'; do
  if run -e TUNNEX_EDGE_LISTEN=https://cp.example.com -e "TUNNEX_EDGE_PROXY_PROTOCOL_FROM=$bad" >/dev/null; then fail "accepted $bad"; fi
done
if run -e TUNNEX_EDGE_LISTEN=http://:80 -e TUNNEX_EDGE_PROXY_PROTOCOL_FROM=172.31.254.2/32 >/dev/null; then fail 'edge accepted without direct HTTPS'; fi
echo 'edge PROXY protocol contract passed'
