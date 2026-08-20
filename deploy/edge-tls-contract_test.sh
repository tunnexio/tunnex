#!/bin/sh
# Narrow contract for the provider-neutral Docker edge. It deliberately checks
# topology, not a live certificate authority: Caddy owns host ports, nginx stays
# internal, and API session-cookie transport is explicitly configured.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
COMPOSE="$ROOT/deploy/tunnex.yml"

grep -Fq 'TUNNEX_COOKIE_SECURE: ${TUNNEX_COOKIE_SECURE:-false}' "$COMPOSE"
grep -Fq 'image: caddy@sha256:' "$COMPOSE"
grep -Fq '"80:80"' "$COMPOSE"
grep -Fq '"443:443"' "$COMPOSE"
grep -Fq 'TUNNEX_EDGE_LISTEN:?set by install.sh' "$COMPOSE"

if sed -n '/^  nginx:/,/^  [a-z].*:/p' "$COMPOSE" | grep -q 'ports:'; then
	echo 'nginx must not publish a host edge port' >&2
	exit 1
fi

for installer in "$ROOT/deploy/get.sh" "$ROOT/deploy/install.sh"; do
	grep -Fq 'TUNNEX_TLS_MODE=${TLS_MODE}' "$installer"
	grep -Fq 'TUNNEX_EDGE_LISTEN=${EDGE_LISTEN}' "$installer"
	grep -Fq 'TUNNEX_COOKIE_SECURE=${COOKIE_SECURE}' "$installer"
	grep -Fq 'Direct HTTPS needs a DNS hostname on port 443' "$installer"
done

grep -Fq 'ensure_edge_config()' "$ROOT/deploy/upgrade.sh"
grep -Fq 'set_dotenv TUNNEX_EDGE_LISTEN' "$ROOT/deploy/upgrade.sh"
grep -Fq 'set_dotenv TUNNEX_COOKIE_SECURE' "$ROOT/deploy/upgrade.sh"

echo 'installer edge TLS contract: PASS'
