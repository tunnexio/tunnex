#!/usr/bin/env bash
# S3.4 milestone e2e: the config a user downloads actually establishes a tunnel.
# It does what a human does — create a device, fetch its .conf, feed it to a real
# `wg-quick up` in a separate container — then PROVES a WireGuard handshake occurs
# AND traffic flows to the gateway (ping the server's tunnel IP). Tunnel works,
# not tunnel parses.
set -euo pipefail
cd "$(dirname "$0")/.."

# Overlay drops the node-agent's published WG port so the client reaches it
# directly by container IP (avoids docker-proxy's UDP source-mangling hairpin).
export COMPOSE_FILE="docker-compose.yml:e2e/compose.e2e.yml"

API="http://api:8080"
NET="tunnex_default"
OWNER_EMAIL="owner@demo.tunnex.local"
OWNER_PASS="tunnex-demo-password"
DEMO_ORG="01900000-0000-7000-8000-000000000001"
CJAR="$(mktemp -d)"
CONFDIR="$(mktemp -d)"
trap 'rm -rf "$CJAR" "$CONFDIR"' EXIT

say() { printf '\n>> %s\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }
capi() { docker run --rm --network "$NET" -v "$CJAR":/j curlimages/curl:8.11.1 "$@"; }

[ -f .env ] || cp .env.example .env

say "Bring up stack + enroll a node with the real wgctrl backend"
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build postgres redis api >/dev/null
for i in $(seq 1 60); do [ "$(docker compose ps api --format '{{.Health}}' 2>/dev/null)" = healthy ] && break; sleep 2; [ "$i" = 60 ] && fail "api unhealthy"; done
make seed >/dev/null
capi -s -o /dev/null -c /j/cookies -H 'Content-Type: application/json' \
	-d "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$OWNER_PASS\"}" "$API/api/v1/auth/login"
tok=$(capi -s -b /j/cookies -H 'X-Tunnex-CSRF: 1' -H 'Content-Type: application/json' -d '{}' \
	"$API/api/v1/organizations/$DEMO_ORG/nodes/join-token" | jq -r '.join_token')
[ -n "$tok" ] && [ "$tok" != null ] || fail "no join token"
TUNNEX_JOIN_TOKEN="$tok" TUNNEX_WG_BACKEND=wgctrl TUNNEX_NODE_ENDPOINT=node-agent:51820 \
	TUNNEX_AGENT_STATUS_INTERVAL=5s \
	docker compose up -d --build node-agent >/dev/null
for i in $(seq 1 45); do
	docker compose exec -T node-agent wget -qO- http://127.0.0.1:9091/readyz 2>/dev/null | grep -q '"ready"' && break
	sleep 2; [ "$i" = 45 ] && { docker compose logs --tail=30 node-agent; fail "agent not ready"; }
done
NODE_ID=$(capi -s -b /j/cookies "$API/api/v1/organizations/$DEMO_ORG/nodes" | jq -r '.[0].id')

say "Create a device (server-generated key) and fetch its .conf"
capi -s -b /j/cookies -H 'X-Tunnex-CSRF: 1' -H 'Content-Type: application/json' \
	-d "{\"name\":\"laptop\",\"node_id\":\"$NODE_ID\"}" \
	"$API/api/v1/organizations/$DEMO_ORG/devices" | jq -r '.config' > "$CONFDIR/tun.conf"
grep -q "\[Interface\]" "$CONFDIR/tun.conf" || { cat "$CONFDIR/tun.conf"; fail "no config returned"; }
echo "--- downloaded config ---"; sed 's/PrivateKey = .*/PrivateKey = <redacted>/' "$CONFDIR/tun.conf"

say "Bring the tunnel up in a client container and prove a handshake + traffic"
# Give the gateway a moment to reconcile the new peer (push is near-instant).
sleep 2
out=$(docker run --rm --network "$NET" --cap-add NET_ADMIN --device /dev/net/tun \
	-v "$CONFDIR":/cfg alpine:3.20 sh -c '
		apk add --no-cache wireguard-tools iproute2 bash iputils >/dev/null 2>&1
		cp /cfg/tun.conf /etc/wireguard/tun.conf
		wg-quick up tun >/dev/null 2>&1 || { echo "WGQUICK_FAILED"; wg-quick up tun; exit 1; }
		# Poll for up to ~20s: nudge with a ping, then check for a completed
		# handshake (tolerates reconcile + WG retry timing).
		for i in $(seq 1 20); do
			ping -c 1 -W 1 10.99.0.1 >/dev/null 2>&1 || true
			hs=$(wg show tun latest-handshakes | awk "{print \$2}")
			[ "${hs:-0}" -gt 0 ] 2>/dev/null && break
			sleep 1
		done
		ping -c 3 -W 2 10.99.0.1 >/dev/null 2>&1 || true # more traffic to be sure
		echo "=== wg show ==="; wg show tun
	')
echo "$out"

# Handshake proof: a non-zero latest-handshake timestamp.
echo "$out" | grep -qi "latest handshake" || fail "no WireGuard handshake occurred (tunnel did not establish)"
# Traffic proof: the peer's transfer counter shows bytes RECEIVED from the
# gateway — i.e. the gateway decrypted our packets and replied through the
# tunnel (cumulative, so not subject to a single ping window's flakiness).
if echo "$out" | grep -q "0 B received"; then
	fail "no traffic flowed back through the tunnel (0 B received)"
fi
echo "$out" | grep -qE "transfer: .+ received" || fail "no transfer recorded on the tunnel"

say "FULL LOOP: the connected device reports ONLINE to the control plane (S3.6)"
online=""
for _ in $(seq 1 12); do
	online=$(capi -s -b /j/cookies "$API/api/v1/organizations/$DEMO_ORG/devices" | jq -r '.[0].online')
	[ "$online" = "true" ] && break
	sleep 3
done
[ "$online" = "true" ] || fail "device never reported online after connecting"
lh=$(capi -s -b /j/cookies "$API/api/v1/organizations/$DEMO_ORG/devices" | jq -r '.[0].last_handshake_at')
echo "   device online=true, last_handshake_at=$lh"

say "PASS — config established a real tunnel (handshake + traffic) AND the user can see the device is connected."
