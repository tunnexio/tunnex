#!/usr/bin/env bash
# S3.3 peer/device lifecycle e2e: proves the real data-plane consequences of the
# control-plane API against a live agent + kernel WireGuard device:
#   - create device -> peer appears on the gateway (`wg show`) within <5s (push)
#   - revoke device -> peer disappears within <5s
#   - deactivate the owner -> that user's peer disappears within <5s (offboarding)
# Read back from the DEVICE, not from API responses.
set -euo pipefail
cd "$(dirname "$0")/.."

API="http://api:8080"
NET="tunnex_default"
OWNER_EMAIL="owner@demo.tunnex.local"
OWNER_PASS="tunnex-demo-password"
DEMO_ORG="01900000-0000-7000-8000-000000000001"
MEMBER_ID="01900000-0000-7000-8000-0000000000aa"
CJAR="$(mktemp -d)"
trap 'rm -rf "$CJAR"' EXIT

say() { printf '\n>> %s\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }
capi() { docker run --rm --network "$NET" -v "$CJAR":/j curlimages/curl:8.11.1 "$@"; }
psql_c() { docker compose exec -T -e PGPASSWORD=tunnex_dev_password postgres psql -U tunnex -d tunnex -tAc "$1"; }
wg_dump() { docker compose exec -T node-agent wg show wg0 dump; }

# wait_peer <pubkey> <present|absent> — polls wg0 every 100ms up to 5s (the S3.1
# bound), prints elapsed, fails on timeout. Uses iteration count for portable ms.
wait_peer() {
	local key="$1" want="$2" i have
	for i in $(seq 0 50); do
		if wg_dump | grep -qF "$key"; then have=1; else have=0; fi
		if { [ "$want" = present ] && [ "$have" = 1 ]; } || { [ "$want" = absent ] && [ "$have" = 0 ]; }; then
			printf '   peer %s within ~%dms\n' "$want" "$((i*100))"; return 0
		fi
		sleep 0.1
	done
	fail "peer did not become $want within 5s (key=$key)"
}

[ -f .env ] || cp .env.example .env

say "Bring up stack (postgres, redis, api) + seed"
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build postgres redis api >/dev/null
for i in $(seq 1 60); do [ "$(docker compose ps api --format '{{.Health}}' 2>/dev/null)" = healthy ] && break; sleep 2; [ "$i" = 60 ] && fail "api unhealthy"; done
make seed >/dev/null

say "Login + enroll a node with the real wgctrl backend"
capi -s -o /dev/null -c /j/cookies -H 'Content-Type: application/json' \
	-d "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$OWNER_PASS\"}" "$API/api/v1/auth/login"
tok=$(capi -s -b /j/cookies -H 'X-Tunnex-CSRF: 1' -H 'Content-Type: application/json' -d '{}' \
	"$API/api/v1/organizations/$DEMO_ORG/nodes/join-token" | jq -r '.join_token')
[ -n "$tok" ] && [ "$tok" != null ] || fail "no join token"
TUNNEX_JOIN_TOKEN="$tok" TUNNEX_WG_BACKEND=wgctrl docker compose up -d --build node-agent >/dev/null
for i in $(seq 1 45); do
	docker compose exec -T node-agent wget -qO- http://127.0.0.1:9091/readyz 2>/dev/null | grep -q '"ready"' && break
	sleep 2; [ "$i" = 45 ] && { docker compose logs --tail=30 node-agent; fail "agent not ready"; }
done
NODE_ID=$(capi -s -b /j/cookies "$API/api/v1/organizations/$DEMO_ORG/nodes" | jq -r '.[0].id')
[ -n "$NODE_ID" ] && [ "$NODE_ID" != null ] || fail "no node id"

say "Seed a second org member (for the offboarding trace)"
psql_c "INSERT INTO users (id,email,name,status,email_verified_at) VALUES ('$MEMBER_ID','member@demo.tunnex.local','Member','active',now()) ON CONFLICT (id) DO NOTHING;" >/dev/null
psql_c "INSERT INTO memberships (org_id,user_id,role) VALUES ('$DEMO_ORG','$MEMBER_ID','member') ON CONFLICT DO NOTHING;" >/dev/null

say "Create a device for the owner (server-generated key)"
OWNER_PK=$(capi -s -b /j/cookies -H 'X-Tunnex-CSRF: 1' -H 'Content-Type: application/json' \
	-d "{\"name\":\"owner-laptop\",\"node_id\":\"$NODE_ID\"}" \
	"$API/api/v1/organizations/$DEMO_ORG/devices" | jq -r '.device.public_key')
[ -n "$OWNER_PK" ] && [ "$OWNER_PK" != null ] || fail "no owner device pubkey"
say "Owner peer should appear on wg0 (push):"
wait_peer "$OWNER_PK" present

say "Admin-create a device bound to the member"
MEMBER_DEV=$(capi -s -b /j/cookies -H 'X-Tunnex-CSRF: 1' -H 'Content-Type: application/json' \
	-d "{\"name\":\"member-phone\",\"node_id\":\"$NODE_ID\",\"user_id\":\"$MEMBER_ID\"}" \
	"$API/api/v1/organizations/$DEMO_ORG/devices")
MEMBER_PK=$(echo "$MEMBER_DEV" | jq -r '.device.public_key')
MEMBER_DEV_ID=$(echo "$MEMBER_DEV" | jq -r '.device.id')
[ -n "$MEMBER_PK" ] && [ "$MEMBER_PK" != null ] || fail "no member device pubkey"
say "Member peer should appear on wg0:"
wait_peer "$MEMBER_PK" present

say "Revoke the owner's device -> peer removed from the gateway (<5s):"
capi -s -o /dev/null -b /j/cookies -H 'X-Tunnex-CSRF: 1' -X POST \
	"$API/api/v1/organizations/$DEMO_ORG/devices/$(capi -s -b /j/cookies "$API/api/v1/organizations/$DEMO_ORG/devices" | jq -r ".[] | select(.public_key==\"$OWNER_PK\") | .id")/revoke"
wait_peer "$OWNER_PK" absent

say "OFFBOARDING: deactivate the member -> their peer leaves the device (<5s):"
capi -s -o /dev/null -b /j/cookies -H 'X-Tunnex-CSRF: 1' -X POST \
	"$API/api/v1/organizations/$DEMO_ORG/members/$MEMBER_ID/deactivate"
wait_peer "$MEMBER_PK" absent

say "PASS — device create/revoke and owner-deactivation converge on the real WG device within the <5s bound."
