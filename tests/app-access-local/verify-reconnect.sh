#!/bin/sh
set -eu
cd "$(dirname "$0")"
./verify.sh
snapshot() {
 ./run.sh exec -T postgres psql -U aa0 -d aa0 -v ON_ERROR_STOP=1 -Atc "select id::text || ':' || cert_serial || ':' || cert_key_fingerprint from nodes where name='aa0-gateway' and status='active';"
}
before=$(snapshot)
[ -n "$before" ]
# Require a heartbeat newer than the pre-restart database timestamp.
threshold=$(./run.sh exec -T postgres psql -U aa0 -d aa0 -Atc 'select now();')
./run.sh restart gateway
attempt=0
while [ "$attempt" -lt 30 ]; do
 if curl --fail --silent http://127.0.0.1:19093/readyz >/dev/null; then
   fresh=$(./run.sh exec -T postgres psql -U aa0 -d aa0 -At -v threshold="$threshold" <<'SQL'
select count(*) from nodes where name='aa0-gateway' and status='active' and last_seen_at > :'threshold'::timestamptz;
SQL
)
   [ "$fresh" != 1 ] || break
 fi
 attempt=$((attempt+1))
 sleep 1
done
[ "$attempt" -lt 30 ] || { echo 'Gateway reconnect heartbeat timed out' >&2; exit 1; }
after=$(snapshot)
[ "$before" = "$after" ] || { echo 'Gateway node/certificate identity changed' >&2; exit 1; }
./verify.sh
printf '%s\n' 'Retained node ID, certificate serial and key fingerprint; post-restart heartbeat verified.'
