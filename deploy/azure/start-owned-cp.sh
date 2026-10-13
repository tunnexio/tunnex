#!/usr/bin/env bash
# Run only on the newly owned Azure peer, through the authorized bastion.
set -euo pipefail
[[ $(hostname) == tunnex-peer ]] || { echo 'Foreign host refused'; exit 1; }
owner=azure-s2s-01a12505
root="$HOME/tunnex-azure-lab"
install -d -m 700 "$root" "$root/state" "$root/tests/azure-s2s-local/.runtime"
python3 - "$root" <<'PYENV'
import os,pathlib,secrets,sys
root=pathlib.Path(sys.argv[1]);env=root/'cp.env'
if not env.exists():
 p=secrets.token_urlsafe(32)
 env.write_text('POSTGRES_USER=azures2s\nPOSTGRES_DB=azures2s\nPOSTGRES_PASSWORD='+p+'\nDATABASE_URL=postgres://azures2s:'+p+'@postgres:5432/azures2s?sslmode=disable\nREDIS_URL=redis://redis:6379/0\nTUNNEX_ENV=development\nTUNNEX_AUTO_MIGRATE=true\nTUNNEX_SECRETS_DIR=/state\nTUNNEX_ADMIN_EMAIL=admin@azure-owned-cloud.local\nTUNNEX_AI_VPN_AUTO=false\nTUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED=false\nAPP_BASE_URL=http://localhost:45173\nTUNNEX_GATEWAY_CONTROL_URL=https://127.0.0.1:48446\n')
 os.chmod(env,0o600)
PYENV
for name in postgres redis api; do
 if sudo docker inspect "tunnex-azure-cloud-$name" >/dev/null 2>&1; then
  [[ $(sudo docker inspect "tunnex-azure-cloud-$name" --format '{{index .Config.Labels "tunnex.owner"}}') == "$owner" ]] || { echo 'Foreign container refused';exit 1; }
 fi
done
if ! sudo docker network inspect tunnex-azure-cloud >/dev/null 2>&1;then sudo docker network create --label tunnex.owner="$owner" tunnex-azure-cloud >/dev/null;fi
if ! sudo docker inspect tunnex-azure-cloud-postgres >/dev/null 2>&1;then
 sudo docker run -d --name tunnex-azure-cloud-postgres --label tunnex.owner="$owner" --network tunnex-azure-cloud --network-alias postgres --env-file "$root/cp.env" -p 127.0.0.1:45440:5432 -v "$root/postgres:/var/lib/postgresql/data" postgres:16-alpine >/dev/null
fi
if ! sudo docker inspect tunnex-azure-cloud-redis >/dev/null 2>&1;then
 sudo docker run -d --name tunnex-azure-cloud-redis --label tunnex.owner="$owner" --network tunnex-azure-cloud --network-alias redis redis:7-alpine >/dev/null
fi
for attempt in $(seq 1 30);do
 if sudo docker exec tunnex-azure-cloud-postgres pg_isready -U azures2s -d azures2s >/dev/null;then break;fi
 sleep 1
done
if ! sudo docker inspect tunnex-azure-cloud-api >/dev/null 2>&1;then
 sudo docker run -d --name tunnex-azure-cloud-api --label tunnex.owner="$owner" --network tunnex-azure-cloud --network-alias api --env-file "$root/cp.env" -p 127.0.0.1:48083:8080 -p 127.0.0.1:48446:8443 -v "$root/state:/state" -v /tmp/azure-s2s-build/tunnex-api:/binaries/tunnex-api:ro alpine:3.24.2 /binaries/tunnex-api >/dev/null
fi
for attempt in $(seq 1 60);do
 if curl -fsS http://127.0.0.1:48083/healthz >/dev/null;then echo 'Owned Azure CP healthy; bootstrap logs remain private';exit 0;fi
 sleep 1
done
echo 'Owned Azure CP not ready; inspect redacted event names';exit 1
