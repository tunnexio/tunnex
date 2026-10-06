#!/bin/sh
# Independent native fixture: public-only trust mount, synthetic keys in Go RAM.
set -eu
cd "$(dirname "$0")"
nonce=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
case "$nonce" in ????????????) ;; *) exit 1 ;; esac
name="sa-native-rotation-$nonce"
folder=".runtime/recording-volume/recovery-native-$nonce"
mkdir -m 755 "$folder"
./run.sh exec -T -e TUNNEX_SA_NATIVE_ROTATION=1 -e "TUNNEX_SA_NATIVE_DIR=/owned-recordings/recovery-native-$nonce" api /binaries/native-recovery-agent-tests -test.run '^TestRecoveryNativeCARotation$' -test.v > "$folder/test.log" 2>&1 &
worker=$!
wait_file() {
 count=0
 while [ ! -f "$1" ]; do
  kill -0 "$worker" 2>/dev/null || { cat "$folder/test.log"; exit 1; }
  count=$((count+1)); [ "$count" -le 400 ] || { echo 'native phase timeout' >&2; exit 1; }
  sleep 0.1
 done
}
wait_file "$folder/old.pub"
wait_file "$folder/new.pub"
chmod 644 "$folder/old.pub" "$folder/new.pub"
cp "$folder/old.pub" "$folder/ca.pub"
chmod 644 "$folder/ca.pub"
network=tunnex-sa0-browser-1005_default
./docker-local.sh network inspect "$network" >/dev/null
./docker-local.sh run -d --name "$name" --network "$network" --network-alias "$name" --label tunnex.fixture=sa-native-rotation --label "tunnex.fixture.owner=$(pwd -P)" --mount "type=bind,src=$(pwd -P)/$folder,dst=/ssh-fixture,readonly" --mount "type=bind,src=$(pwd -P)/recovery-native-target.sh,dst=/fixture/recovery-native-target.sh,readonly" --entrypoint /bin/sh tunnex-sa0-tools:local /fixture/recovery-native-target.sh >/dev/null
count=0
until ./docker-local.sh exec "$name" sh -c 'test -f /ssh-state/host.pub && pgrep -f "[s]shd.*listener" >/dev/null'; do
 count=$((count+1));[ "$count" -le 100 ] || exit 1;sleep 0.1
done
fingerprint=$(./docker-local.sh exec "$name" ssh-keygen -lf /ssh-state/host.pub -E sha256 | awk '{print $2}')
python3 - "$folder/ready.json" "$name:2222" "$fingerprint" <<'PY'
import json,sys
with open(sys.argv[1],'w') as f:json.dump({'address':sys.argv[2],'fingerprint':sys.argv[3]},f)
PY
wait_file "$folder/old-phase.done"
cp "$folder/new.pub" "$folder/ca.pub"
printf 'publictrust switched\n' > "$folder/trust-switched.done"
wait "$worker" || { cat "$folder/test.log";exit 1; }
cat "$folder/test.log"
printf 'New native target retained for inspection: %s (no host port, public CA mount only).\n' "$name"
