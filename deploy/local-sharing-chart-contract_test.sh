#!/usr/bin/env bash
# LS-UX-1 D.1: the control-plane chart runs Local Sharing only from a signed
# digest, independently of App Access, sharing only the authority listener and
# restore fence when both are enabled.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHART="$ROOT/deploy/helm/tunnex-cp"
TMP=$(mktemp -d "${TUNNEX_DEPLOY_TEST_TMPDIR:-${TMPDIR:-/tmp}}/tunnex-ls-chart.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
fail() { echo "local sharing chart: $*" >&2; exit 1; }
D="sha256:$(printf 'a%.0s' $(seq 64))"
BASE=(--namespace ls-check --set appBaseURL=https://cp.example.com
  --set masterKey.existingSecret=roots --set redis.urlSecret=redis --set database.urlSecret=database)
LS=(--set localSharing.enabled=true --set localSharing.baseDomain=share.example.dev
  --set localSharing.proxyURL=https://cp.example.com:8447 --set localSharing.restore.existingClaim=fence
  --set "localSharing.proxy.image=ghcr.io/tunnexio/tunnex-beam-proxy@$D" --set localSharing.proxy.credentialSecret=c
  --set localSharing.proxy.publicTLSSecret=p --set localSharing.proxy.connectorTLSSecret=k --set localSharing.proxy.agentCASecret=a)
AA=(--set appAccess.enabled=true --set appAccess.baseDomain=apps.example.com --set appAccess.restore.existingClaim=fence
  --set "appAccess.proxy.image=ghcr.io/tunnexio/tunnex-app-proxy@$D" --set appAccess.proxy.credentialSecret=c
  --set appAccess.proxy.publicTLSSecret=p --set appAccess.proxy.gatewayTLSSecret=g --set appAccess.proxy.agentCASecret=a)

helm template t "$CHART" "${BASE[@]}" >"$TMP/default.yaml"
! grep -Eq 'beam-proxy|app-authority|TUNNEX_APP_PROXY_AUTHORITY_ADDR' "$TMP/default.yaml" || fail 'default renders Local Sharing or authority'

helm template t "$CHART" "${BASE[@]}" "${LS[@]}" >"$TMP/ls.yaml"
grep -q 'name: beam-proxy$' "$TMP/ls.yaml" || fail 'Local Sharing deployment missing'
grep -q "image: \"ghcr.io/tunnexio/tunnex-beam-proxy@$D\"" "$TMP/ls.yaml" || fail 'proxy not pinned by digest'
grep -q 'metadata: {name: app-authority}' "$TMP/ls.yaml" || fail 'Local Sharing alone lacks the authority service'
grep -q 'TUNNEX_APP_PROXY_AUTHORITY_ADDR' "$TMP/ls.yaml" || fail 'API authority listener missing without App Access'
grep -q 'TUNNEX_BEAM_BASE_DOMAIN' "$TMP/ls.yaml" || fail 'API Local Sharing seed missing'
! grep -Eq 'name: app-proxy$|TUNNEX_APP_ACCESS_BASE_DOMAIN' "$TMP/ls.yaml" || fail 'Local Sharing pulled in App Access'

helm template t "$CHART" "${BASE[@]}" "${AA[@]}" >"$TMP/aa.yaml"
! grep -q 'beam-proxy' "$TMP/aa.yaml" || fail 'App Access pulled in Local Sharing'
grep -q 'metadata: {name: app-authority}' "$TMP/aa.yaml" || fail 'App Access lost its authority service'

helm template t "$CHART" "${BASE[@]}" "${AA[@]}" "${LS[@]}" >"$TMP/both.yaml"
[ "$(grep -c 'metadata: {name: app-authority}' "$TMP/both.yaml")" -eq 1 ] || fail 'authority service duplicated'

for bad in "localSharing.proxy.image=ghcr.io/tunnexio/tunnex-beam-proxy:latest" "localSharing.proxy.credentialSecret=" "api.replicas=2"; do
  if helm template t "$CHART" "${BASE[@]}" "${LS[@]}" --set "$bad" >/dev/null 2>&1; then fail "accepted $bad"; fi
done
if helm template t "$CHART" "${BASE[@]}" "${AA[@]}" "${LS[@]}" --set appAccess.restore.existingClaim=other >/dev/null 2>&1; then
  fail 'accepted two restore fences'
fi
echo 'local sharing chart contract passed'
