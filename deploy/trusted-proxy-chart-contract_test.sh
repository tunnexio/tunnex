#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHART="$ROOT/deploy/helm/tunnex-cp"
# Local container VMs may not share the host's default temporary directory.
TMP=$(mktemp -d "${TUNNEX_DEPLOY_TEST_TMPDIR:-${TMPDIR:-/tmp}}/tunnex-proxy.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
BASE=(--namespace transport-check --set appBaseURL=https://vpn.example.com
  --set masterKey.existingSecret=roots --set redis.urlSecret=redis
  --set database.urlSecret=database)
helm template transport "$CHART" "${BASE[@]}" >"$TMP/default.yaml"
helm template transport "$CHART" "${BASE[@]}" --set ingress.enabled=true \
  --set ingress.host=vpn.example.com --set 'ingress.tls[0].secretName=tls' \
  --set 'edge.trustedIngressCIDRs[0]=192.0.2.10/32' \
  --set 'edge.trustedIngressCIDRs[1]=2001:db8::10/128' >"$TMP/trusted.yaml"
if helm template transport "$CHART" "${BASE[@]}" --set ingress.enabled=true \
  --set ingress.host=vpn.example.com --set 'ingress.tls[0].secretName=tls' >"$TMP/rejected" 2>&1; then
  echo 'TLS ingress silently accepted no trusted ingress peers' >&2; exit 1
fi
grep -Fq 'edge.trustedIngressCIDRs must list the ingress-controller peers' "$TMP/rejected"
if helm template transport "$CHART" "${BASE[@]}" --set 'edge.trustedIngressCIDRs[0]=0.0.0.0/0; injected' >"$TMP/rejected" 2>&1; then
  echo 'nginx configuration injection accepted as an ingress peer' >&2; exit 1
fi
ruby -ryaml -e '
  defaults, explicit = ARGV.map { |path| YAML.load_stream(File.read(path)).compact }
  [defaults, explicit].each do |docs|
    peer = docs.find { |d| d["kind"] == "Service" && d.dig("spec", "clusterIP") == "None" }
    abort "missing managed proxy peer identity" unless peer
    abort "peer readiness cycle" unless peer.dig("spec", "publishNotReadyAddresses") == true
    abort "peer selector expanded trust" unless peer.dig("spec", "selector") == {"app.kubernetes.io/instance" => "transport", "app.kubernetes.io/component" => "edge"}
    api = docs.find { |d| d["kind"] == "Deployment" && d.dig("metadata", "labels", "app.kubernetes.io/component") == "api" }
    env = api.dig("spec", "template", "spec", "containers").first.fetch("env")
    trust = env.find { |e| e["name"] == "TUNNEX_TRUSTED_PROXIES" }.fetch("value")
    abort "API trusts broader peers than edge pods" unless trust == "#{peer.dig("metadata", "name")}.transport-check.svc"
    edge = docs.find { |d| d["kind"] == "Deployment" && d.dig("metadata", "labels", "app.kubernetes.io/component") == "edge" }
    abort "edge config not mounted when AI disabled" unless edge.dig("spec", "template", "spec", "containers").first.fetch("volumeMounts").any? { |m| m["mountPath"] == "/etc/nginx/conf.d/default.conf" }
    config = docs.find { |d| d["kind"] == "ConfigMap" && d.fetch("data", {}).key?("default.conf") }.fetch("data").fetch("default.conf")
    ["geo $remote_addr $tunnex_ingress_trusted", "default 0;", "default $scheme;", "\"1:http\" http;", "\"1:https\" https;", "~^1: invalid;", "if ($tunnex_client_scheme = invalid) { return 400; }", "proxy_set_header X-Forwarded-Proto $tunnex_client_scheme;", "map $http_host $tunnex_client_authority", "proxy_set_header Host $tunnex_client_authority;", "proxy_set_header X-Forwarded-Host \"\";"].each { |part| abort "missing ingress trust boundary: #{part}" unless config.include?(part) }
    abort "wildcard trust introduced" if config.include?("0.0.0.0/0") || config.include?("::/0")
  end
  configs = [defaults, explicit].map { |docs| docs.find { |d| d["kind"] == "ConfigMap" && d.fetch("data", {}).key?("default.conf") }.dig("data", "default.conf") }
  abort "default trusts an ingress address" if configs[0].include?("192.0.2.10/32")
  abort "explicit IPv4 missing" unless configs[1].include?("192.0.2.10/32 1;")
  abort "explicit IPv6 missing" unless configs[1].include?("2001:db8::10/128 1;")
  checksums = [defaults, explicit].map { |docs| docs.find { |d| d["kind"] == "Deployment" && d.dig("metadata", "labels", "app.kubernetes.io/component") == "edge" }.dig("spec", "template", "metadata", "annotations", "checksum/edge") }
  abort "changed trust does not roll edge pods" if checksums[0] == checksums[1]
' "$TMP/default.yaml" "$TMP/trusted.yaml"
# Exercise nginx itself: a string-only assertion cannot prove map precedence or
# the forwarding behavior that decides whether HTTP may use the AI gateway.
helm template transport "$CHART" "${BASE[@]}" --set 'edge.trustedIngressCIDRs[0]=127.0.0.1/32' >"$TMP/loopback.yaml"
for fixture in default loopback docker; do
  ruby -ryaml -e '
    if ARGV[2] == "docker"
      conf = File.read(ARGV[3])
    else
      docs = YAML.load_stream(File.read(ARGV[0])).compact
      conf = docs.find { |d| d["kind"] == "ConfigMap" && d.fetch("data", {}).key?("default.conf") }.dig("data", "default.conf")
    end
    conf = conf.gsub("api:8080", "127.0.0.1:18081").gsub("web:8080", "127.0.0.1:18081")
    conf += %Q(\nserver { listen 18081; location = /api/authority { return 200 "$http_host|$http_x_forwarded_host"; } location / { return 200 "$http_x_forwarded_proto"; } }\n)
    File.write(ARGV[1], conf)
  ' "$TMP/$fixture.yaml" "$TMP/$fixture.conf" "$fixture" "$ROOT/deploy/nginx/nginx.conf"
  docker run --rm --network none --entrypoint sh \
    -v "$TMP/$fixture.conf:/etc/nginx/conf.d/default.conf:ro" \
    nginxinc/nginx-unprivileged:1.30.5-alpine@sha256:4714e0b1b2577eaa1a6131d07c958b67f0eb68e6d0521e90c6e5287db8cf0bc5 \
    -ec '
      nginx -t >/dev/null
      nginx
      i=0
      until wget -qO- --header="X-Forwarded-Proto: http" http://127.0.0.1:8080/healthz >/dev/null; do
        i=$((i+1)); [ "$i" -lt 20 ] || exit 1; sleep 0.1
      done
      scheme=$(wget -qO- --header="X-Forwarded-Proto: https" http://127.0.0.1:8080/api/check)
      if [ "$1" = default ]; then
        [ "$scheme" = http ] || { echo "untrusted client forged HTTPS" >&2; exit 1; }
      else
        [ "$scheme" = https ] || { echo "trusted ingress HTTPS was lost" >&2; exit 1; }
        if [ "$1" = loopback ] && wget -qO- --header="X-Forwarded-Proto: https,http" http://127.0.0.1:8080/api/check >/dev/null 2>&1; then
          echo "malformed trusted scheme was accepted" >&2; exit 1
        fi
      fi
      for authority in console.example.net console.example.net:9443 192.0.2.20:9443 "[2001:db8::1]:9443"; do
        forwarded=$(wget -qO- --header="Host: $authority" --header="X-Forwarded-Host: attacker.example" --header="X-Forwarded-Proto: https" http://127.0.0.1:8080/api/authority)
        [ "$forwarded" = "$authority|" ] || { echo "original authority lost or forwarded host trusted: $forwarded" >&2; exit 1; }
      done
      if wget -qO- --header="Host: console.example.net/invalid" --header="X-Forwarded-Proto: https" http://127.0.0.1:8080/api/authority >/dev/null 2>&1; then
        echo "nginx accepted an invalid Host authority" >&2; exit 1
      fi
    ' sh "$fixture"
done
echo 'trusted proxy chart contract: PASS'
