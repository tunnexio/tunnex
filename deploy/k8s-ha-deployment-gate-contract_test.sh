#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE="$ROOT/deploy/tunnex.yml"
CHART="$ROOT/deploy/helm/tunnex-cp"

grep -Fq 'TUNNEX_K8S_HA_ENABLED: ${TUNNEX_K8S_HA_ENABLED:-false}' "$COMPOSE" || {
  echo "compose must expose TUNNEX_K8S_HA_ENABLED with a false default" >&2
  exit 1
}
grep -Fq 'enabled: false' "$CHART/values.yaml" || {
  echo "Helm kubernetesHA.enabled must default false" >&2
  exit 1
}
grep -Fq 'value: {{ .Values.kubernetesHA.enabled | quote }}' "$CHART/templates/deployment-api.yaml" || {
  echo "Helm API deployment must wire kubernetesHA.enabled to the runtime env" >&2
  exit 1
}

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  compose_render() {
    POSTGRES_PASSWORD=test \
      APP_BASE_URL=https://tunnex.example.test \
      DATABASE_URL=postgres://db.example.test/tunnex \
      TUNNEX_NODE_ENDPOINT=gateway.example.test \
      TUNNEX_EDGE_LISTEN=https://tunnex.example.test \
      TUNNEX_K8S_HA_ENABLED="$1" \
      docker compose -f "$COMPOSE" config
  }

  default_compose=$(compose_render "")
  printf '%s\n' "$default_compose" | grep -Fq 'TUNNEX_K8S_HA_ENABLED: "false"' || {
    echo "default Compose render must set TUNNEX_K8S_HA_ENABLED=false" >&2
    exit 1
  }
  enabled_compose=$(compose_render true)
  printf '%s\n' "$enabled_compose" | grep -Fq 'TUNNEX_K8S_HA_ENABLED: "true"' || {
    echo "enabled Compose render must set TUNNEX_K8S_HA_ENABLED=true" >&2
    exit 1
  }
else
  if [ "${CI:-}" = "true" ]; then
    echo "FAIL: Docker Compose is required in CI; the semantic HA deployment render must not skip" >&2
    exit 1
  fi
  echo "SKIP: Docker Compose not installed or unusable; static Compose deployment-gate contract passed"
fi

if ! command -v helm >/dev/null 2>&1; then
  if [ "${CI:-}" = "true" ]; then
    echo "FAIL: helm is required in CI; the semantic HA deployment render must not skip" >&2
    exit 1
  fi
  echo "SKIP: helm not installed; static deployment-gate contract passed"
  exit 0
fi

render() {
  release=$1
  shift
  helm template "$release" "$CHART" \
    --set appBaseURL=https://tunnex.example.test \
    --set database.url=postgres://user:pass@postgres.example.test/tunnex \
    --set redis.url=redis://redis.example.test:6379/0 \
    --set masterKey.existingSecret=tunnex-master \
    "$@"
}

default_render=$(render ha-default)
printf '%s\n' "$default_render" | grep -A1 'name: TUNNEX_K8S_HA_ENABLED' | grep -Fq 'value: "false"' || {
  echo "default Helm render must set TUNNEX_K8S_HA_ENABLED=false" >&2
  exit 1
}

enabled_render=$(render ha-enabled --set kubernetesHA.enabled=true)
printf '%s\n' "$enabled_render" | grep -A1 'name: TUNNEX_K8S_HA_ENABLED' | grep -Fq 'value: "true"' || {
  echo "enabled Helm render must set TUNNEX_K8S_HA_ENABLED=true" >&2
  exit 1
}

echo "PASS: Kubernetes HA deployment gate defaults OFF and renders explicit opt-in"
