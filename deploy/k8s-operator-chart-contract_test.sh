#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHART="${ROOT}/deploy/helm/tunnex-operator"
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

VALUES=(
  --namespace tunnex-system
  --set controlPlane.url=https://cp.example.com
  --set controlPlane.organizationID=11111111-1111-1111-1111-111111111111
  --set machineToken.existingSecret=tunnex-operator-credential
  --set image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
)

helm lint "${CHART}" "${VALUES[@]}"
helm template op "${CHART}" "${VALUES[@]}" >"${TMP}/rendered.yaml"

require() {
  local pattern=$1 description=$2
  if ! grep -Eq -- "${pattern}" "${TMP}/rendered.yaml"; then
    echo "operator chart contract missing: ${description}" >&2
    exit 1
  fi
}

require '^kind: Deployment$' 'operator Deployment'
require '^kind: ClusterRole$' 'least-privilege ClusterRole'
require '^kind: ClusterRoleBinding$' 'ClusterRoleBinding'
require '^kind: ServiceAccount$' 'ServiceAccount'
require 'image: "ghcr.io/tunnexio/tunnex-operator@sha256:a{64}"' 'digest-pinned operator image'
require 'path: /healthz' 'health probe'
require 'path: /readyz' 'readiness probe'
require 'timeoutSeconds: 3' 'bounded control-plane readiness probe'
require 'secretKeyRef:' 'external machine credential Secret reference'
require 'name: "tunnex-operator-credential"' 'selected credential Secret'

# Tagged packaging must select the operator image carrying that same release
# version when no explicit digest/tag override is supplied.
helm package "${CHART}" --version 9.8.7 --app-version v9.8.7 --destination "${TMP}" >/dev/null
helm template op-version "${TMP}/tunnex-operator-9.8.7.tgz" \
  --namespace tunnex-system \
  --set controlPlane.url=https://cp.example.com \
  --set controlPlane.organizationID=11111111-1111-1111-1111-111111111111 \
  --set machineToken.existingSecret=tunnex-operator-credential >"${TMP}/version-matched.yaml"
grep -Eq 'image: "ghcr.io/tunnexio/tunnex-operator:v9\.8\.7"' "${TMP}/version-matched.yaml" || {
  echo 'operator chart appVersion must select the version-matched operator image' >&2
  exit 1
}

if grep -Eq '(^|[[:space:]])(stringData|data):[[:space:]]*$' "${TMP}/rendered.yaml"; then
  echo 'operator chart must not render credential Secret data' >&2
  exit 1
fi
if grep -Eq 'resources: \["\*"\]|verbs: \["\*"\]' "${TMP}/rendered.yaml"; then
  echo 'operator chart must not grant wildcard RBAC' >&2
  exit 1
fi

awk '
  /^kind: ClusterRole$/ { found = 1 }
  found && /^---$/ { exit }
  found { print }
' "${TMP}/rendered.yaml" >"${TMP}/cluster-role.yaml"
test "$(grep -c '^[[:space:]]*resources:' "${TMP}/cluster-role.yaml")" -eq 3
test "$(grep -c '^[[:space:]]*verbs:' "${TMP}/cluster-role.yaml")" -eq 3
require_role() {
  local pattern=$1 description=$2
  if ! grep -Eq -- "$pattern" "${TMP}/cluster-role.yaml"; then
    echo "operator ClusterRole contract missing exact ${description}" >&2
    exit 1
  fi
}
require_role 'resources: \["tunnexclusters", "tunnexexposedservices", "tunnexgrants"\]' 'CR read resources'
require_role 'verbs: \["get", "list", "watch", "patch", "update"\]' 'CR read/write verbs'
require_role 'resources: \["tunnexclusters/status", "tunnexexposedservices/status", "tunnexgrants/status"\]' 'status resources'
require_role 'verbs: \["get", "patch", "update"\]' 'status verbs'
require_role 'resources: \["events"\]' 'Event resource'
require_role 'verbs: \["create", "patch"\]' 'Event verbs'

test "$(grep -c '^kind: CustomResourceDefinition$' "${TMP}/rendered.yaml")" -eq 0 || {
  echo 'operator chart must not couple rollbackable workloads to the monotonic CRD lifecycle' >&2
  exit 1
}

if helm template op "${CHART}" >"${TMP}/missing.out" 2>&1; then
  echo 'operator chart must refuse missing control-plane and Secret references' >&2
  exit 1
fi
grep -Eq 'controlPlane.url|controlPlane/organizationID' "${TMP}/missing.out"

if helm template op "${CHART}" "${VALUES[@]}" --set machineToken.token=must-not-enter-helm >"${TMP}/raw.out" 2>&1; then
  echo 'operator chart schema must reject raw machine tokens' >&2
  exit 1
fi
grep -Eq "additional (properties 'token'|property token).*not allowed|Additional property token is not allowed" "${TMP}/raw.out"

if helm template op "${CHART}" "${VALUES[@]}" --set controlPlane.url=http://cp.example.com >"${TMP}/http.out" 2>&1; then
  echo 'operator chart must refuse an insecure control-plane URL' >&2
  exit 1
fi
grep -Eq 'controlPlane.url|controlPlane/url|https://' "${TMP}/http.out"

if helm template op "${CHART}" "${VALUES[@]}" --kube-version 1.28.9 >"${TMP}/old-kube.out" 2>&1; then
  echo 'operator chart must refuse Kubernetes versions below the supported CEL floor' >&2
  exit 1
fi
grep -Eq 'kubeVersion|Kubernetes' "${TMP}/old-kube.out"

if helm template op "${CHART}" "${VALUES[@]}" --set-string controlPlane.url=https:// >"${TMP}/hostless.out" 2>&1; then
  echo 'operator chart must refuse an HTTPS URL without a host' >&2
  exit 1
fi
grep -Eq 'controlPlane.url|pattern' "${TMP}/hostless.out"

if helm template op "${CHART}" "${VALUES[@]}" --set-string controlPlane.organizationID=not-a-uuid >"${TMP}/org.out" 2>&1; then
  echo 'operator chart must refuse a non-UUID organization ID' >&2
  exit 1
fi
grep -Eq 'controlPlane.organizationID|UUID|pattern' "${TMP}/org.out"

if helm template op "${CHART}" "${VALUES[@]}" --set 'imagePullSecrets[0]=raw-name' >"${TMP}/pull-secret.out" 2>&1; then
  echo 'operator chart schema must reject an invalid string imagePullSecret' >&2
  exit 1
fi
grep -Eq 'imagePullSecrets|want object|expected object|type.*object' "${TMP}/pull-secret.out"

echo 'k8s operator chart contract: PASS'
