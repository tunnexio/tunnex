#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHART="${ROOT}/deploy/helm/tunnex-host-posture"
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT
. "${ROOT}/deploy/helm-label-contract-lib.sh"

if ! command -v helm >/dev/null 2>&1; then
  echo 'FAIL: helm is required for the host-posture chart contract' >&2
  exit 1
fi

DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
BASE=(
  --namespace tunnex-system
  --set acknowledgePrivileged=true
  --set-string image.digest="${DIGEST}"
  --set-string rolloutRevision=contract-r1
)

require() {
  local file=$1 pattern=$2 description=$3
  if ! grep -Eq -- "${pattern}" "${file}"; then
    echo "host-posture chart contract missing: ${description}" >&2
    exit 1
  fi
}

reject() {
  local file=$1 pattern=$2 description=$3
  if grep -Eq -- "${pattern}" "${file}"; then
    echo "host-posture chart contract rendered forbidden ${description}" >&2
    exit 1
  fi
}

extract_source() {
  local source=$1 output=$2
  awk -v source="# Source: tunnex-host-posture/templates/${source}" '
    $0 == source { found = 1; next }
    found && /^---$/ { exit }
    found { print }
    END { if (!found) exit 2 }
  ' "${TMP}/rendered.yaml" >"${output}"
}

expect_fail() {
  local name=$1 expected=$2
  shift 2
  if helm template tunnex-host-posture "${CHART}" "$@" >"${TMP}/${name}.out" 2>&1; then
    echo "host-posture chart accepted invalid case: ${name}" >&2
    exit 1
  fi
  if ! grep -Eq -- "${expected}" "${TMP}/${name}.out"; then
    echo "host-posture chart rejected ${name}, but not for the expected reason" >&2
    sed -n '1,80p' "${TMP}/${name}.out" >&2
    exit 1
  fi
}

helm template tunnex-host-posture "${CHART}" "${BASE[@]}" >"${TMP}/rendered.yaml"

# A deliberately long prerelease remains a useful Kubernetes-label boundary
# fixture even though private walk candidates now use a bounded source prefix.
LONG_VERSION=0.0.0-walk.shaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
mkdir "${TMP}/long-version"
helm package "${CHART}" --version "${LONG_VERSION}" --app-version "${LONG_VERSION}" \
  --destination "${TMP}/long-version" >/dev/null
helm template tunnex-host-posture \
  "${TMP}/long-version/tunnex-host-posture-${LONG_VERSION}.tgz" "${BASE[@]}" \
  >"${TMP}/long-version.yaml"
assert_helm_chart_labels "${TMP}/long-version.yaml" \
  "$(helm_chart_label_expected tunnex-host-posture "${LONG_VERSION}")" \
  'host-posture long-version chart'

METADATA_VERSION=1.2.3+private.1
mkdir "${TMP}/metadata-version"
helm package "${CHART}" --version "${METADATA_VERSION}" --app-version "${METADATA_VERSION}" \
  --destination "${TMP}/metadata-version" >/dev/null
helm template tunnex-host-posture \
  "${TMP}/metadata-version/tunnex-host-posture-${METADATA_VERSION}.tgz" "${BASE[@]}" \
  >"${TMP}/metadata-version.yaml"
assert_helm_chart_labels "${TMP}/metadata-version.yaml" \
  "$(helm_chart_label_expected tunnex-host-posture "${METADATA_VERSION}")" \
  'host-posture build-metadata chart'
extract_source daemonset.yaml "${TMP}/daemonset.yaml"
extract_source serviceaccount.yaml "${TMP}/serviceaccount.yaml"
extract_source rbac.yaml "${TMP}/rbac-first.yaml"

require "${TMP}/rendered.yaml" '^kind: DaemonSet$' 'cluster-singleton DaemonSet'
require "${TMP}/rendered.yaml" '^  name: tunnex-host-posture$' 'fixed cluster-singleton name'
require "${TMP}/rendered.yaml" 'tunnex.io/host-posture-contract: "tunnex-host-posture/v1"' 'fixed manager contract annotation'
require "${TMP}/rendered.yaml" 'command: \["/usr/local/bin/tunnex-node", "k8s-host-posture-manager", "--run"\]' 'closed manager command'
require "${TMP}/rendered.yaml" 'image: "ghcr.io/tunnexio/tunnex-node-agent@sha256:a{64}"' 'digest-pinned node runtime'
require "${TMP}/rendered.yaml" 'privileged: true' 'per-node privileged manager'
test "$(grep -Ec '^[[:space:]]+privileged: true$' "${TMP}/rendered.yaml")" -eq 1 || {
  echo 'host-posture chart must render exactly one privileged container' >&2
  exit 1
}
require "${TMP}/rendered.yaml" 'hostNetwork: true' 'host network namespace ownership'
require "${TMP}/rendered.yaml" 'path: /var/lib/tunnex/host-posture/v1' 'versioned Tunnex host journal path'
require "${TMP}/rendered.yaml" 'path: /proc/sys' 'explicit host sysctl source mount'
require "${TMP}/rendered.yaml" 'mountPath: /host/proc/sys' 'closed host sysctl target mount'
require "${TMP}/rendered.yaml" 'type: DirectoryOrCreate' 'node-local journal directory creation'
require "${TMP}/rendered.yaml" 'fieldPath: spec.nodeName' 'exact manager node identity'
require "${TMP}/rendered.yaml" 'fieldPath: metadata.uid' 'exact manager Pod identity'
require "${TMP}/rendered.yaml" 'expirationSeconds: 3600' 'bounded projected API credential'
require "${TMP}/rendered.yaml" 'automountServiceAccountToken: false' 'pod-wide credential automount disabled'
require "${TMP}/rendered.yaml" 'resources: \["pods"\]' 'Pod-only API resource scope'
require "${TMP}/rendered.yaml" 'verbs: \["get", "list"\]' 'read-only owner readback verbs'
reject "${TMP}/rendered.yaml" 'resources: \["secrets"\]|verbs:.*(create|update|patch|delete|impersonate|escalate)' 'credential or mutation RBAC'
require "${TMP}/rendered.yaml" 'kubernetes.io/os: linux' 'provider-neutral all-Linux node selector'
awk '
  /^      tolerations:$/ { selected = 1; print; next }
  selected && /^      [A-Za-z]/ { exit }
  selected { print }
' "${TMP}/rendered.yaml" >"${TMP}/tolerations.yaml"
require "${TMP}/tolerations.yaml" 'operator: Exists' 'broad taint toleration for every Linux node'
test "$(grep -Ec '^[[:space:]]+- operator: Exists$' "${TMP}/tolerations.yaml")" -eq 1 || {
  echo 'host-posture normal path must render exactly one broad Exists toleration' >&2
  exit 1
}
reject "${TMP}/tolerations.yaml" '^[[:space:]]+(key|value|effect):' 'narrow default taint toleration'
require "${TMP}/rendered.yaml" 'maxUnavailable: 1' 'sequential per-node manager replacement'
require "${TMP}/rendered.yaml" 'maxSurge: 0' 'no overlapping privileged managers during rollout'
require "${TMP}/rendered.yaml" 'k8s-host-posture-check", "--ready"' 'real readiness heartbeat probe'
require "${TMP}/rendered.yaml" 'k8s-host-posture-check", "--live"' 'non-restarting blocked-state liveness probe'
test "$(grep -Fc 'command: ["/usr/local/bin/tunnex-node", "k8s-host-posture-check", "--ready"]' "${TMP}/daemonset.yaml")" -eq 2 || {
  echo 'host-posture manager must render exact startup and readiness heartbeat probes' >&2
  exit 1
}
test "$(grep -Fc 'command: ["/usr/local/bin/tunnex-node", "k8s-host-posture-check", "--live"]' "${TMP}/daemonset.yaml")" -eq 1 || {
  echo 'host-posture manager must render exactly one liveness heartbeat probe' >&2
  exit 1
}
test "$(grep -Ec '^[[:space:]]+timeoutSeconds: 2$' "${TMP}/daemonset.yaml")" -eq 3 || {
  echo 'host-posture manager probes must all use the fixed two-second timeout' >&2
  exit 1
}
require "${TMP}/daemonset.yaml" 'failureThreshold: 45' 'bounded startup heartbeat budget'
test "$(grep -Ec '^[[:space:]]+failureThreshold: 3$' "${TMP}/daemonset.yaml")" -eq 2 || {
  echo 'host-posture readiness and liveness failure thresholds must stay exact' >&2
  exit 1
}
reject "${TMP}/daemonset.yaml" 'httpGet:|tcpSocket:|grpc:' 'alternate manager health handler'

# The privileged manager has one fixed identity across the entire cluster. A
# second Helm release/name/namespace must be rejected before it can create a
# second DaemonSet that only contends on the host flock.
test "$(grep -Ec '^kind: DaemonSet$' "${TMP}/rendered.yaml")" -eq 1 || {
  echo 'host-posture chart must render exactly one DaemonSet' >&2
  exit 1
}
test "$(grep -Ec '^kind: ClusterRole$' "${TMP}/rendered.yaml")" -eq 1 || {
  echo 'host-posture chart must render exactly one ClusterRole' >&2
  exit 1
}
test "$(grep -Ec '^kind: ClusterRoleBinding$' "${TMP}/rendered.yaml")" -eq 1 || {
  echo 'host-posture chart must render exactly one ClusterRoleBinding' >&2
  exit 1
}
require "${TMP}/rendered.yaml" '^  name: tunnex-host-posture-gateway-owner-reader$' 'fixed singleton ClusterRole identity'
test "$(grep -Ec '^kind: ServiceAccount$' "${TMP}/rendered.yaml")" -eq 1 || {
  echo 'host-posture chart must render exactly one ServiceAccount' >&2
  exit 1
}
require "${TMP}/serviceaccount.yaml" '^  name: tunnex-host-posture$' 'fixed singleton ServiceAccount identity'
require "${TMP}/serviceaccount.yaml" '^automountServiceAccountToken: false$' 'ServiceAccount credential automount disabled'
require "${TMP}/rendered.yaml" '^  name: tunnex-host-posture-gateway-owner-reader$' 'fixed singleton RBAC identity'
require "${TMP}/rendered.yaml" '^  kind: ClusterRole$' 'ClusterRoleBinding fixed role kind'
require "${TMP}/rendered.yaml" '^    name: tunnex-host-posture$' 'ClusterRoleBinding fixed ServiceAccount subject'
require "${TMP}/rendered.yaml" '^    namespace: tunnex-system$' 'ClusterRoleBinding fixed ServiceAccount namespace'

if helm template another-host-posture "${CHART}" "${BASE[@]}" >"${TMP}/wrong-release.out" 2>&1; then
  echo 'host-posture chart accepted a second release name' >&2
  exit 1
fi
require "${TMP}/wrong-release.out" 'release name must be exactly tunnex-host-posture' 'second release-name refusal'

if helm template tunnex-host-posture "${CHART}" \
  --namespace another-system \
  --set acknowledgePrivileged=true \
  --set-string image.digest="${DIGEST}" >"${TMP}/wrong-namespace.out" 2>&1; then
  echo 'host-posture chart accepted a second release namespace' >&2
  exit 1
fi
require "${TMP}/wrong-namespace.out" 'release namespace must be exactly tunnex-system' 'second namespace refusal'

# Gateway releases may live in independent namespaces. They register their Pod
# UID against, and wait on, the same fixed node-local manager contract; neither
# gateway release renders another privileged host-posture manager.
GATEWAY_CHART="${ROOT}/deploy/helm/tunnex-gateway"
render_gateway() {
  local release=$1 namespace=$2 node_name=$3 output=$4
  helm template "${release}" "${GATEWAY_CHART}" \
    --namespace "${namespace}" \
    --set acknowledgePrivileged=true \
    --set controlPlane.apiURL=https://cp.example.test/api \
    --set controlPlane.agentURL=https://cp.example.test:8443 \
    --set-string image.digest="${DIGEST}" \
    --set enrollment.mode=enroll \
    --set enrollment.existingSecret=tunnex-join \
    --set nodeName="${node_name}" \
    --set rbac.create=false \
    --set serviceAccount.create=false \
    --set serviceAccount.name="${release}-gateway" >"${output}"
}
render_gateway gateway-a team-a gateway-a "${TMP}/gateway-a.yaml"
render_gateway gateway-b team-b gateway-b "${TMP}/gateway-b.yaml"
for gateway in "${TMP}/gateway-a.yaml" "${TMP}/gateway-b.yaml"; do
  require "${gateway}" 'tunnex.io/host-posture-contract: "tunnex-host-posture/v1"' 'shared singleton manager contract'
  require "${gateway}" 'path: /var/lib/tunnex/host-posture/v1' 'shared node-local manager journal'
  require "${gateway}" 'fieldPath: metadata.uid' 'live gateway Pod UID registration'
  require "${gateway}" 'k8s-host-posture-check", "--wait"' 'shared manager readiness admission'
  reject "${gateway}" '^kind: DaemonSet$|^kind: ClusterRole$|^kind: ClusterRoleBinding$' 'per-gateway manager singleton resources'
done

# The manager contract must remain cloud-neutral in both runtime and chart.
if grep -Eiq 'azure|amazon|aws|gcp|google|eks|aks|gke' "${CHART}/templates/daemonset.yaml" "${ROOT}/apps/node/internal/hostposture/"*.go; then
  echo 'host-posture runtime or chart contains provider-specific authority' >&2
  exit 1
fi

# A local source chart selects its own literal appVersion. This intentionally
# differs from release packaging below, which stamps the immutable vX.Y.Z image
# tag. Lifecycle planning must read chart metadata rather than synthesize a
# prefix from --chart-version.
helm template tunnex-host-posture "${CHART}" "${BASE[@]}" \
  --set-string image.digest= >"${TMP}/local-version.yaml"
require "${TMP}/local-version.yaml" 'image: "ghcr.io/tunnexio/tunnex-node-agent:0\.2\.0"' 'literal local chart appVersion runtime'

helm package "${CHART}" --version 9.8.7 --app-version v9.8.7 --destination "${TMP}" >/dev/null
mkdir "${TMP}/repeat"
helm package "${CHART}" --version 9.8.7 --app-version v9.8.7 --destination "${TMP}/repeat" >/dev/null
cmp -s "${TMP}/tunnex-host-posture-9.8.7.tgz" "${TMP}/repeat/tunnex-host-posture-9.8.7.tgz" || {
  echo 'host-posture chart packaging is not byte-identical across repeated builds' >&2
  exit 1
}
helm template tunnex-host-posture "${TMP}/tunnex-host-posture-9.8.7.tgz" "${BASE[@]}" \
  --set-string image.digest= >"${TMP}/version.yaml"
require "${TMP}/version.yaml" 'image: "ghcr.io/tunnexio/tunnex-node-agent:v9\.8\.7"' 'version-matched released runtime'

expect_fail acknowledgement 'acknowledgePrivileged' \
  --namespace tunnex-system --set acknowledgePrivileged=false
expect_fail max-owners 'maxOwners' "${BASE[@]}" --set maxOwners=33
expect_fail digest 'image.digest' "${BASE[@]}" --set-string image.digest=sha256:bad
expect_fail unknown 'additional properties.*unexpected' "${BASE[@]}" --set unexpected=true
expect_fail singleton-name-override 'additional properties.*fullnameOverride' \
  "${BASE[@]}" --set fullnameOverride=second-manager
expect_fail invalid-toleration 'additional properties.*cloudProvider' \
  "${BASE[@]}" --set-string 'tolerations[0].cloudProvider=aks'
expect_fail restricted-node-selector 'nodeSelector/kubernetes.io.*value must be.*linux' \
  "${BASE[@]}" --set-string 'nodeSelector.kubernetes\.io/os=windows'
expect_fail restricted-toleration 'tolerations.*additional properties.*key|tolerations.*key.*not allowed' \
  "${BASE[@]}" --set-string 'tolerations[0].key=dedicated'
expect_fail restricted-affinity 'affinity.*maxProperties: got 1, want 0' \
  "${BASE[@]}" --set-string 'affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=kubernetes.io/hostname' \
  --set-string 'affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=Exists'
expect_fail external-service-account 'serviceAccount.create.*value must be true' \
  "${BASE[@]}" --set serviceAccount.create=false --set-string serviceAccount.name=external-manager
expect_fail renamed-service-account 'serviceAccount.name.*value must be' \
  "${BASE[@]}" --set-string serviceAccount.name=renamed-manager
expect_fail external-rbac 'rbac.create.*value must be true' \
  "${BASE[@]}" --set rbac.create=false

echo 'kubernetes host-posture chart contract: PASS'
