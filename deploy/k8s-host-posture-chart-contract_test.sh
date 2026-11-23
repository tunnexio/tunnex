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
  if ! grep -Eiq -- "${expected}" "${TMP}/${name}.out"; then
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
test "$(grep -Fc 'path: /proc/sys' "${TMP}/daemonset.yaml")" -eq 1 || {
  echo 'host-posture manager must render exactly one host /proc/sys source' >&2
  exit 1
}
test "$(grep -Fc 'mountPath: /host/proc/sys' "${TMP}/daemonset.yaml")" -eq 1 || {
  echo 'host-posture manager must render exactly one writable host /proc/sys mount' >&2
  exit 1
}
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
# K8N-1, "Hardening after the live install": each probe starts the whole binary,
# and a 2 s timeout restarted the manager on a busy node. The exact numbers are
# also what `tunnex k8s install` verifies (hostPostureCurrentProbes).
probe_block() {
  awk -v probe="$1" '
    $0 ~ "^          " probe ":$" { selected = 1; next }
    selected && /^          [A-Za-z]/ { exit }
    selected { print }
  ' "${TMP}/daemonset.yaml" | sed -E 's/^[[:space:]]+//' | grep -Ev '^(exec:|command:)' | tr '\n' ' '
}
test "$(probe_block startupProbe)" = 'periodSeconds: 2 timeoutSeconds: 5 failureThreshold: 45 ' || {
  echo "host-posture startup probe must be period 2 s, timeout 5 s, 45 failures; got: $(probe_block startupProbe)" >&2
  exit 1
}
test "$(probe_block readinessProbe)" = 'periodSeconds: 5 timeoutSeconds: 5 failureThreshold: 3 ' || {
  echo "host-posture readiness probe must be period 5 s, timeout 5 s, 3 failures; got: $(probe_block readinessProbe)" >&2
  exit 1
}
test "$(probe_block livenessProbe)" = 'periodSeconds: 10 timeoutSeconds: 5 failureThreshold: 6 ' || {
  echo "host-posture liveness probe must be period 10 s, timeout 5 s, 6 failures; got: $(probe_block livenessProbe)" >&2
  exit 1
}
reject "${TMP}/daemonset.yaml" 'initialDelaySeconds:|successThreshold:' 'probe field outside the fixed health contract'
reject "${TMP}/daemonset.yaml" 'httpGet:|tcpSocket:|grpc:' 'alternate manager health handler'

# Requests follow the measured use (K8N-1, "Hardening after the live install");
# the memory limit is unchanged and there is no CPU limit.
resources_block() {
  awk '
    /^          resources:$/ { selected = 1; next }
    selected && /^      [A-Za-z]/ { exit }
    selected { print }
  ' "$1" | sed -E 's/^[[:space:]]+//' | tr '\n' ' '
}
test "$(resources_block "${TMP}/daemonset.yaml")" = 'limits: memory: 128Mi requests: cpu: 40m memory: 48Mi ' || {
  echo "host-posture default resources are not the measured contract; got: $(resources_block "${TMP}/daemonset.yaml")" >&2
  exit 1
}

# K8N-2: the two Cilium host paths. Off by default, so a cluster without Cilium
# gets exactly the mounts it had. With cilium.enabled=true the DaemonSet gains
# exactly two hostPath volumes, both mounted read-only, and its requests become
# the ones measured with bpftool running. Nothing else in the rendered release
# changes: no capability, no environment, no RBAC, no limit.
reject "${TMP}/rendered.yaml" '[Cc]ilium|/sys/fs/bpf' 'Cilium host path or name without cilium.enabled'
test "$(grep -Ec '^[[:space:]]+hostPath:$' "${TMP}/daemonset.yaml")" -eq 2 || {
  echo 'host-posture manager must render exactly two hostPath volumes by default' >&2
  exit 1
}
helm template tunnex-host-posture "${CHART}" "${BASE[@]}" --set cilium.enabled=false >"${TMP}/cilium-off.yaml"
cmp -s "${TMP}/rendered.yaml" "${TMP}/cilium-off.yaml" || {
  echo 'cilium.enabled=false must render exactly the default release' >&2
  exit 1
}
helm template tunnex-host-posture "${CHART}" "${BASE[@]}" --set cilium.enabled=true >"${TMP}/cilium-on-raw.yaml"
test "$(resources_block "${TMP}/cilium-on-raw.yaml")" = 'limits: memory: 128Mi requests: cpu: 50m memory: 96Mi ' || {
  echo "host-posture Cilium resources are not the measured contract; got: $(resources_block "${TMP}/cilium-on-raw.yaml")" >&2
  exit 1
}
# The two request lines are the only lines allowed to differ; they were checked
# exactly above, so exactly those two are taken out of each side. The limit
# stays in the comparison.
strip_requests() {
  local file=$1 cpu=$2 memory=$3
  test "$(grep -Ec "^              (cpu: ${cpu}|memory: ${memory})\$" "${file}")" -eq 2 || {
    echo "host-posture manager must render exactly one ${cpu} CPU request and one ${memory} memory request in ${file##*/}" >&2
    exit 1
  }
  grep -Ev "^              (cpu: ${cpu}|memory: ${memory})\$" "${file}"
}
strip_requests "${TMP}/rendered.yaml" 40m 48Mi >"${TMP}/rendered-no-requests.yaml"
strip_requests "${TMP}/cilium-on-raw.yaml" 50m 96Mi >"${TMP}/cilium-on.yaml"
reject "${TMP}/cilium-on-raw.yaml" '^[[:space:]]+cpu: (40m)$|^[[:space:]]+memory: (48Mi)$' 'default request on a Cilium cluster'
if diff "${TMP}/rendered-no-requests.yaml" "${TMP}/cilium-on.yaml" | grep -E '^<' >"${TMP}/cilium-removed.txt"; then
  echo 'cilium.enabled=true removed or changed a line of the default release:' >&2
  cat "${TMP}/cilium-removed.txt" >&2
  exit 1
fi
diff "${TMP}/rendered-no-requests.yaml" "${TMP}/cilium-on.yaml" | sed -n 's/^> //p' | grep -Ev '^[[:space:]]*#' >"${TMP}/cilium-added.txt" || true
cat >"${TMP}/cilium-expected.txt" <<'CILIUM'
            - name: cilium-run
              mountPath: /var/run/cilium
              readOnly: true
            - name: host-bpf
              mountPath: /sys/fs/bpf
              readOnly: true
              mountPropagation: HostToContainer
        - name: cilium-run
          hostPath:
            path: /var/run/cilium
            type: Directory
        - name: host-bpf
          hostPath:
            path: /sys/fs/bpf
            type: Directory
CILIUM
# `type: Directory` already ends a default volume, so which of two identical
# lines counts as "added" is the diff tool's choice: GNU diff and the BSD diff
# of macOS choose differently. Compare the added lines as a set of lines, and
# prove the order of each mount and volume separately below.
LC_ALL=C sort "${TMP}/cilium-added.txt" >"${TMP}/cilium-added-sorted.txt"
LC_ALL=C sort "${TMP}/cilium-expected.txt" >"${TMP}/cilium-expected-sorted.txt"
cmp -s "${TMP}/cilium-added-sorted.txt" "${TMP}/cilium-expected-sorted.txt" || {
  echo 'cilium.enabled=true must add exactly the two read-only Cilium host paths:' >&2
  diff "${TMP}/cilium-expected-sorted.txt" "${TMP}/cilium-added-sorted.txt" >&2 || true
  exit 1
}
cilium_entry() {
  grep -A "$2" -- "^$1\$" "${TMP}/cilium-on.yaml" | grep -Ev '^[[:space:]]*#' | sed -E 's/^[[:space:]]+//' | tr '\n' ' '
}
test "$(cilium_entry '            - name: cilium-run' 2)" = '- name: cilium-run mountPath: /var/run/cilium readOnly: true ' &&
  test "$(cilium_entry '            - name: host-bpf' 5)" = '- name: host-bpf mountPath: /sys/fs/bpf readOnly: true mountPropagation: HostToContainer ' &&
  test "$(cilium_entry '        - name: cilium-run' 3)" = '- name: cilium-run hostPath: path: /var/run/cilium type: Directory ' &&
  test "$(cilium_entry '        - name: host-bpf' 3)" = '- name: host-bpf hostPath: path: /sys/fs/bpf type: Directory ' || {
  echo 'each Cilium host path must be an existing host Directory mounted read-only at its own path' >&2
  exit 1
}
test "$(grep -Ec '^[[:space:]]+privileged: true$' "${TMP}/cilium-on.yaml")" -eq 1 || {
  echo 'cilium.enabled=true must not render another privileged container' >&2
  exit 1
}
reject "${TMP}/cilium-on.yaml" 'mountPropagation: Bidirectional' 'mount that propagates from the manager to the host'
expect_fail cilium-not-boolean 'cilium.*enabled.*(boolean|got string)' "${BASE[@]}" --set-string cilium.enabled=yes
expect_fail cilium-resources-not-object 'cilium.*resources.*(object|got string)' "${BASE[@]}" --set-string cilium.resources=none
# An operator who finds heartbeat.json and no host-facts.json on a node without
# a gateway must be told, where they look, that this is normal.
require "${CHART}/templates/NOTES.txt" 'heartbeat\.json \(state "idle"\) and no host-facts\.json' 'idle-manager sentence in the install notes'
expect_fail cilium-unknown-key 'additional propert(y|ies).*socket' "${BASE[@]}" --set-string cilium.socket=/run/other.sock

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
  # K8N-2: only the manager reads Cilium. The gateway gets no path to the
  # agent socket or to the pinned maps; it decides on the manager's receipt.
  reject "${gateway}" 'path: /var/run/cilium|path: /sys/fs/bpf|mountPath: /sys/fs/bpf|cilium\.sock' 'Cilium host path in a gateway'
done

# The manager contract remains mechanism-based. A literal observed chain or
# closed receipt scope may name AWS; that is not a provider SDK/identity grant.
# Keep provider placement/config out of the chart, and reject actual cloud
# authority inputs/dependencies in the runtime instead of banning prose/names.
if grep -Eiq 'azure|amazon|aws|gcp|google|eks|aks|gke' "${CHART}/templates/daemonset.yaml"; then
  echo 'host-posture chart contains provider-specific authority or placement' >&2
  exit 1
fi
for posture_source in "${ROOT}/apps/node/internal/hostposture/"*.go; do
  [[ "${posture_source}" == *_test.go ]] && continue
  if grep -En 'github\.com/(aws/|Azure/|azure/)|cloud\.google\.com/go|google\.golang\.org/api|AWS_(REGION|ACCESS_KEY|SECRET_ACCESS_KEY|ROLE_ARN)|AZURE_(CLIENT|TENANT|SUBSCRIPTION)|GOOGLE_APPLICATION_CREDENTIALS|169\.254\.169\.254|metadata\.google\.internal' "${posture_source}"; then
    echo 'host-posture runtime contains cloud SDK, credential, or metadata authority' >&2
    exit 1
  fi
done

# A local source chart selects its own literal appVersion. This intentionally
# differs from release packaging below, which stamps the immutable vX.Y.Z image
# tag. Lifecycle planning must read chart metadata rather than synthesize a
# prefix from --chart-version.
helm template tunnex-host-posture "${CHART}" "${BASE[@]}" \
  --set-string image.digest= >"${TMP}/local-version.yaml"
require "${TMP}/local-version.yaml" 'image: "ghcr.io/tunnexio/tunnex-node-agent:0\.2\.0"' 'literal local chart appVersion runtime'

bash "${ROOT}/deploy/helm-package-reproducible.sh" "${CHART}" 9.8.7 v9.8.7 "${TMP}"
mkdir "${TMP}/repeat"
bash "${ROOT}/deploy/helm-package-reproducible.sh" "${CHART}" 9.8.7 v9.8.7 "${TMP}/repeat"
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
expect_fail unknown 'additional propert(y|ies).*unexpected' "${BASE[@]}" --set unexpected=true
expect_fail singleton-name-override 'additional propert(y|ies).*fullnameOverride' \
  "${BASE[@]}" --set fullnameOverride=second-manager
expect_fail invalid-toleration 'additional propert(y|ies).*cloudProvider' \
  "${BASE[@]}" --set-string 'tolerations[0].cloudProvider=aks'
expect_fail restricted-node-selector 'nodeSelector[/.]kubernetes.io.*(value must be|does not match).*linux' \
  "${BASE[@]}" --set-string 'nodeSelector.kubernetes\.io/os=windows'
expect_fail restricted-toleration 'tolerations.*additional propert(y|ies).*key|tolerations.*key.*not allowed' \
  "${BASE[@]}" --set-string 'tolerations[0].key=dedicated'
expect_fail restricted-affinity 'affinity.*(maxProperties: got 1, want 0|must have at most 0 properties)' \
  "${BASE[@]}" --set-string 'affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=kubernetes.io/hostname' \
  --set-string 'affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=Exists'
expect_fail external-service-account 'serviceAccount.create.*(value must be true|does not match: true)' \
  "${BASE[@]}" --set serviceAccount.create=false --set-string serviceAccount.name=external-manager
expect_fail renamed-service-account 'serviceAccount.name.*(value must be|does not match:)' \
  "${BASE[@]}" --set-string serviceAccount.name=renamed-manager
expect_fail external-rbac 'rbac.create.*(value must be true|does not match: true)' \
  "${BASE[@]}" --set rbac.create=false

echo 'kubernetes host-posture chart contract: PASS'
