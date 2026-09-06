#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHART="${ROOT}/deploy/helm/tunnex-gateway"
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT
. "${ROOT}/deploy/helm-label-contract-lib.sh"

if ! command -v helm >/dev/null 2>&1; then
  echo 'FAIL: helm is required for the gateway chart contract' >&2
  exit 1
fi

DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ORG_ID=11111111-1111-4111-8111-111111111111
LIFECYCLE_CLAIM=22222222-2222-4222-8222-222222222222
INSTALL_PROOF=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
BASE=(
  --namespace tunnex-system
  --set acknowledgePrivileged=true
  --set controlPlane.apiURL=https://cp.example.test/api
  --set controlPlane.agentURL=https://cp.example.test:8443
  --set-string image.digest="${DIGEST}"
  --set-string rolloutRevision=contract-r1
  --set-string nodeSelector.lifecycle-test=exact-node
  --set-string 'tolerations[0].key=lifecycle-test'
  --set-string 'tolerations[0].operator=Equal'
  --set-string 'tolerations[0].value=exact-node'
  --set-string 'tolerations[0].effect=NoSchedule'
)
ENROLL=(
  "${BASE[@]}"
  --set enrollment.mode=enroll
  --set nodeName=aks-gw-a
  --set enrollment.existingSecret=tunnex-join
  --set-string persistence.provenance.organizationID="${ORG_ID}"
  --set-string persistence.provenance.lifecycleClaim="${LIFECYCLE_CLAIM}"
)

require() {
  local file=$1 pattern=$2 description=$3
  if ! grep -Eq -- "${pattern}" "${file}"; then
    echo "gateway chart contract missing: ${description}" >&2
    exit 1
  fi
}

reject() {
  local file=$1 pattern=$2 description=$3
  if grep -Eq -- "${pattern}" "${file}"; then
    echo "gateway chart contract leaked/rendered forbidden ${description}" >&2
    exit 1
  fi
}

extract_source() {
  local input=$1 source=$2 output=$3
  awk -v source="# Source: tunnex-gateway/templates/${source}" '
    $0 == source { found = 1; next }
    found && /^---$/ { exit }
    found { print }
    END { if (!found) exit 2 }
  ' "${input}" >"${output}"
}

expect_fail() {
  local name=$1 expected=$2
  shift 2
  if helm template "negative-${name}" "${CHART}" "$@" >"${TMP}/${name}.out" 2>&1; then
    echo "gateway chart contract accepted invalid case: ${name}" >&2
    exit 1
  fi
  # Helm's schema libraries spell identical numeric string constraints
  # differently. Keep the field-specific refusal checks below, normalizing
  # only these two equivalent diagnostics from pinned Helm 3.18.4.
  sed -e 's/String length must be greater than or equal to /length must be >= /g' \
    -e 's/String length must be less than or equal to /length must be <= /g' \
    "${TMP}/${name}.out" >"${TMP}/${name}.normalized"
  if ! grep -Eiq -- "${expected}" "${TMP}/${name}.normalized"; then
    echo "gateway chart contract rejected ${name}, but not for the expected reason" >&2
    sed -n '1,80p' "${TMP}/${name}.out" >&2
    exit 1
  fi
}

# Canonical enrollment: the one-time token body must stay entirely outside Helm.
helm lint "${CHART}" "${ENROLL[@]}"
helm template gw-a "${CHART}" "${ENROLL[@]}" >"${TMP}/enroll.yaml"

# A deliberately long prerelease remains a useful Kubernetes-label boundary
# fixture after the chart name is added.
LONG_VERSION=0.0.0-walk.shaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
mkdir "${TMP}/long-version"
helm package "${CHART}" --version "${LONG_VERSION}" --app-version "${LONG_VERSION}" \
  --destination "${TMP}/long-version" >/dev/null
helm template gw-long "${TMP}/long-version/tunnex-gateway-${LONG_VERSION}.tgz" \
  "${ENROLL[@]}" >"${TMP}/long-version.yaml"
assert_helm_chart_labels "${TMP}/long-version.yaml" \
  "$(helm_chart_label_expected tunnex-gateway "${LONG_VERSION}")" \
  'gateway long-version chart'

METADATA_VERSION=1.2.3+private.1
mkdir "${TMP}/metadata-version"
helm package "${CHART}" --version "${METADATA_VERSION}" --app-version "${METADATA_VERSION}" \
  --destination "${TMP}/metadata-version" >/dev/null
helm template gw-metadata "${TMP}/metadata-version/tunnex-gateway-${METADATA_VERSION}.tgz" \
  "${ENROLL[@]}" >"${TMP}/metadata-version.yaml"
assert_helm_chart_labels "${TMP}/metadata-version.yaml" \
  "$(helm_chart_label_expected tunnex-gateway "${METADATA_VERSION}")" \
  'gateway build-metadata chart'
extract_source "${TMP}/enroll.yaml" deployment.yaml "${TMP}/deployment.yaml"
extract_source "${TMP}/enroll.yaml" job-preflight.yaml "${TMP}/preflight.yaml"
extract_source "${TMP}/enroll.yaml" pvc.yaml "${TMP}/pvc.yaml"

require "${TMP}/deployment.yaml" '^kind: Deployment$' 'gateway Deployment'
require "${TMP}/preflight.yaml" '^kind: Job$' 'pre-install/pre-upgrade placement preflight'
require "${TMP}/preflight.yaml" '^  name: gw-a-tunnex-gateway-preflight$' 'canonical failed preflight hook name'
require "${TMP}/preflight.yaml" 'app.kubernetes.io/name: tunnex-gateway' 'failed preflight hook product label'
require "${TMP}/preflight.yaml" 'app.kubernetes.io/instance: gw-a' 'failed preflight hook release label'
require "${TMP}/preflight.yaml" 'app.kubernetes.io/component: preflight' 'failed preflight hook component label'
require "${TMP}/preflight.yaml" 'app.kubernetes.io/managed-by: Helm' 'failed preflight hook manager label'
require "${TMP}/preflight.yaml" '"helm.sh/hook": pre-install,pre-upgrade' 'failed preflight hook lifecycle annotation'
require "${TMP}/preflight.yaml" '"helm.sh/hook-weight": "-5"' 'failed preflight hook weight'
require "${TMP}/preflight.yaml" '"helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded,hook-failed' 'failed preflight hook cleanup'
reject "${TMP}/preflight.yaml" 'tunnex.io/lifecycle-install-proof' 'proof-bearing recovery on a direct/manual Helm render'
helm template gw-proof "${CHART}" "${ENROLL[@]}" \
  --set-string lifecycle.installProof="${INSTALL_PROOF}" >"${TMP}/proof.yaml"
extract_source "${TMP}/proof.yaml" job-preflight.yaml "${TMP}/proof-preflight.yaml"
require "${TMP}/proof-preflight.yaml" "\"tunnex.io/lifecycle-install-proof\": \"${INSTALL_PROOF}\"" 'exact zero-touch lifecycle install proof'
# Helm rollback renders the target revision as an upgrade. Revision 1 retains
# its enrollment values, so that phase must not replay the old holder proof.
helm template gw-rollback "${CHART}" "${ENROLL[@]}" --is-upgrade \
  --set-string lifecycle.installProof="${INSTALL_PROOF}" >"${TMP}/rollback.yaml"
extract_source "${TMP}/rollback.yaml" job-preflight.yaml "${TMP}/rollback-preflight.yaml"
reject "${TMP}/rollback-preflight.yaml" 'tunnex.io/lifecycle-install-proof' 'rollback replay of an enrollment-only lifecycle install proof'
require "${TMP}/deployment.yaml" 'tunnex.io/rollout-revision: "contract-r1"' 'non-secret rollout revision'
require "${TMP}/deployment.yaml" 'image: ghcr.io/tunnexio/tunnex-node-agent@sha256:a{64}' 'digest-pinned gateway and posture-check images'
require "${ROOT}/deploy/docker/node.Dockerfile" 'ARG VERSION=dev' 'node image build-version input'
require "${ROOT}/deploy/docker/node.Dockerfile" '\-X main\.buildVersion=\$\{VERSION\}' 'node binary build provenance stamp'
require "${TMP}/deployment.yaml" 'tunnex.io/zero-touch-contract: "tunnex-zero-touch/v1"' 'fixed live lifecycle provenance annotation'
require "${TMP}/deployment.yaml" 'tunnex.io/host-posture-contract: "tunnex-host-posture/v1"' 'fixed shared manager contract annotation'
require "${TMP}/deployment.yaml" 'tunnex.io/host-posture-service-account: "gw-a-tunnex-gateway"' 'exact gateway ServiceAccount authority annotation'
require "${TMP}/deployment.yaml" 'tunnex.io/host-posture-owner: "true"' 'live Pod UID owner selector label'
require "${TMP}/deployment.yaml" 'command: \["/usr/local/bin/tunnex-node", "k8s-host-posture-check", "--wait"\]' 'fixed credentialless manager admission command'
test "$(grep -Ec '^[[:space:]]+privileged: true$' "${TMP}/deployment.yaml")" -eq 0 || {
  echo 'gateway Deployment must contain no privileged container; privilege belongs to the shared manager' >&2
  exit 1
}
reject "${TMP}/deployment.yaml" 'path: /proc/sys|mountPath: /host/proc/sys|name: TUNNEX_HOST_POSTURE_PROC_SYS' 'host sysctl write surface in gateway Deployment'
test "$(grep -Ec '^[[:space:]]+hostPath:$' "${TMP}/deployment.yaml")" -eq 2 || {
  echo 'gateway Deployment hostPath sources must be exactly the posture state directory and /dev/net/tun' >&2
  exit 1
}
test "$(grep -Ec '^[[:space:]]+path: /var/lib/tunnex/host-posture/v1$' "${TMP}/deployment.yaml")" -eq 1 || {
  echo 'gateway Deployment must mount exactly one allowed host-posture state hostPath' >&2
  exit 1
}
test "$(grep -Ec '^[[:space:]]+path: /dev/net/tun$' "${TMP}/deployment.yaml")" -eq 1 || {
  echo 'gateway Deployment must mount exactly one allowed /dev/net/tun hostPath' >&2
  exit 1
}
require "${TMP}/deployment.yaml" 'automountServiceAccountToken: false' 'pod-wide service-account token automount disabled'
require "${TMP}/deployment.yaml" 'name: health' 'health port'
require "${TMP}/deployment.yaml" 'containerPort: 9091' 'health server port 9091'
require "${TMP}/deployment.yaml" 'startupProbe:' 'startup probe'
require "${TMP}/deployment.yaml" 'readinessProbe:' 'readiness probe'
require "${TMP}/deployment.yaml" 'livenessProbe:' 'liveness probe'
require "${TMP}/deployment.yaml" 'path: /readyz' 'real readiness endpoint'
require "${TMP}/deployment.yaml" 'path: /healthz' 'real health endpoint'
require "${TMP}/deployment.yaml" 'name: TUNNEX_NODE_NAME' 'enrollment node-name pin'
require "${TMP}/deployment.yaml" 'value: "aks-gw-a"' 'selected enrollment node name'
require "${TMP}/deployment.yaml" 'name: TUNNEX_JOIN_TOKEN' 'external one-time token reference'
require "${TMP}/deployment.yaml" 'name: tunnex-join' 'selected external one-time token Secret'
require "${TMP}/deployment.yaml" 'optional: true' 'consumed bootstrap Secret may be deleted'
require "${TMP}/deployment.yaml" 'name: TUNNEX_K8S_MODE' 'closed Kubernetes gateway mode'
require "${TMP}/deployment.yaml" 'value: "true"' 'enabled Kubernetes gateway mode'
require "${TMP}/deployment.yaml" 'name: TUNNEX_K8S_ENDPOINT_SERVICE' 'automatic LoadBalancer Service discovery'
require "${TMP}/deployment.yaml" 'value: "gw-a-tunnex-gateway-wg"' 'release-scoped LoadBalancer Service name'
require "${TMP}/deployment.yaml" 'name: TUNNEX_K8S_ENDPOINT_NAMESPACE' 'automatic Service namespace discovery'
require "${TMP}/deployment.yaml" 'name: TUNNEX_K8S_ENDPOINT_PORT' 'automatic numeric WireGuard Service port'
require "${TMP}/deployment.yaml" 'value: "51820"' 'automatic WireGuard Service port value'
reject "${TMP}/deployment.yaml" 'name: TUNNEX_NODE_ENDPOINT' 'explicit endpoint in automatic discovery mode'
require "${TMP}/pvc.yaml" '^kind: PersistentVolumeClaim$' 'fresh identity PVC'
require "${TMP}/pvc.yaml" '"helm.sh/resource-policy": keep' 'retain-by-default identity PVC policy'
require "${TMP}/pvc.yaml" 'app.kubernetes.io/managed-by: Helm' 'exact Helm manager ownership label'
require "${TMP}/pvc.yaml" 'meta.helm.sh/release-name: "gw-a"' 'exact Helm release ownership annotation'
require "${TMP}/pvc.yaml" 'meta.helm.sh/release-namespace: "tunnex-system"' 'exact Helm namespace ownership annotation'
require "${TMP}/pvc.yaml" "tunnex.io/organization-id: \"${ORG_ID}\"" 'token-blind organization provenance'
require "${TMP}/pvc.yaml" "tunnex.io/lifecycle-claim: \"${LIFECYCLE_CLAIM}\"" 'token-blind lifecycle-claim provenance'
reject "${TMP}/enroll.yaml" '^kind: Secret$' 'Secret manifest for canonical external-Secret enrollment'

# A local source chart selects its literal appVersion. Release packaging below
# deliberately stamps a v-prefixed image tag, so lifecycle planning must read
# chart metadata rather than derive the runtime tag from --chart-version.
helm template gw-local-version "${CHART}" "${ENROLL[@]}" \
  --set-string image.digest= >"${TMP}/local-version.yaml"
extract_source "${TMP}/local-version.yaml" deployment.yaml "${TMP}/local-version-deployment.yaml"
extract_source "${TMP}/local-version.yaml" job-preflight.yaml "${TMP}/local-version-preflight.yaml"
require "${TMP}/local-version-deployment.yaml" 'image: ghcr.io/tunnexio/tunnex-node-agent:0\.2\.0' 'literal local chart appVersion gateway and posture-check images'
require "${TMP}/local-version-preflight.yaml" 'image: "ghcr.io/tunnexio/tunnex-node-agent:0\.2\.0"' 'literal local chart appVersion preflight image'

# A released chart selects the version-matched immutable release tag by
# default. A mutable control-plane hint must not be needed for this path.
helm package "${CHART}" --version 9.8.7 --app-version v9.8.7 --destination "${TMP}" >/dev/null
helm template gw-version "${TMP}/tunnex-gateway-9.8.7.tgz" "${ENROLL[@]}" \
  --set-string image.digest= >"${TMP}/version-matched.yaml"
extract_source "${TMP}/version-matched.yaml" deployment.yaml "${TMP}/version-matched-deployment.yaml"
extract_source "${TMP}/version-matched.yaml" job-preflight.yaml "${TMP}/version-matched-preflight.yaml"
require "${TMP}/version-matched-deployment.yaml" 'image: ghcr.io/tunnexio/tunnex-node-agent:v9\.8\.7' 'chart appVersion-matched gateway and posture-check images'
require "${TMP}/version-matched-preflight.yaml" 'image: "ghcr.io/tunnexio/tunnex-node-agent:v9\.8\.7"' 'chart appVersion-matched privileged preflight image'
test "$(grep -Fc 'image: ghcr.io/tunnexio/tunnex-node-agent:v9.8.7' "${TMP}/version-matched-deployment.yaml")" -eq 2 || {
  echo 'version-matched image must be shared by posture admission and the gateway' >&2
  exit 1
}

# The host-posture init reads only the non-secret node-local heartbeat; it never
# receives host mutation privilege, identity, join, or Kubernetes credentials.
awk '
  /^[[:space:]]+initContainers:$/ { in_init = 1 }
  in_init && /^[[:space:]]+containers:$/ { exit }
  in_init { print }
' "${TMP}/deployment.yaml" >"${TMP}/init.yaml"
reject "${TMP}/init.yaml" 'TUNNEX_JOIN_TOKEN|k8s-api-token|/var/lib/tunnex-node|/var/run/secrets|privileged: true|NET_ADMIN' 'credential, identity, or host privilege in posture-check init'
require "${TMP}/init.yaml" 'mountPath: /var/lib/tunnex/host-posture/v1' 'read-only manager heartbeat mount'
require "${TMP}/init.yaml" 'readOnly: true' 'read-only manager heartbeat boundary'
require "${TMP}/init.yaml" 'runAsUser: 65532' 'fixed unprivileged posture-check UID'
require "${TMP}/init.yaml" 'runAsNonRoot: true' 'non-root posture-check process'
require "${TMP}/init.yaml" 'allowPrivilegeEscalation: false' 'posture-check privilege escalation disabled'
require "${TMP}/init.yaml" 'readOnlyRootFilesystem: true' 'posture-check read-only root filesystem'
require "${TMP}/init.yaml" 'drop: \["ALL"\]' 'posture-check complete capability drop'
require "${TMP}/init.yaml" 'type: RuntimeDefault' 'posture-check default seccomp profile'
reject "${TMP}/init.yaml" '^[[:space:]]+add:' 'added capability in credentialless posture-check init'
require "${TMP}/init.yaml" 'fieldPath: metadata.uid' 'exact live gateway Pod UID admission input'
require "${TMP}/init.yaml" 'fieldPath: spec.nodeName' 'exact scheduled node admission input'
require "${TMP}/deployment.yaml" 'path: /var/lib/tunnex/host-posture/v1' 'fixed versioned host posture hostPath'
require "${TMP}/deployment.yaml" 'type: Directory' 'manager-created host posture path prerequisite'
awk '
  /^[[:space:]]+containers:$/ { in_main = 1 }
  in_main && /^[[:space:]]+volumes:$/ { exit }
  in_main { print }
' "${TMP}/deployment.yaml" >"${TMP}/main-container.yaml"
reject "${TMP}/main-container.yaml" '^[[:space:]]+privileged: true$' 'privileged main gateway container'
require "${TMP}/main-container.yaml" 'drop: \["ALL"\]' 'gateway complete default capability drop'
require "${TMP}/main-container.yaml" 'add: \["NET_ADMIN", "NET_BIND_SERVICE"\]' 'gateway exact host capability set'
require "${TMP}/main-container.yaml" 'runAsNonRoot: false' 'gateway explicit root execution contract'
require "${TMP}/main-container.yaml" 'type: RuntimeDefault' 'gateway default seccomp profile'
require "${TMP}/main-container.yaml" 'name: TUNNEX_HOST_POSTURE_NODE_NAME' 'runtime exact node authority input'
require "${TMP}/main-container.yaml" 'name: TUNNEX_HOST_POSTURE_OWNER_UID' 'runtime exact Pod authority input'
require "${TMP}/main-container.yaml" 'fieldPath: spec.nodeName' 'runtime downward-API node identity'
require "${TMP}/main-container.yaml" 'fieldPath: metadata.uid' 'runtime downward-API Pod identity'
require "${TMP}/main-container.yaml" 'name: TUNNEX_HOST_POSTURE_STATE_DIR' 'runtime public authority location'
# Check this particular mount, not any unrelated read-only token mount.
awk '
  /- name: host-posture-state$/ { capture = 1; next }
  capture && /- name:/ { exit }
  capture { print }
' "${TMP}/main-container.yaml" >"${TMP}/runtime-posture-mount.yaml"
require "${TMP}/runtime-posture-mount.yaml" 'mountPath: /var/lib/tunnex/host-posture/v1' 'runtime exact host authority mount'
require "${TMP}/runtime-posture-mount.yaml" 'readOnly: true' 'runtime cannot write manager journal or authority'
reject "${TMP}/runtime-posture-mount.yaml" 'readOnly: false' 'writable runtime posture authority'

require "${TMP}/preflight.yaml" 'privileged: true' 'privileged admission-context preflight'
require "${TMP}/preflight.yaml" 'automountServiceAccountToken: false' 'credentialless privileged preflight'
require "${TMP}/preflight.yaml" 'image: "ghcr.io/tunnexio/tunnex-node-agent@sha256:a{64}"' 'release/digest-pinned privileged preflight image'
require "${TMP}/preflight.yaml" 'name: DNS_PROBE' 'DNS probe passed as data through an environment variable'
require "${TMP}/preflight.yaml" 'nslookup "\$DNS_PROBE"' 'quoted DNS probe shell argument'
reject "${TMP}/preflight.yaml" 'nslookup kubernetes\.default' 'template interpolation inside privileged shell command'

test "$(grep -Fc 'mountPath: /var/run/secrets/kubernetes.io/serviceaccount' "${TMP}/deployment.yaml")" -eq 1 || {
  echo 'projected Kubernetes API token must be mounted exactly once (main gateway only)' >&2
  exit 1
}
test "$(grep -Fc 'mountPath: /var/lib/tunnex-node' "${TMP}/deployment.yaml")" -eq 1 || {
  echo 'identity state must be mounted exactly once (main gateway only)' >&2
  exit 1
}
require "${TMP}/deployment.yaml" 'serviceAccountToken:' 'short-lived projected Kubernetes API token'
require "${TMP}/deployment.yaml" 'expirationSeconds: 3600' 'bounded Kubernetes API token lifetime'

# Hook and real gateway must be schedulable on the same class of node.
for rendered in "${TMP}/deployment.yaml" "${TMP}/preflight.yaml"; do
  require "${rendered}" 'lifecycle-test: exact-node' 'gateway/preflight nodeSelector parity'
  require "${rendered}" 'key: lifecycle-test' 'gateway/preflight toleration parity'
  require "${rendered}" 'value: exact-node' 'gateway/preflight toleration value parity'
done

# Reuse consumes only an explicitly named retained claim; no token or new PVC.
REUSE=(
  "${BASE[@]}"
  --set enrollment.mode=reuse
  --set persistence.existingClaim=retained-gateway-identity
)
helm lint "${CHART}" "${REUSE[@]}"
helm template gw-reuse "${CHART}" "${REUSE[@]}" >"${TMP}/reuse.yaml"
extract_source "${TMP}/reuse.yaml" deployment.yaml "${TMP}/reuse-deployment.yaml"
reject "${TMP}/reuse.yaml" '^kind: Secret$' 'Secret in retained-identity reuse mode'
reject "${TMP}/reuse.yaml" '^kind: PersistentVolumeClaim$' 'new PVC in retained-identity reuse mode'
reject "${TMP}/reuse-deployment.yaml" 'TUNNEX_JOIN_TOKEN' 'join token in retained-identity reuse mode'
require "${TMP}/reuse-deployment.yaml" 'claimName: retained-gateway-identity' 'explicit retained identity claim reuse'

# Explicit endpoint is authoritative and suppresses Service discovery envs.
helm template gw-explicit "${CHART}" "${ENROLL[@]}" \
  --set endpoint=198.51.100.10:51820 >"${TMP}/explicit.yaml"
extract_source "${TMP}/explicit.yaml" deployment.yaml "${TMP}/explicit-deployment.yaml"
require "${TMP}/explicit-deployment.yaml" 'name: TUNNEX_NODE_ENDPOINT' 'explicit endpoint override'
require "${TMP}/explicit-deployment.yaml" 'value: "198.51.100.10:51820"' 'explicit endpoint value'
require "${TMP}/explicit-deployment.yaml" 'name: TUNNEX_K8S_MODE' 'Kubernetes mode retained with explicit endpoint'
require "${TMP}/explicit-deployment.yaml" 'value: "true"' 'enabled explicit-endpoint Kubernetes mode'
reject "${TMP}/explicit-deployment.yaml" 'TUNNEX_K8S_ENDPOINT_' 'automatic discovery env alongside explicit endpoint'

# NodePort advertises the selected public nodePort, not the pod/Service target
# port. Preserve that distinct contract while LoadBalancer stays on wireguard.port.
helm template gw-nodeport "${CHART}" "${ENROLL[@]}" \
  --set service.type=NodePort \
  --set service.nodePort=30182 \
  --set endpoint=198.51.100.10:30182 >"${TMP}/nodeport.yaml"
extract_source "${TMP}/nodeport.yaml" deployment.yaml "${TMP}/nodeport-deployment.yaml"
extract_source "${TMP}/nodeport.yaml" service-wg.yaml "${TMP}/nodeport-service.yaml"
require "${TMP}/nodeport-deployment.yaml" 'value: "198.51.100.10:30182"' 'selected NodePort advertised endpoint'
require "${TMP}/nodeport-service.yaml" 'nodePort: 30182' 'selected NodePort Service port'

# Legacy raw-token compatibility remains visible and loudly warned; it is not
# used by the customer lifecycle flow.
# Helm install's client dry-run still performs API discovery in pinned Helm
# 3.18.4. Render the exact NOTES source through a test-only ConfigMap instead:
# this exercises the warning with real values without requiring a live cluster.
cp -R "${CHART}" "${TMP}/legacy-chart"
mkdir "${TMP}/legacy-chart/contract"
cp "${CHART}/templates/NOTES.txt" "${TMP}/legacy-chart/contract/NOTES.txt"
cat >"${TMP}/legacy-chart/templates/notes-contract.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: legacy-notes-contract
data:
  notes: |
{{ tpl (.Files.Get "contract/NOTES.txt") . | indent 4 }}
EOF
helm template gw-legacy "${TMP}/legacy-chart" "${BASE[@]}" \
  --set enrollment.mode=enroll \
  --set nodeName=legacy-gateway \
  --set-string joinToken=legacy-contract-token >"${TMP}/legacy.yaml"
require "${TMP}/legacy.yaml" '^kind: Secret$' 'legacy raw-token compatibility Secret'
require "${TMP}/legacy.yaml" 'INSECURE LEGACY' 'legacy raw-token warning'

helm template gw-legacy-secret "${CHART}" "${BASE[@]}" \
  --set enrollment.mode=enroll \
  --set nodeName=legacy-existing-secret \
  --set existingJoinTokenSecret=tunnex-legacy-join >"${TMP}/legacy-existing.yaml"
reject "${TMP}/legacy-existing.yaml" '^kind: Secret$' 'chart-minted Secret for the legacy external-Secret value'
require "${TMP}/legacy-existing.yaml" 'name: tunnex-legacy-join' 'legacy existingJoinTokenSecret compatibility'

# Invalid lifecycle combinations fail closed at schema/render time.
expect_fail old-nested-shape 'got object, want string|expected string|type.*string' \
  "${ENROLL[@]}" --set 'joinToken.secretRef=tunnex-join'
expect_fail nodeport-without-endpoint 'endpoint.*required|length must be >= 1|/endpoint.*minLength' \
  "${ENROLL[@]}" --set service.type=NodePort --set endpoint=
expect_fail nodeport-without-selected-port 'service\.nodePort.*explicitly selected|/service/nodePort.*minimum|must be greater than or equal to 30000' \
  "${ENROLL[@]}" --set service.type=NodePort --set service.nodePort=0 --set endpoint=198.51.100.10:31820
expect_fail loadbalancer-endpoint-port-mismatch 'endpoint port.*wireguard\.port|wireguard\.port.*endpoint port' \
  "${ENROLL[@]}" --set endpoint=198.51.100.10:9999
expect_fail malformed-endpoint 'endpoint.*pattern|must match pattern|host:port' \
  "${ENROLL[@]}" --set-string endpoint=not-a-host-port
expect_fail mutable-privileged-preflight-image 'image/preflight.*pattern|must match pattern|sha256' \
  "${ENROLL[@]}" --set-string image.preflight=busybox:1.37.0
expect_fail hostile-dns-probe 'preflight[/.]dnsProbe.*pattern|must match pattern' \
  "${ENROLL[@]}" --set-string 'preflight.dnsProbe=$$(touch /tmp/tunnex-preflight-pwn)'
expect_fail malformed-lifecycle-install-proof 'lifecycle/installProof.*pattern|must match pattern|sha256' \
  "${ENROLL[@]}" --set-string lifecycle.installProof=sha256:SHORT
expect_fail nodeport-selected-port-mismatch 'NodePort endpoint port.*service\.nodePort' \
  "${ENROLL[@]}" --set service.type=NodePort --set service.nodePort=30183 --set endpoint=198.51.100.10:30182
expect_fail enroll-without-node-name 'nodeName.*required|length must be >= 1|/nodeName.*minLength' \
  "${ENROLL[@]}" --set nodeName=
expect_fail enroll-without-token 'exactly one token source|oneOf|one of' \
  "${BASE[@]}" --set enrollment.mode=enroll --set nodeName=missing-token
expect_fail reuse-without-claim 'existingClaim.*required|length must be >= 1|/persistence/existingClaim.*minLength' \
  "${BASE[@]}" --set enrollment.mode=reuse
expect_fail reuse-with-token 'accepts no join token|length must be <= 0|/enrollment/existingSecret.*maxLength' \
  "${REUSE[@]}" --set enrollment.existingSecret=must-not-be-mounted
expect_fail reuse-with-lifecycle-install-proof 'installProof.*length must be <= 0|/lifecycle/installProof.*maxLength' \
  "${REUSE[@]}" --set-string lifecycle.installProof="${INSTALL_PROOF}"
expect_fail partial-lifecycle-provenance 'lifecycleClaim.*length must be >= 1|/persistence/provenance/lifecycleClaim.*minLength' \
  "${BASE[@]}" --set enrollment.mode=enroll --set nodeName=partial-provenance --set enrollment.existingSecret=tunnex-join \
  --set-string persistence.provenance.organizationID="${ORG_ID}"
expect_fail reuse-with-lifecycle-provenance 'organizationID.*length must be <= 0|/persistence/provenance/organizationID.*maxLength' \
  "${REUSE[@]}" --set-string persistence.provenance.organizationID="${ORG_ID}" \
  --set-string persistence.provenance.lifecycleClaim="${LIFECYCLE_CLAIM}"
expect_fail ambiguous-token-sources 'exactly one token source|oneOf|one of' \
  "${ENROLL[@]}" --set-string joinToken=must-not-be-accepted
expect_fail external-service-account-without-name 'serviceAccount.name is required' \
  "${ENROLL[@]}" --set serviceAccount.create=false --set-string serviceAccount.name=

# Supplying a ServiceAccount suppresses only its creation. Default read-only
# endpoint RBAC must still bind that selected account, avoiding manual RBAC.
helm template gw-external-sa "${CHART}" "${ENROLL[@]}" \
  --set serviceAccount.create=false \
  --set-string serviceAccount.name=customer-gateway >"${TMP}/external-sa.yaml"
reject "${TMP}/external-sa.yaml" '^kind: ServiceAccount$' 'chart-created ServiceAccount in external-SA mode'
require "${TMP}/external-sa.yaml" '^kind: ClusterRole$' 'endpoint reader RBAC with external ServiceAccount'
require "${TMP}/external-sa.yaml" 'name: customer-gateway' 'RBAC binding to selected external ServiceAccount'

expect_fail insecure-api-url 'controlPlane.apiURL|pattern|https' \
  "${ENROLL[@]}" --set-string controlPlane.apiURL=http://cp.example.test/api
expect_fail insecure-agent-url 'controlPlane.agentURL|pattern|https' \
  "${ENROLL[@]}" --set-string controlPlane.agentURL=http://cp.example.test:8443

# Offline template rendering cannot prove lookup behavior. Exercise the actual
# Helm engine against a local read-only Kubernetes API fixture as well.
python3 "${ROOT}/deploy/k8s-gateway-pvc-lookup_test.py"

echo 'k8s gateway chart contract: PASS'
