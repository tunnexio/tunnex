#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHART="${ROOT}/deploy/helm/tunnex-operator-crds"
TMP=$(mktemp -d)
READONLY_API_PID=""

stop_readonly_api() {
  if [[ -n "${READONLY_API_PID}" ]]; then
    kill "${READONLY_API_PID}" 2>/dev/null || true
    wait "${READONLY_API_PID}" 2>/dev/null || true
    READONLY_API_PID=""
  fi
}

cleanup() {
  stop_readonly_api
  rm -rf "${TMP}"
}
trap cleanup EXIT

helm lint "${CHART}"
helm template tunnex-operator-crds "${CHART}" \
  --namespace tunnex-system >"${TMP}/rendered.yaml"

if helm template tunnex-operator-crds "${CHART}" --kube-version 1.28.9 >"${TMP}/old-kube.out" 2>&1; then
  echo 'CRD chart must refuse Kubernetes versions below stable CEL admission' >&2
  exit 1
fi
grep -Eq 'kubeVersion|Kubernetes' "${TMP}/old-kube.out"

test "$(grep -c '^kind: CustomResourceDefinition$' "${TMP}/rendered.yaml")" -eq 3 || {
  echo 'CRD chart must render exactly the three Tunnex operator CRDs' >&2
  exit 1
}
test "$(grep -c 'helm.sh/resource-policy: keep' "${TMP}/rendered.yaml")" -eq 3 || {
  echo 'CRD chart must retain every CRD on uninstall' >&2
  exit 1
}
test "$(grep -c 'tunnex.io/schema-generation: "1"' "${TMP}/rendered.yaml")" -eq 3 || {
  echo 'CRD chart must give every CRD the same monotonic schema generation' >&2
  exit 1
}

for crd in tunnex.io_tunnexclusters.yaml tunnex.io_tunnexexposedservices.yaml tunnex.io_tunnexgrants.yaml; do
  sed \
    -e '/^[[:space:]]*helm.sh\/resource-policy: keep$/d' \
    -e '/^[[:space:]]*tunnex.io\/schema-generation: "1"$/d' \
    "${CHART}/templates/${crd}" >"${TMP}/${crd}"
  cmp "${ROOT}/apps/operator/config/crd/${crd}" "${TMP}/${crd}" || {
    echo "managed CRD source drift: ${crd}" >&2
    exit 1
  }
done

if grep -Eq '^kind: (Deployment|DaemonSet|StatefulSet|Job|Secret|ServiceAccount)$' "${TMP}/rendered.yaml"; then
  echo 'CRD lifecycle chart must contain no workload, credential, or service-account resources' >&2
  exit 1
fi

# Execute the real 00-preflight.yaml lookup loop. Helm's client-only template
# mode intentionally returns empty lookup results, so use server dry-run against
# a local GET-only Kubernetes discovery/CRD fixture. This is an offline
# substitute for, not a replacement for, the mandatory live lookup matrix.
READONLY_API_BIN="${TMP}/k8s-operator-crd-readonly-api"
go build -o "${READONLY_API_BIN}" \
  "${ROOT}/deploy/testtools/k8s-operator-crd-readonly-api/main.go"

start_readonly_api() {
  local fixture=$1
  local case_name=$2
  local case_dir="${TMP}/readonly-api-${case_name}"
  mkdir -p "${case_dir}"
  "${READONLY_API_BIN}" \
    --fixture "${fixture}" \
    --address-file "${case_dir}/address" \
    --request-log "${case_dir}/requests.log" \
    >"${case_dir}/server.out" 2>&1 &
  READONLY_API_PID=$!
  for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -s "${case_dir}/address" ]]; then
      break
    fi
    if ! kill -0 "${READONLY_API_PID}" 2>/dev/null; then
      cat "${case_dir}/server.out" >&2
      echo "read-only Kubernetes API fixture exited during ${case_name}" >&2
      exit 1
    fi
    sleep 0.05
  done
  if [[ ! -s "${case_dir}/address" ]]; then
    cat "${case_dir}/server.out" >&2
    echo "read-only Kubernetes API fixture did not become ready during ${case_name}" >&2
    exit 1
  fi
  local server
  IFS= read -r server <"${case_dir}/address"
  cat >"${case_dir}/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: readonly-fixture
    cluster:
      server: ${server}
contexts:
  - name: readonly-fixture
    context:
      cluster: readonly-fixture
      user: readonly-fixture
current-context: readonly-fixture
users:
  - name: readonly-fixture
    user: {}
EOF
  chmod 600 "${case_dir}/kubeconfig"
  READONLY_API_KUBECONFIG="${case_dir}/kubeconfig"
  READONLY_API_REQUEST_LOG="${case_dir}/requests.log"
}

assert_crd_lookup_paths() {
  local request_log=$1
  shift
  local actual="${request_log}.crd.actual"
  local expected="${request_log}.crd.expected"
  awk '$1 == "GET" && $2 ~ /^\/apis\/apiextensions.k8s.io\/v1\/customresourcedefinitions\// { print $2 }' \
    "${request_log}" >"${actual}"
  printf '%s\n' "$@" >"${expected}"
  cmp "${expected}" "${actual}" || {
    echo 'real preflight did not execute the expected cluster-scoped CRD lookup sequence' >&2
    exit 1
  }
  if grep -Ev '^GET ' "${request_log}"; then
    echo 'Helm server dry-run attempted a write against the read-only fixture' >&2
    exit 1
  fi
}

CRD_LOOKUP_BASE='/apis/apiextensions.k8s.io/v1/customresourcedefinitions'
start_readonly_api \
  "${ROOT}/deploy/testdata/k8s-operator-crd-chart/current-generation-all.json" \
  current-generation
helm template tunnex-operator-crds "${CHART}" \
  --namespace tunnex-system \
  --dry-run=server \
  --kubeconfig "${READONLY_API_KUBECONFIG}" \
  >"${TMP}/current-generation.yaml"
assert_crd_lookup_paths "${READONLY_API_REQUEST_LOG}" \
  "${CRD_LOOKUP_BASE}/tunnexclusters.tunnex.io" \
  "${CRD_LOOKUP_BASE}/tunnexexposedservices.tunnex.io" \
  "${CRD_LOOKUP_BASE}/tunnexgrants.tunnex.io"
stop_readonly_api

start_readonly_api \
  "${ROOT}/deploy/testdata/k8s-operator-crd-chart/foreign-release.json" \
  foreign-release
if helm template tunnex-operator-crds "${CHART}" \
  --namespace tunnex-system \
  --dry-run=server \
  --kubeconfig "${READONLY_API_KUBECONFIG}" \
  >"${TMP}/foreign-release.out" 2>&1; then
  echo 'real CRD preflight must reject a foreign Helm release owner' >&2
  exit 1
fi
grep -q 'owned by Helm release foreign-release; refusing ownership takeover' \
  "${TMP}/foreign-release.out"
assert_crd_lookup_paths "${READONLY_API_REQUEST_LOG}" \
  "${CRD_LOOKUP_BASE}/tunnexclusters.tunnex.io"
stop_readonly_api

start_readonly_api \
  "${ROOT}/deploy/testdata/k8s-operator-crd-chart/cross-namespace-owner.json" \
  cross-namespace-owner
if helm template tunnex-operator-crds "${CHART}" \
  --namespace tunnex-system \
  --dry-run=server \
  --kubeconfig "${READONLY_API_KUBECONFIG}" \
  >"${TMP}/cross-namespace-owner.out" 2>&1; then
  echo 'real CRD preflight must reject a current owner from another namespace' >&2
  exit 1
fi
grep -q 'owned from namespace foreign-system; expected tunnex-system' \
  "${TMP}/cross-namespace-owner.out"
assert_crd_lookup_paths "${READONLY_API_REQUEST_LOG}" \
  "${CRD_LOOKUP_BASE}/tunnexclusters.tunnex.io"
stop_readonly_api

start_readonly_api \
  "${ROOT}/deploy/testdata/k8s-operator-crd-chart/newer-generation.json" \
  newer-generation
if helm template tunnex-operator-crds "${CHART}" \
  --namespace tunnex-system \
  --dry-run=server \
  --kubeconfig "${READONLY_API_KUBECONFIG}" \
  >"${TMP}/newer-generation.out" 2>&1; then
  echo 'real CRD preflight must reject a sane newer schema generation' >&2
  exit 1
fi
grep -q 'schema generation 2 is newer than chart generation 1; refusing downgrade' \
  "${TMP}/newer-generation.out"
assert_crd_lookup_paths "${READONLY_API_REQUEST_LOG}" \
  "${CRD_LOOKUP_BASE}/tunnexclusters.tunnex.io"
stop_readonly_api

# Findings 11 and 22 remain HELD policy questions. Record the present branch
# behavior without calling it the desired contract: a valid generation marker
# currently bypasses fingerprinting for both the same and legacy release owner.
for descriptive_case in same-release-drifted-generation legacy-owner-drifted-generation; do
  start_readonly_api \
    "${ROOT}/deploy/testdata/k8s-operator-crd-chart/${descriptive_case}.json" \
    "${descriptive_case}"
  helm template tunnex-operator-crds "${CHART}" \
    --namespace tunnex-system \
    --dry-run=server \
    --kubeconfig "${READONLY_API_KUBECONFIG}" \
    >"${TMP}/${descriptive_case}.yaml"
  assert_crd_lookup_paths "${READONLY_API_REQUEST_LOG}" \
    "${CRD_LOOKUP_BASE}/tunnexclusters.tunnex.io" \
    "${CRD_LOOKUP_BASE}/tunnexexposedservices.tunnex.io" \
    "${CRD_LOOKUP_BASE}/tunnexgrants.tunnex.io"
  stop_readonly_api
done

# Exercise the same named-template guard used after the live lookup. Kubernetes
# defaults an omitted conversion block to {strategy: None}; every approved
# historical source schema must still pass after that normalization, while one
# changed spec must fail closed. The first two cluster fixtures are read from
# their authoritative git content tips rather than reconstructed by the test.
FINGERPRINT_CHART="${TMP}/fingerprint-chart"
cp -R "${CHART}" "${FINGERPRINT_CHART}"
mkdir -p "${FINGERPRINT_CHART}/contract-fixtures"
cp "${ROOT}"/apps/operator/config/crd/*.yaml "${FINGERPRINT_CHART}/contract-fixtures/"
git -C "${ROOT}" show \
  025368ab:apps/operator/config/crd/tunnex.io_tunnexclusters.yaml \
  >"${FINGERPRINT_CHART}/contract-fixtures/tunnexclusters-initial.yaml"
git -C "${ROOT}" show \
  1160009:apps/operator/config/crd/tunnex.io_tunnexclusters.yaml \
  >"${FINGERPRINT_CHART}/contract-fixtures/tunnexclusters-connector.yaml"

cp "${ROOT}/deploy/testdata/k8s-operator-crd-chart/ownerless-known-legacy.yaml.tpl" \
  "${FINGERPRINT_CHART}/templates/zz-ownerless-contract.yaml"
helm template ownerless-known-legacy "${FINGERPRINT_CHART}" \
  --namespace tunnex-system >"${TMP}/ownerless-known-legacy.yaml"
grep -q 'name: ownerless-known-legacy-contract' "${TMP}/ownerless-known-legacy.yaml"

cp "${ROOT}/deploy/testdata/k8s-operator-crd-chart/ownerless-unknown-schema.yaml.tpl" \
  "${FINGERPRINT_CHART}/templates/zz-ownerless-contract.yaml"
if helm template ownerless-unknown-schema "${FINGERPRINT_CHART}" \
  --namespace tunnex-system >"${TMP}/ownerless-unknown-schema.out" 2>&1; then
  echo 'CRD chart must reject an ownerless same-name CRD with an unknown schema' >&2
  exit 1
fi
grep -q 'not an approved Tunnex legacy schema; refusing ownership takeover' \
  "${TMP}/ownerless-unknown-schema.out"

cp "${ROOT}/deploy/testdata/k8s-operator-crd-chart/legacy-owner-unknown-schema.yaml.tpl" \
  "${FINGERPRINT_CHART}/templates/zz-ownerless-contract.yaml"
if helm template legacy-owner-unknown-schema "${FINGERPRINT_CHART}" \
  --namespace tunnex-system >"${TMP}/legacy-owner-unknown-schema.out" 2>&1; then
  echo 'CRD chart must reject an unknown schema owned by the unversioned legacy release' >&2
  exit 1
fi
grep -q 'not an approved Tunnex legacy schema; refusing ownership takeover' \
  "${TMP}/legacy-owner-unknown-schema.out"

cp "${ROOT}/deploy/testdata/k8s-operator-crd-chart/invalid-generation.yaml.tpl" \
  "${FINGERPRINT_CHART}/templates/zz-ownerless-contract.yaml"
if helm template invalid-generation "${FINGERPRINT_CHART}" \
  --namespace tunnex-system >"${TMP}/invalid-generation.out" 2>&1; then
  echo 'CRD chart must reject a malformed or overflowing schema generation' >&2
  exit 1
fi
grep -q 'invalid schema generation' "${TMP}/invalid-generation.out"

helm package "${CHART}" --version 9.8.7 --app-version v9.8.7 --destination "${TMP}" >/dev/null
test -s "${TMP}/tunnex-operator-crds-9.8.7.tgz"

if helm template tunnex-operator-crds "${CHART}" --set unexpected=true >"${TMP}/unexpected.out" 2>&1; then
  echo 'CRD chart schema must reject unknown values' >&2
  exit 1
fi
grep -Eq 'additional propert|Additional property' "${TMP}/unexpected.out"

echo 'k8s operator CRD lifecycle chart contract: PASS'
