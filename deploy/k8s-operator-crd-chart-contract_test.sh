#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHART="${ROOT}/deploy/helm/tunnex-operator-crds"
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

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

grep -q 'refusing ownership takeover' "${CHART}/templates/_helpers.tpl" || {
  echo 'CRD chart must refuse an unexpected existing Helm owner before adoption' >&2
  exit 1
}
grep -q 'refusing downgrade' "${CHART}/templates/_helpers.tpl" || {
  echo 'CRD chart must refuse a detected schema-generation rollback' >&2
  exit 1
}
grep -q 'assertAdoptableExisting' "${CHART}/templates/00-preflight.yaml" || {
  echo 'CRD chart must prove an ownerless CRD is an exact known legacy schema before adoption' >&2
  exit 1
}

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
  3ccbaf71:apps/operator/config/crd/tunnex.io_tunnexclusters.yaml \
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
