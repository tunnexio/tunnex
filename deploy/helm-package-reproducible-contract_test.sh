#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Compare real Helm input/output contents and behavior, not just archive bytes.
# These archives are built here from repository-owned charts; extraction is
# confined to this new fixture directory and never handles caller input.
for chart in tunnex-host-posture tunnex-gateway tunnex-operator-crds tunnex-operator; do
  case_dir="$TMP/$chart"
  mkdir -p "$case_dir/raw" "$case_dir/canonical" "$case_dir/raw-tree" "$case_dir/canonical-tree"
  helm package "$ROOT/deploy/helm/$chart" --version 9.8.7 --app-version v9.8.7 \
    --destination "$case_dir/raw" >/dev/null
  bash "$ROOT/deploy/helm-package-reproducible.sh" "$ROOT/deploy/helm/$chart" \
    9.8.7 v9.8.7 "$case_dir/canonical"
  raw="$case_dir/raw/$chart-9.8.7.tgz"
  canonical="$case_dir/canonical/$chart-9.8.7.tgz"
  tar -xzf "$raw" -C "$case_dir/raw-tree"
  tar -xzf "$canonical" -C "$case_dir/canonical-tree"
  diff -r "$case_dir/raw-tree" "$case_dir/canonical-tree"
  helm show all "$raw" >"$case_dir/raw-metadata"
  helm show all "$canonical" >"$case_dir/canonical-metadata"
  cmp "$case_dir/raw-metadata" "$case_dir/canonical-metadata"
  values=(--namespace tunnex-system)
  case "$chart" in
    tunnex-host-posture) values+=(--set acknowledgePrivileged=true) ;;
    tunnex-gateway)
      values+=(--set acknowledgePrivileged=true --set enrollment.mode=enroll
        --set enrollment.existingSecret=fixture-join --set nodeName=fixture-gateway
        --set controlPlane.apiURL=https://cp.example.test/api
        --set controlPlane.agentURL=https://cp.example.test:8443) ;;
    tunnex-operator)
      values+=(--set controlPlane.url=https://cp.example.test
        --set controlPlane.organizationID=11111111-1111-1111-1111-111111111111
        --set machineToken.existingSecret=fixture-machine) ;;
  esac
  helm template "$chart" "$raw" "${values[@]}" >"$case_dir/raw-rendered"
  helm template "$chart" "$canonical" "${values[@]}" >"$case_dir/canonical-rendered"
  cmp "$case_dir/raw-rendered" "$case_dir/canonical-rendered"
done
echo 'reproducible chart content and render parity: PASS'
