#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(git -C "${SCRIPT_DIR}/.." rev-parse --show-toplevel)

usage() {
  cat <<'EOF'
Usage: deploy/k8s-walk-candidate-package.sh \
  --output ABSOLUTE_DIRECTORY \
  --api-image REGISTRY/REPOSITORY@sha256:DIGEST \
  --web-image REGISTRY/REPOSITORY@sha256:DIGEST \
  --nginx-image REGISTRY/REPOSITORY@sha256:DIGEST \
  --migrate-image REGISTRY/REPOSITORY@sha256:DIGEST \
  --node-image REGISTRY/REPOSITORY@sha256:DIGEST \
  --operator-image REGISTRY/REPOSITORY@sha256:DIGEST \
  [--walk-sequence N]

Builds one local, private pre-release Kubernetes walk-candidate bundle from a
clean committed HEAD. The command never logs in, pushes, deploys, or accepts a
credential. Every image input must already be an immutable digest reference.

Optional --walk-sequence accepts a canonical decimal integer from 1 through
999 and selects 0.0.1-walk.N.sha<actual 32-hex HEAD prefix>. Choose increasing
sequences for successive private candidates. Without it, the historical
0.0.0-walk.sha<actual 32-hex HEAD prefix> version remains unchanged. Build all
input images with the same selected version; no arbitrary version override is
accepted. The manifest always records the full source SHA.
EOF
}

fail() {
  echo "k8s walk candidate: $*" >&2
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "required tool $1 is not available"
}

validate_image_ref() {
  local label=$1 value=$2
  if ! [[ "$value" =~ ^[A-Za-z0-9._:-]+(/[A-Za-z0-9._-]+)+@sha256:[0-9a-f]{64}$ ]]; then
    fail "--${label}-image must be a credential-free registry/repository@sha256:<64 lowercase hex> reference"
  fi
}

output_dir=
api_image=
web_image=
nginx_image=
migrate_image=
node_image=
operator_image=
walk_sequence=

while (($#)); do
  case "$1" in
    --output|--api-image|--web-image|--nginx-image|--migrate-image|--node-image|--operator-image|--walk-sequence)
      (($# >= 2)) || fail "$1 requires a value"
      case "$1" in
        --output) output_dir=$2 ;;
        --api-image) api_image=$2 ;;
        --web-image) web_image=$2 ;;
        --nginx-image) nginx_image=$2 ;;
        --migrate-image) migrate_image=$2 ;;
        --node-image) node_image=$2 ;;
        --operator-image) operator_image=$2 ;;
        --walk-sequence)
          [[ "$2" =~ ^[1-9][0-9]{0,2}$ ]] || fail "--walk-sequence must be a canonical integer from 1 through 999"
          walk_sequence=$2
          ;;
      esac
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument $1"
      ;;
  esac
done

[[ -n "$output_dir" ]] || fail "--output is required"
case "$output_dir" in
  /*) ;;
  *) fail "--output must be an absolute path" ;;
esac
output_parent=$(dirname "$output_dir")
output_name=$(basename "$output_dir")
[[ "$output_name" != "." && "$output_name" != ".." ]] || fail "--output must name a new directory"
[[ -d "$output_parent" ]] || fail "--output parent must already exist"
output_parent=$(cd "$output_parent" && pwd -P)
output_dir="$output_parent/$output_name"
case "$output_parent/" in
  "$REPO_ROOT/"|"$REPO_ROOT/"*) fail "--output must be outside the source checkout" ;;
esac
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || fail "output already exists: $output_dir"

for tool in git go helm jq sha256sum cmp tar; do
  require_tool "$tool"
done

validate_image_ref api "$api_image"
validate_image_ref web "$web_image"
validate_image_ref nginx "$nginx_image"
validate_image_ref migrate "$migrate_image"
validate_image_ref node "$node_image"
validate_image_ref operator "$operator_image"

source_sha=$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')
[[ "$source_sha" =~ ^[0-9a-f]{40,64}$ ]] || fail "HEAD did not resolve to a full commit SHA"
git -C "$REPO_ROOT" cat-file -e "${source_sha}^{commit}"
worktree_status=$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=normal)
[[ -z "$worktree_status" ]] || fail "source tree must be a clean committed HEAD; commit or remove every tracked and untracked change first"

# One bounded scalar identifies every runtime/package surface. The API accepts
# at most 50 characters for agent_version, so the scalar carries a 128-bit
# source abbreviation while the manifest below remains authoritative for the
# complete immutable source identity.
candidate_source_prefix=${source_sha:0:32}
[[ "$candidate_source_prefix" =~ ^[0-9a-f]{32}$ ]] || fail "could not derive the candidate source abbreviation"
candidate_version="0.0.0-walk.sha${candidate_source_prefix}"
if [[ -n "$walk_sequence" ]]; then
  candidate_version="0.0.1-walk.${walk_sequence}.sha${candidate_source_prefix}"
fi
((${#candidate_version} <= 50)) || fail "candidate version exceeds the agent_version API limit"

stage=$(mktemp -d "${output_parent}/.tunnex-k8s-walk-candidate.XXXXXX")
cleanup() {
  if [[ -n "${stage:-}" && -d "$stage" ]]; then
    rm -rf -- "$stage"
  fi
}
trap cleanup EXIT

bundle="$stage/bundle"
work="$stage/work"
source_root="$work/source"
mkdir -p "$bundle/charts" "$work/charts-a" "$work/charts-b" "$source_root"
git -C "$REPO_ROOT" archive --format=tar "$source_sha" | tar -xf - -C "$source_root"

build_cli() {
  local goos=$1 goarch=$2 destination=$3
  (
    cd "$source_root/apps/cli"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOFLAGS=-mod=readonly \
      go build -trimpath -buildvcs=false \
        -ldflags="-s -w -buildid= -X main.version=${candidate_version}" \
        -o "$destination" ./cmd/tunnex
  )
}

cli_path="$bundle/tunnex-linux-amd64"
build_cli linux amd64 "$cli_path"
[[ -s "$cli_path" ]] || fail "CLI build produced no artifact"
chmod 0500 "$cli_path"

# Execute the command path that customers use. Cross-platform packagers build a
# disposable native witness with the identical source and ldflags; the shipped
# artifact remains the Linux amd64 binary required by the control-plane host.
host_goos=$(go env GOOS)
host_goarch=$(go env GOARCH)
cli_probe="$cli_path"
if [[ "$host_goos/$host_goarch" != "linux/amd64" ]]; then
  cli_probe="$work/tunnex-version-probe"
  build_cli "$host_goos" "$host_goarch" "$cli_probe"
  chmod 0500 "$cli_probe"
fi
actual_cli_version=$("$cli_probe" version)
[[ "$actual_cli_version" == "$candidate_version" ]] || \
  fail "CLI reports $actual_cli_version instead of the exact candidate version"

read_chart_field() {
  local metadata=$1 key=$2 line value
  line=$(grep -m1 -E "^${key}:[[:space:]]*" <<<"$metadata") || return 1
  value=${line#*:}
  value=${value#"${value%%[![:space:]]*}"}
  value=${value%"${value##*[![:space:]]}"}
  if [[ ${#value} -ge 2 && ( ( ${value:0:1} == '"' && ${value: -1} == '"' ) || ( ${value:0:1} == "'" && ${value: -1} == "'" ) ) ]]; then
    value=${value:1:${#value}-2}
  fi
  printf '%s' "$value"
}

package_chart() {
  local name=$1 source="$source_root/deploy/helm/$1"
  local a="$work/charts-a/${name}-${candidate_version}.tgz"
  local b="$work/charts-b/${name}-${candidate_version}.tgz"
  local final="$bundle/charts/${name}-${candidate_version}.tgz"
  local metadata actual_name actual_version actual_app_version

  [[ -d "$source" ]] || fail "chart source is absent: $source"
  bash "$source_root/deploy/helm-package-reproducible.sh" \
    "$source" "$candidate_version" "$candidate_version" "$work/charts-a"
  bash "$source_root/deploy/helm-package-reproducible.sh" \
    "$source" "$candidate_version" "$candidate_version" "$work/charts-b"
  [[ -s "$a" && -s "$b" ]] || fail "Helm did not produce both $name package witnesses"
  cmp -s "$a" "$b" || fail "$name chart packaging is not byte-deterministic with this Helm toolchain"

  metadata=$(helm show chart "$a")
  actual_name=$(read_chart_field "$metadata" name) || fail "$name chart metadata has no name"
  actual_version=$(read_chart_field "$metadata" version) || fail "$name chart metadata has no version"
  actual_app_version=$(read_chart_field "$metadata" appVersion) || fail "$name chart metadata has no appVersion"
  [[ "$actual_name" == "$name" ]] || fail "$name chart reports unexpected name $actual_name"
  [[ "$actual_version" == "$candidate_version" ]] || fail "$name chart version is not the candidate version"
  [[ "$actual_app_version" == "$candidate_version" ]] || fail "$name chart appVersion is not the candidate version"

  cp "$a" "$final"
  chmod 0400 "$final"
}

charts=(tunnex-host-posture tunnex-gateway tunnex-operator-crds tunnex-operator)
for chart in "${charts[@]}"; do
  package_chart "$chart"
done

cli_sha=$(sha256sum "$cli_path" | awk '{print $1}')
host_posture_sha=$(sha256sum "$bundle/charts/tunnex-host-posture-${candidate_version}.tgz" | awk '{print $1}')
gateway_sha=$(sha256sum "$bundle/charts/tunnex-gateway-${candidate_version}.tgz" | awk '{print $1}')
operator_crds_sha=$(sha256sum "$bundle/charts/tunnex-operator-crds-${candidate_version}.tgz" | awk '{print $1}')
operator_chart_sha=$(sha256sum "$bundle/charts/tunnex-operator-${candidate_version}.tgz" | awk '{print $1}')
go_toolchain=$(go version)
helm_toolchain=$(helm version --short)

jq -n \
  --arg version "$candidate_version" \
  --arg source_sha "$source_sha" \
  --arg go_toolchain "$go_toolchain" \
  --arg helm_toolchain "$helm_toolchain" \
  --arg cli_sha "$cli_sha" \
  --arg host_posture_sha "$host_posture_sha" \
  --arg gateway_sha "$gateway_sha" \
  --arg operator_crds_sha "$operator_crds_sha" \
  --arg operator_chart_sha "$operator_chart_sha" \
  --arg api_image "$api_image" \
  --arg web_image "$web_image" \
  --arg nginx_image "$nginx_image" \
  --arg migrate_image "$migrate_image" \
  --arg node_image "$node_image" \
  --arg operator_image "$operator_image" \
  '{
    schema_version: 1,
    kind: "tunnex-kubernetes-private-walk-candidate",
    release_class: "private-pre-release-qualification",
    public_release: false,
    candidate_version: $version,
    source: {sha: $source_sha, state: "clean-committed-head"},
    build_inputs: {go: $go_toolchain, helm: $helm_toolchain},
    cli: {
      path: "tunnex-linux-amd64",
      goos: "linux",
      goarch: "amd64",
      version: $version,
      sha256: $cli_sha
    },
    charts: [
      {name: "tunnex-host-posture", path: ("charts/tunnex-host-posture-" + $version + ".tgz"), version: $version, app_version: $version, sha256: $host_posture_sha},
      {name: "tunnex-gateway", path: ("charts/tunnex-gateway-" + $version + ".tgz"), version: $version, app_version: $version, sha256: $gateway_sha},
      {name: "tunnex-operator-crds", path: ("charts/tunnex-operator-crds-" + $version + ".tgz"), version: $version, app_version: $version, sha256: $operator_crds_sha},
      {name: "tunnex-operator", path: ("charts/tunnex-operator-" + $version + ".tgz"), version: $version, app_version: $version, sha256: $operator_chart_sha}
    ],
    images: {
      api: {reference: $api_image, digest: ($api_image | split("@")[1])},
      web: {reference: $web_image, digest: ($web_image | split("@")[1])},
      nginx: {reference: $nginx_image, digest: ($nginx_image | split("@")[1])},
      migrate: {reference: $migrate_image, digest: ($migrate_image | split("@")[1])},
      "node-agent": {reference: $node_image, digest: ($node_image | split("@")[1])},
      operator: {reference: $operator_image, digest: ($operator_image | split("@")[1])}
    }
  }' >"$bundle/candidate-manifest.json"
chmod 0400 "$bundle/candidate-manifest.json"

(
  cd "$bundle"
  sha256sum \
    tunnex-linux-amd64 \
    charts/tunnex-host-posture-"${candidate_version}".tgz \
    charts/tunnex-gateway-"${candidate_version}".tgz \
    charts/tunnex-operator-crds-"${candidate_version}".tgz \
    charts/tunnex-operator-"${candidate_version}".tgz \
    candidate-manifest.json | sort -k2 >SHA256SUMS
  chmod 0400 SHA256SUMS
)

final_source_sha=$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')
final_worktree_status=$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=normal)
[[ "$final_source_sha" == "$source_sha" && -z "$final_worktree_status" ]] || \
  fail "source HEAD or worktree changed during packaging; candidate was not published"

mv "$bundle" "$output_dir"
echo "Private Kubernetes walk candidate ${candidate_version} written to ${output_dir}"
echo "No registry, Kubernetes cluster, cloud resource, or control plane was changed."
