#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$ROOT/deploy/k8s-walk-candidate-package.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "walk-candidate packaging contract: $*" >&2
  exit 1
}

[[ -x "$SCRIPT" ]] || fail "packaging script is not executable"
if grep -Eq '(^|[[:space:]])(docker|helm|oras)[[:space:]]+push|kubectl|az[[:space:]]+acr|gh[[:space:]]+release|(^|[[:space:]])(scp|ssh)[[:space:]]' "$SCRIPT"; then
  fail "local packaging script contains a registry or live-system mutation command"
fi
if grep -Eqi '(token|password|credential)[_-]?(file|value|arg|env)?=' "$SCRIPT"; then
  fail "local packaging script accepts or assigns credential material"
fi

REPO="$TMP/repo"
FAKEBIN="$TMP/fake-bin"
mkdir -p "$REPO/deploy" "$REPO/apps/cli/cmd/tunnex" "$FAKEBIN"
cp "$SCRIPT" "$REPO/deploy/k8s-walk-candidate-package.sh"
chmod +x "$REPO/deploy/k8s-walk-candidate-package.sh"

charts=(tunnex-host-posture tunnex-gateway tunnex-operator-crds tunnex-operator)
for chart in "${charts[@]}"; do
  mkdir -p "$REPO/deploy/helm/$chart"
  printf 'apiVersion: v2\nname: %s\nversion: 0.1.0\nappVersion: "0.1.0"\n' "$chart" \
    >"$REPO/deploy/helm/$chart/Chart.yaml"
done
printf 'package main\nfunc main() {}\n' >"$REPO/apps/cli/cmd/tunnex/main.go"
printf 'module example.test/candidate\n\ngo 1.25\n' >"$REPO/apps/cli/go.mod"

cat >"$FAKEBIN/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  build)
    output= version=
    while (($#)); do
      case "$1" in
        -o) output=$2; shift 2 ;;
        -ldflags=*)
          version=${1##*main.version=}
          shift
          ;;
        *) shift ;;
      esac
    done
    [[ -n "$output" && -n "$version" ]]
    printf '#!/usr/bin/env bash\ncandidate=%q\nif [[ "${1:-}" == version ]]; then printf "%%s\\n" "$candidate"; else exit 2; fi\n' \
      "$version" >"$output"
    chmod +x "$output"
    ;;
  env)
    case "${2:-}" in
      GOOS) echo linux ;;
      GOARCH) echo amd64 ;;
      *) exit 2 ;;
    esac
    ;;
  version)
    if [[ "${2:-}" == "-m" ]]; then
      version=$(sed -n 's/^candidate=//p' "$3")
      printf '%s: go1.25.13\n\tbuild\t-ldflags="-s -w -buildid= -X main.version=%s"\n' "$3" "$version"
    else
      echo 'go version go1.25.13 linux/amd64'
    fi
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$FAKEBIN/go"

cat >"$FAKEBIN/helm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  package)
    chart_dir=$2
    shift 2
    version= app_version= destination=
    while (($#)); do
      case "$1" in
        --version) version=$2; shift 2 ;;
        --app-version) app_version=$2; shift 2 ;;
        --destination) destination=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    name=$(sed -n 's/^name:[[:space:]]*//p' "$chart_dir/Chart.yaml" | head -n1)
    mkdir -p "$destination"
    printf 'name: %s\nversion: %s\nappVersion: %s\n' "$name" "$version" "$app_version" \
      >"$destination/$name-$version.tgz"
    ;;
  show)
    [[ "${2:-}" == chart ]]
    cat "$3"
    ;;
  version)
    echo 'v3.18.6+contract'
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$FAKEBIN/helm"

git -C "$REPO" init -q
git -C "$REPO" config user.name contract
git -C "$REPO" config user.email contract@example.test
git -C "$REPO" add .
git -C "$REPO" commit -qm 'fixture'
SOURCE_SHA=$(git -C "$REPO" rev-parse HEAD)
VERSION="0.0.0-walk.sha${SOURCE_SHA}"

digest() {
  local char=$1
  printf '%64s' '' | tr ' ' "$char"
}

args=(
  --api-image "example.azurecr.io/tunnex-api@sha256:$(digest 1)"
  --web-image "example.azurecr.io/tunnex-web@sha256:$(digest 2)"
  --nginx-image "example.azurecr.io/tunnex-nginx@sha256:$(digest 3)"
  --migrate-image "example.azurecr.io/tunnex-migrate@sha256:$(digest 4)"
  --node-image "example.azurecr.io/tunnex-node-agent@sha256:$(digest 5)"
  --operator-image "example.azurecr.io/tunnex-operator@sha256:$(digest 6)"
)

OUT_A="$TMP/candidate-a"
OUT_B="$TMP/candidate-b"
PATH="$FAKEBIN:$PATH" "$REPO/deploy/k8s-walk-candidate-package.sh" --output "$OUT_A" "${args[@]}" >/dev/null
PATH="$FAKEBIN:$PATH" "$REPO/deploy/k8s-walk-candidate-package.sh" --output "$OUT_B" "${args[@]}" >/dev/null

jq -e --arg sha "$SOURCE_SHA" --arg version "$VERSION" '
  .schema_version == 1 and
  .kind == "tunnex-kubernetes-private-walk-candidate" and
  .release_class == "private-pre-release-qualification" and
  .public_release == false and
  .source == {sha: $sha, state: "clean-committed-head"} and
  .candidate_version == $version and
  .cli.version == $version and
  (.charts | length) == 4 and
  ([.charts[].version] | unique) == [$version] and
  ([.charts[].app_version] | unique) == [$version] and
  (.images | length) == 6 and
  ([.images[].reference | test("@sha256:[0-9a-f]{64}$")] | all)
' "$OUT_A/candidate-manifest.json" >/dev/null || fail "manifest did not bind one committed candidate version and six immutable images"

(
  cd "$OUT_A"
  sha256sum -c SHA256SUMS >/dev/null
) || fail "candidate checksums do not verify"

for chart in "${charts[@]}"; do
  [[ -s "$OUT_A/charts/$chart-$VERSION.tgz" ]] || fail "missing version-matched $chart package"
done
[[ -s "$OUT_A/tunnex-linux-amd64" ]] || fail "missing CLI artifact"
grep -Fxq "candidate=$VERSION" "$OUT_A/tunnex-linux-amd64" || fail "CLI artifact is not version matched"
diff -qr "$OUT_A" "$OUT_B" >/dev/null || fail "two builds from the same committed inputs were not byte-identical"

if grep -R -Eqi '(join[_ -]?token|machine[_ -]?token|password|private[_ -]?key|certificate[_ -]?body)' "$OUT_A"; then
  fail "candidate bundle contains a credential-shaped field"
fi

BAD_OUT="$TMP/bad-image"
if PATH="$FAKEBIN:$PATH" "$REPO/deploy/k8s-walk-candidate-package.sh" \
  --output "$BAD_OUT" "${args[@]:0:8}" \
  --node-image example.azurecr.io/tunnex-node-agent:mutable \
  "${args[@]:10}" >/dev/null 2>"$TMP/bad-image.err"; then
  fail "mutable image input was accepted"
fi
[[ ! -e "$BAD_OUT" ]] || fail "invalid image input created an output bundle"
grep -Fq 'credential-free registry/repository@sha256' "$TMP/bad-image.err" || fail "mutable image refusal was not actionable"

printf '\n# dirty\n' >>"$REPO/deploy/helm/tunnex-gateway/Chart.yaml"
DIRTY_OUT="$TMP/dirty"
if PATH="$FAKEBIN:$PATH" "$REPO/deploy/k8s-walk-candidate-package.sh" --output "$DIRTY_OUT" "${args[@]}" \
  >/dev/null 2>"$TMP/dirty.err"; then
  fail "dirty source tree was accepted"
fi
[[ ! -e "$DIRTY_OUT" ]] || fail "dirty source tree created an output bundle"
grep -Fq 'clean committed HEAD' "$TMP/dirty.err" || fail "dirty source refusal was not actionable"

echo 'walk-candidate packaging contract: PASS'
