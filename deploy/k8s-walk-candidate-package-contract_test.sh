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
mkdir -p "$REPO/deploy" "$REPO/apps/cli/cmd/tunnex" "$REPO/apps/cli/cmd/chartarchive"
cp "$SCRIPT" "$REPO/deploy/k8s-walk-candidate-package.sh"
cp "$ROOT/deploy/helm-package-reproducible.sh" "$REPO/deploy/helm-package-reproducible.sh"
cp "$ROOT/apps/cli/cmd/chartarchive/main.go" "$REPO/apps/cli/cmd/chartarchive/main.go"
chmod +x "$REPO/deploy/k8s-walk-candidate-package.sh"

charts=(tunnex-host-posture tunnex-gateway tunnex-operator-crds tunnex-operator)
for chart in "${charts[@]}"; do
  mkdir -p "$REPO/deploy/helm/$chart"
  printf 'apiVersion: v2\nname: %s\nversion: 0.1.0\nappVersion: "0.1.0"\n' "$chart" \
    >"$REPO/deploy/helm/$chart/Chart.yaml"
done
# This small CLI is explicitly an orchestration fixture, built by real Go.
# The production Tunnex CLI is separately built/tested and must be packaged
# again from final committed content before live qualification.
cat >"$REPO/apps/cli/cmd/tunnex/main.go" <<'EOF'
package main
import ("fmt"; "os")
var version = "dev"
func main() {
  if len(os.Args) != 2 || os.Args[1] != "version" { os.Exit(2) }
  fmt.Println(version)
}
EOF
printf 'module example.test/candidate\n\ngo 1.25\n' >"$REPO/apps/cli/go.mod"
printf '.walk-credential\n' >"$REPO/.gitignore"

git -C "$REPO" init -q
git -C "$REPO" config user.name contract
git -C "$REPO" config user.email contract@example.test
git -C "$REPO" add .
git -C "$REPO" commit -qm 'fixture'
SOURCE_SHA=$(git -C "$REPO" rev-parse HEAD)
VERSION="0.0.0-walk.sha${SOURCE_SHA:0:32}"
[[ ${#VERSION} -le 50 ]] || fail "fixture candidate version exceeds the agent_version API limit"
SENTINEL=S205_EXCLUDED_CREDENTIAL_SENTINEL_7b3a19
printf '%s\n' "$SENTINEL" >"$REPO/.walk-credential"

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
"$REPO/deploy/k8s-walk-candidate-package.sh" --output "$OUT_A" "${args[@]}" >/dev/null
"$REPO/deploy/k8s-walk-candidate-package.sh" --output "$OUT_B" "${args[@]}" >/dev/null

jq -e --arg sha "$SOURCE_SHA" --arg version "$VERSION" '
  .schema_version == 1 and
  .kind == "tunnex-kubernetes-private-walk-candidate" and
  .release_class == "private-pre-release-qualification" and
  .public_release == false and
  .source == {sha: $sha, state: "clean-committed-head"} and
  .candidate_version == $version and
  (.candidate_version | test("^0[.]0[.]0-walk[.]sha[0-9a-f]{32}$")) and
  (.candidate_version | length) <= 50 and
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
  archive="$OUT_A/charts/$chart-$VERSION.tgz"
  [[ -s "$archive" ]] || fail "missing version-matched $chart package"
  tar -tzf "$archive" > "$TMP/chart-members"
  grep -Fxq "$chart/Chart.yaml" "$TMP/chart-members" || fail "chart archive is not a real Helm tarball"
  helm show chart "$archive" > "$TMP/chart-metadata"
  grep -Fxq "version: $VERSION" "$TMP/chart-metadata" || fail "real chart version mismatch"
  tar -xzOf "$archive" > "$TMP/chart-content"
  if grep -Fq "$SENTINEL" "$TMP/chart-content"; then
    fail "ignored credential sentinel entered a compressed chart"
  fi
done
[[ -s "$OUT_A/tunnex-linux-amd64" ]] || fail "missing CLI artifact"
[[ "$(od -An -tx1 -N4 "$OUT_A/tunnex-linux-amd64" | tr -d ' \n')" == 7f454c46 ]] || fail "CLI artifact is not real ELF"
go version -m "$OUT_A/tunnex-linux-amd64" > "$TMP/cli-build-metadata"
grep -Fq 'GOOS=linux' "$TMP/cli-build-metadata" || fail "real CLI target is not Linux"
grep -Fq 'GOARCH=amd64' "$TMP/cli-build-metadata" || fail "real CLI architecture is not amd64"
diff -qr "$OUT_A" "$OUT_B" >/dev/null || fail "two builds from the same committed inputs were not byte-identical"

# Trimpath builds need not expose ldflags in build metadata. Inspect the real
# binary's strings, in addition to the native `version` command the packager
# actually executes (the shipped binary itself is executed on Linux/amd64).
strings "$OUT_A/tunnex-linux-amd64" > "$TMP/cli-strings"
grep -Fq "$VERSION" "$TMP/cli-strings" || fail "real CLI binary lacks candidate version"
if grep -Fq "$SENTINEL" "$TMP/cli-strings" "$OUT_A/candidate-manifest.json" "$OUT_A/SHA256SUMS"; then
  fail "ignored credential sentinel entered a candidate artifact"
fi

# Exercise real packaging at the lower bound, across a decimal-width change,
# and at the upper bound (exactly the API's 50-character version limit).
for sequence in 1 10 999; do
  sequence_version="0.0.1-walk.${sequence}.sha${SOURCE_SHA:0:32}"
  sequence_out="$TMP/candidate-sequence-$sequence"
  "$REPO/deploy/k8s-walk-candidate-package.sh" --output "$sequence_out" \
    --walk-sequence "$sequence" "${args[@]}" >/dev/null
  jq -e --arg sha "$SOURCE_SHA" --arg version "$sequence_version" '
    .source == {sha: $sha, state: "clean-committed-head"} and
    .candidate_version == $version and
    (.candidate_version | length) <= 50 and
    .cli.version == $version and
    (.charts | length) == 4 and
    ([.charts[].version] | unique) == [$version] and
    ([.charts[].app_version] | unique) == [$version] and
    ([.charts[] | .path == ("charts/" + .name + "-" + $version + ".tgz")] | all) and
    (.images | length) == 6 and
    ([.images[].reference | test("@sha256:[0-9a-f]{64}$")] | all)
  ' "$sequence_out/candidate-manifest.json" >/dev/null || fail "sequence $sequence lost exact candidate provenance"
  (
    cd "$sequence_out"
    sha256sum -c SHA256SUMS >/dev/null
  ) || fail "sequence $sequence candidate checksums do not verify"
  for chart in "${charts[@]}"; do
    helm show chart "$sequence_out/charts/$chart-$sequence_version.tgz" > "$TMP/sequence-chart-metadata"
    grep -Fxq "version: $sequence_version" "$TMP/sequence-chart-metadata" || fail "sequence $sequence chart version mismatch"
  done
  strings "$sequence_out/tunnex-linux-amd64" > "$TMP/sequence-cli-strings"
  grep -Fq "$sequence_version" "$TMP/sequence-cli-strings" || fail "sequence $sequence CLI lacks exact version"
done
[[ ${#sequence_version} -eq 50 ]] || fail "sequence 999 did not exercise the exact version limit"

bad_sequence_index=0
for sequence in '' 0 00 01 001 0001 -1 +1 1.0 1e2 1000 999999999999999999999 ' 1' '1 ' $'1\n' 1a; do
  bad_sequence_index=$((bad_sequence_index + 1))
  bad_sequence_out="$TMP/bad-sequence-$bad_sequence_index"
  if "$REPO/deploy/k8s-walk-candidate-package.sh" --output "$bad_sequence_out" \
    --walk-sequence "$sequence" "${args[@]}" >/dev/null 2>"$TMP/bad-sequence.err"; then
    fail "noncanonical or out-of-range walk sequence was accepted"
  fi
  [[ ! -e "$bad_sequence_out" ]] || fail "invalid walk sequence created an output bundle"
  grep -Fq -- '--walk-sequence must be a canonical integer from 1 through 999' "$TMP/bad-sequence.err" || fail "walk sequence refusal was not actionable"
done
if "$REPO/deploy/k8s-walk-candidate-package.sh" --walk-sequence \
  >/dev/null 2>"$TMP/missing-sequence.err"; then
  fail "missing walk sequence was accepted"
fi
grep -Fq -- '--walk-sequence requires a value' "$TMP/missing-sequence.err" || fail "missing walk sequence refusal was not actionable"
if "$REPO/deploy/k8s-walk-candidate-package.sh" --version 99.0.0 \
  >/dev/null 2>"$TMP/arbitrary-version.err"; then
  fail "arbitrary version override was accepted"
fi
grep -Fq 'unknown argument --version' "$TMP/arbitrary-version.err" || fail "arbitrary version refusal was not actionable"

BAD_OUT="$TMP/bad-image"
if "$REPO/deploy/k8s-walk-candidate-package.sh" \
  --output "$BAD_OUT" "${args[@]:0:8}" \
  --node-image example.azurecr.io/tunnex-node-agent:mutable \
  "${args[@]:10}" >/dev/null 2>"$TMP/bad-image.err"; then
  fail "mutable image input was accepted"
fi
[[ ! -e "$BAD_OUT" ]] || fail "invalid image input created an output bundle"
grep -Fq 'credential-free registry/repository@sha256' "$TMP/bad-image.err" || fail "mutable image refusal was not actionable"

printf '\n# dirty\n' >>"$REPO/deploy/helm/tunnex-gateway/Chart.yaml"
DIRTY_OUT="$TMP/dirty"
if "$REPO/deploy/k8s-walk-candidate-package.sh" --output "$DIRTY_OUT" "${args[@]}" \
  >/dev/null 2>"$TMP/dirty.err"; then
  fail "dirty source tree was accepted"
fi
[[ ! -e "$DIRTY_OUT" ]] || fail "dirty source tree created an output bundle"
grep -Fq 'clean committed HEAD' "$TMP/dirty.err" || fail "dirty source refusal was not actionable"

echo 'walk-candidate packaging contract: PASS'
