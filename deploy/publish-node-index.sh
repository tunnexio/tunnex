#!/usr/bin/env bash
# Join only the two exact digests uploaded by this run's native build jobs.
set -euo pipefail
: "${IMAGE:?}" "${TAGS:?}" "${GITHUB_OUTPUT:?}"
directory=${1:?digest directory required}
shopt -s nullglob
files=("$directory"/*)
[[ ${#files[@]} == 2 ]] || { echo 'Expected exactly two native image digests' >&2; exit 1; }
sources=()
platforms=()
for file in "${files[@]}"; do
  digest=${file##*/}
  [[ -f "$file" && "$digest" =~ ^[a-f0-9]{64}$ ]] || exit 1
  ref="$IMAGE@sha256:$digest"
  raw=$(docker buildx imagetools inspect --raw "$ref")
  # BuildKit emits an index containing one runtime platform plus attestations.
  platform=$(jq -er '[.manifests[] | select(.platform.os != "unknown") | (.platform.os + "/" + .platform.architecture)] | if length == 1 then .[0] else error("ambiguous runtime platform") end' <<< "$raw")
  platforms+=("$platform")
  sources+=("$ref")
done
[[ "$(printf '%s\n' "${platforms[@]}" | sort)" == $'linux/amd64\nlinux/arm64' ]] || { echo 'Native platform pair is incomplete' >&2; exit 1; }
args=()
while IFS= read -r tag; do
  [[ -n "$tag" && "$tag" == "$IMAGE:"* ]] || exit 1
  args+=(--tag "$tag")
done <<< "$TAGS"
metadata=$(mktemp)
trap 'rm -f "$metadata"' EXIT
docker buildx imagetools create "${args[@]}" --metadata-file "$metadata" "${sources[@]}"
digest=$(jq -er '."containerimage.descriptor".digest | select(test("^sha256:[a-f0-9]{64}$"))' "$metadata")
printf 'digest=%s\n' "$digest" >> "$GITHUB_OUTPUT"
