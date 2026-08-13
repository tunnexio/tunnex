#!/bin/bash
# S6.5a — emit SHA256SUMS over the shipped installers. This is the integrity
# substitute for a code signature until S6.5b: users verify the hash they downloaded
# against the value published on the (trusted) release page (see docs/install.md).
set -euo pipefail

REL="$(cd "$(dirname "$0")/.." && pwd)/release"
cd "$REL"

# Only the user-facing installers (skip electron-builder's blockmap/yml internals).
shopt -s nullglob
FILES=(*.pkg *.dmg *.exe)
if [ ${#FILES[@]} -eq 0 ]; then
  echo "no .pkg/.dmg/.exe artifacts in $REL — did electron-builder run?" >&2
  exit 1
fi

# shasum on macOS, sha256sum on Linux.
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${FILES[@]}" > SHA256SUMS
else
  shasum -a 256 "${FILES[@]}" > SHA256SUMS
fi
echo ">> wrote $REL/SHA256SUMS"
cat SHA256SUMS
