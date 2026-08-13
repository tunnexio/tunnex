#!/bin/bash
# S6.5a — produce the UNSIGNED installable artifact end to end:
#   web bundle → client main/preload (tsc) → staged helper → electron-builder → SHA256SUMS
# Usage: pack.sh [mac|win]   (default: current platform)
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
TARGET="${1:-$([ "$(uname)" = "Darwin" ] && echo mac || echo win)}"

echo ">> [1/5] build the SPA bundle (apps/web → dist, bundled as Resources/web)"
( cd "$HERE/../web" && npm run build )

echo ">> [2/5] compile main + preload (tsc → dist)"
npm run build

echo ">> [3/5] build + stage the privilege helper ($TARGET)"
bash scripts/stage-helper.sh "$TARGET"

echo ">> [4/5] electron-builder ($TARGET, UNSIGNED)"
# CSC_IDENTITY_AUTO_DISCOVERY=false: never pick up a stray Developer ID from the
# keychain — S6.5a is deliberately unsigned (signing is S6.5b).
CSC_IDENTITY_AUTO_DISCOVERY=false npx electron-builder --"$TARGET" --config electron-builder.yml

echo ">> [5/5] checksums"
bash scripts/sha256sums.sh

echo ">> DONE — artifacts + SHA256SUMS in $HERE/release"
