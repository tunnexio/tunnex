#!/bin/bash
# S6.5a — build the Go privilege helper and stage it into build/helper for
# electron-builder to bundle as an extraResource. Ad-hoc-signed (no Developer ID —
# that's S6.5b). Usage: stage-helper.sh [mac|win]  (default: current platform).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HELPER_SRC="$(cd "$HERE/../../helper" && pwd)"
OUT="$(cd "$HERE/.." && pwd)/build/helper"
# Hermetic: wipe any prior target's artifacts so a win pack never bundles the mac
# helper (or vice versa) — extraResources copies the whole build/helper dir.
rm -rf "$OUT"
mkdir -p "$OUT"
export GOFLAGS=-mod=readonly

TARGET="${1:-$([ "$(uname)" = "Darwin" ] && echo mac || echo win)}"

case "$TARGET" in
  mac)
    echo ">> building UNIVERSAL macOS helper (CGO caller-auth: libproc)"
    CGO_ENABLED=1 GOARCH=arm64 CC="clang -arch arm64" go build -C "$HELPER_SRC" -o "$OUT/tunnex-helper.arm64" ./cmd/tunnex-helper
    CGO_ENABLED=1 GOARCH=amd64 CC="clang -arch x86_64" go build -C "$HELPER_SRC" -o "$OUT/tunnex-helper.amd64" ./cmd/tunnex-helper
    lipo -create -output "$OUT/tunnex-helper" "$OUT/tunnex-helper.arm64" "$OUT/tunnex-helper.amd64"
    rm -f "$OUT/tunnex-helper.arm64" "$OUT/tunnex-helper.amd64"
    # Ad-hoc sign so the copied-to-/usr/local binary can exec on Apple Silicon
    # (an unsigned/invalidated mach-o gets Killed:9). Re-signed again at install time.
    codesign --force --sign - --timestamp=none "$OUT/tunnex-helper"
    echo ">> staged: $OUT/tunnex-helper"
    lipo -info "$OUT/tunnex-helper"
    codesign -dv "$OUT/tunnex-helper" 2>&1 | grep -E 'Signature|Identifier' | head -2 || true
    ;;
  win)
    echo ">> building windows amd64 helper (pure Go — WFP/wintun via x/sys/windows)"
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -C "$HELPER_SRC" -o "$OUT/tunnex-helper.exe" ./cmd/tunnex-helper
    echo ">> staged: $OUT/tunnex-helper.exe"
    # Bundle the vendored wintun.dll (committed, MIT — see vendor/wintun/README.md).
    VENDORED="$(cd "$HERE/.." && pwd)/vendor/wintun/wintun.dll"
    if [ -f "$VENDORED" ]; then
      cp "$VENDORED" "$OUT/wintun.dll"
      echo ">> staged: $OUT/wintun.dll"
    else
      echo "!! vendor/wintun/wintun.dll missing — Windows data plane needs it."
    fi
    # S6.7: on-box recovery note next to the helper. The full-tunnel WFP kill-switch is
    # PERSISTENT (survives process death by design) — so a locked-out operator must be able to
    # find the escape hatch WITHOUT network access. This file ships in the install dir; the same
    # command is in the app's failed/unsafe state, the WFP provider description (netsh wfp show
    # state), and the install docs.
    cat > "$OUT/README-RECOVERY.txt" <<'RECOV'
Tunnex — Windows full-tunnel kill-switch: RECOVERY
===================================================

The Tunnex full-tunnel kill-switch is a PERSISTENT Windows Filtering Platform (WFP) block: it
deliberately SURVIVES the helper process dying, so your traffic cannot leak in cleartext if the
tunnel crashes. If networking is stuck BLOCKED after a crash and does not recover on its own:

  1) EASIEST — REBOOT. The Tunnex helper service auto-starts and clears any stale block before
     it does anything else. After the reboot, networking is back.

  2) IMMEDIATE — run this from an ADMINISTRATOR command prompt, in THIS folder:

         tunnex-helper.exe --wfp-clean

     It removes the Tunnex WFP block and restores networking. Safe to run any time (it does
     nothing if no block is present).

To INSPECT what WFP objects exist:  netsh wfp show state   (look for provider "Tunnex").

You will NOT be permanently blocked: a bug means "reboot to recover", never a bricked machine.
RECOV
    echo ">> staged: $OUT/README-RECOVERY.txt"
    ;;
  *)
    echo "usage: stage-helper.sh [mac|win]" >&2; exit 2 ;;
esac
