#!/usr/bin/env bash
# S6.3 MINI-SMOKE dev-install (macOS) — scope: validate the kill-switch + data
# plane ONLY. This is NOT the production installer (SMAppService); it is the
# minimal path to run the mini-smoke. Requires admin (sudo prompts).
set -euo pipefail

DIR=/usr/local/tunnex
PLIST=/Library/LaunchDaemons/io.tunnex.helper.plist
SOCK=/var/run/tunnex/helper.sock
LOG=/tmp/tunnex-helper.log
REPO="$(cd "$(dirname "$0")/.." && pwd)"
HELPER_SRC="$REPO/apps/helper"

# TRUSTED CALLER DIRS (colon-joined; the helper trusts a caller in ANY of them).
# $DIR holds the tunnelctl driver (mini-smoke). The dev Electron app runs from
# node_modules, so AUTO-DETECT its binary dir and trust it too — this is what stops
# `caller_untrusted` recurring for the desktop-app POC (item-5 pt 2), so no manual
# PlistBuddy repoint is ever needed.
detect_electron_dir() {
  local bin=""
  bin="$( (cd "$REPO/apps/client" && node -e "process.stdout.write(require('electron'))") 2>/dev/null )" || bin=""
  if [ -n "$bin" ]; then dirname "$bin"; fi
}
# Self-correct: if an earlier run logged a caller_untrusted with the rejected exe,
# trust that binary's dir too (covers a hoisted/renamed Electron path require()
# resolution might miss).
rejected_dir() {
  local p=""
  p="$(grep -o 'caller exe "[^"]*"' "$LOG" 2>/dev/null | tail -1 | sed 's/caller exe "//; s/"$//')" || p=""
  if [ -n "$p" ]; then dirname "$p"; fi
}
TRUST_DIRS="$DIR"
ELDIR="$(detect_electron_dir)"
if [ -n "$ELDIR" ]; then TRUST_DIRS="$TRUST_DIRS:$ELDIR"; fi
REJDIR="$(rejected_dir)"
if [ -n "$REJDIR" ] && [ "$REJDIR" != "$DIR" ] && [ "$REJDIR" != "$ELDIR" ]; then TRUST_DIRS="$TRUST_DIRS:$REJDIR"; fi
echo ">> trusted caller dirs: $TRUST_DIRS"

echo ">> [1/6] build helper (CGO_ENABLED=1 → native caller-auth) + tunnelctl driver"
( cd "$HELPER_SRC"
  CGO_ENABLED=1 go build -o /tmp/tunnex-helper ./cmd/tunnex-helper
  CGO_ENABLED=1 go build -o /tmp/tunnelctl ./cmd/tunnelctl )

echo ">> [2/6] install to $DIR (sudo)"
sudo mkdir -p "$DIR"
sudo cp /tmp/tunnex-helper /tmp/tunnelctl "$DIR/"
sudo chmod 0755 "$DIR" "$DIR/tunnex-helper" "$DIR/tunnelctl"
# Re-apply an ad-hoc signature IN PLACE. On Apple Silicon the sudo cp above
# invalidates the Go build-time signature, and the kernel then kills the binary on
# exec ("Killed: 9"). Sign the installed copies so they can run. (Dev-install only;
# the production SMAppService installer ships a real Developer ID signature — S6.5b.)
sudo codesign --force --sign - "$DIR/tunnex-helper" "$DIR/tunnelctl"

echo ">> [3/6] STEP ZERO — caller-auth indicator MUST print 'native':"
"$DIR/tunnex-helper" --version

echo ">> [4/6] reference the pf anchor from /etc/pf.conf (backup first) so it is EVALUATED"
if ! grep -q 'anchor "tunnex"' /etc/pf.conf; then
  sudo cp /etc/pf.conf /etc/pf.conf.tunnex-bak
  echo 'anchor "tunnex"' | sudo tee -a /etc/pf.conf >/dev/null
  sudo pfctl -f /etc/pf.conf 2>/dev/null || true
fi

echo ">> [5/6] write + load the LaunchDaemon"
sudo tee "$PLIST" >/dev/null <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>io.tunnex.helper</string>
  <key>ProgramArguments</key><array><string>$DIR/tunnex-helper</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>TUNNEX_INSTALL_DIR</key><string>$TRUST_DIRS</string>
    <key>TUNNEX_HELPER_SOCKET</key><string>$SOCK</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/tmp/tunnex-helper.log</string>
</dict></plist>
PL
sudo launchctl bootout system "$PLIST" 2>/dev/null || true
sudo launchctl bootstrap system "$PLIST"
sleep 1

echo ">> [6/6] daemon up? (expect a pid + the 'caller-auth: native' startup log)"
sudo launchctl print system/io.tunnex.helper 2>/dev/null | grep -E 'state|pid' | head -2 || true
grep 'caller-auth' /tmp/tunnex-helper.log 2>/dev/null | tail -1 || true
echo ">> DONE. Driver: $DIR/tunnelctl   Socket: $SOCK   Log: /tmp/tunnex-helper.log"
