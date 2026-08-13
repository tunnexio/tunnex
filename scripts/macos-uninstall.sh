#!/bin/bash
# S6.5a — production macOS helper uninstall + residue check. Run with sudo. Removes the
# LaunchDaemon, the installed helper, the runtime dir, and restores /etc/pf.conf from the
# backup the installer made. The packaged-app residue smoke asserts this leaves nothing.
set -euo pipefail

LABEL=io.tunnex.helper
PLIST=/Library/LaunchDaemons/${LABEL}.plist
DIR=/usr/local/tunnex
RUN=/var/run/tunnex

echo ">> stop + unload the daemon"
launchctl bootout system "$PLIST" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true

echo ">> remove installed files"
rm -f "$PLIST"
rm -rf "$DIR" "$RUN"

echo ">> remove the tunnex anchor line from /etc/pf.conf (surgical — never clobber the user's file)"
if grep -q '^[[:space:]]*anchor "tunnex"[[:space:]]*$' /etc/pf.conf 2>/dev/null; then
  # Delete ONLY our anchor reference; leave any rules the user/another tool added intact.
  grep -v '^[[:space:]]*anchor "tunnex"[[:space:]]*$' /etc/pf.conf > /etc/pf.conf.tunnex-tmp && mv /etc/pf.conf.tunnex-tmp /etc/pf.conf
  pfctl -f /etc/pf.conf 2>/dev/null || true
fi
rm -f /etc/pf.conf.tunnex-bak
pfctl -a tunnex -F all 2>/dev/null || true

echo
echo "=== RESIDUE CHECK (all must be gone) ==="
test ! -f "$PLIST" && echo "  plist: removed OK" || echo "  plist STILL PRESENT <-- FAIL"
launchctl print "system/${LABEL}" >/dev/null 2>&1 && echo "  daemon STILL LOADED <-- FAIL" || echo "  daemon: not loaded OK"
test ! -e "$DIR" && echo "  $DIR: removed OK" || echo "  $DIR STILL PRESENT <-- FAIL"
test ! -e "$RUN/helper.sock" && echo "  socket: gone OK" || echo "  socket STILL PRESENT <-- FAIL"
grep -q 'anchor "tunnex"' /etc/pf.conf 2>/dev/null && echo "  pf.conf anchor STILL PRESENT <-- FAIL" || echo "  pf.conf: clean OK"
echo ">> uninstall done"
