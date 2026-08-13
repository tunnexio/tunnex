#!/usr/bin/env bash
# S6.3 MINI-SMOKE dev-uninstall (macOS). Reverses macos-dev-install.sh and asserts
# no residue (the mini-smoke's cleanup + a preview of the real uninstall checks).
set -uo pipefail

DIR=/usr/local/tunnex
PLIST=/Library/LaunchDaemons/io.tunnex.helper.plist
SOCK=/var/run/tunnex/helper.sock

echo ">> unload the daemon"
sudo launchctl bootout system "$PLIST" 2>/dev/null || sudo launchctl unload "$PLIST" 2>/dev/null || true

echo ">> flush + release the pf kill-switch (in case a tunnel was left up / crashed)"
sudo pfctl -a tunnex -F all 2>/dev/null || true
# Release any lingering pfctl -E reference this session may hold is best-effort;
# a reboot fully clears refcounts. Verify enforcement is gone below.

echo ">> restore /etc/pf.conf from the install backup (or strip the anchor line) + reload"
if [ -f /etc/pf.conf.tunnex-bak ]; then
  sudo cp /etc/pf.conf.tunnex-bak /etc/pf.conf     # exact original, not a line-delete guess
  sudo rm -f /etc/pf.conf.tunnex-bak
else
  sudo sed -i '' '/anchor "tunnex"/d' /etc/pf.conf 2>/dev/null || true
fi
sudo pfctl -f /etc/pf.conf 2>/dev/null || true

echo ">> remove files, socket, pf token, runtime dir"
sudo rm -f "$PLIST"
sudo rm -rf "$DIR"
sudo rm -f "$SOCK"
sudo rm -f /var/run/tunnex/pf.token       # persisted kill-switch enable-ref (recovery)
sudo rmdir /var/run/tunnex 2>/dev/null || true

echo ">> RESIDUE CHECK (all should be empty / not-found):"
echo -n "  daemon:  "; sudo launchctl print system/io.tunnex.helper 2>&1 | head -1
echo -n "  socket:  "; ls "$SOCK" 2>&1 | head -1
echo -n "  pf rules:"; sudo pfctl -a tunnex -s rules 2>&1 | head -1
echo -n "  pf token: "; ls /var/run/tunnex/pf.token 2>&1 | head -1
echo -n "  split-default routes: "; netstat -rn 2>/dev/null | grep -E '^(0\.0\.0\.0/1|128\.0\.0\.0/1|::/1|8000::/1) ' | head -1 || echo "none"
echo -n "  net now works (curl):"; curl -s -m 5 -o /dev/null -w '%{http_code}\n' https://api.ipify.org || echo "FAILED — pf may still be enforcing; reboot to clear"
echo ">> DONE."
