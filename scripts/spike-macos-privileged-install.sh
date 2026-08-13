#!/bin/bash
# S6.5a Spike 1 — does an UNSIGNED caller's GUI admin prompt reliably perform a
# privileged LaunchDaemon install? Proxy for the packaged app's in-app "install
# helper" step (the zero-terminal crux). SAFE + self-cleaning:
#   - benign daemon (sleeps 3s), distinct label io.tunnex.spike, distinct plist path
#   - NEVER touches the real helper, its socket, pf, or routing
#   - ONE admin password prompt; installs -> captures loaded state -> uninstalls
# It mirrors exactly the privileged op the app will run: write to
# /Library/LaunchDaemons + `launchctl bootstrap`, invoked via osascript's
# admin-privileges prompt (NOT the deprecated SMJobBless / Authorization C API).
set -euo pipefail

LABEL="io.tunnex.spike"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"

# The privileged script (runs as root via the GUI prompt). Writes a trivial daemon,
# loads it, prints its launchd state to STDOUT (captured by osascript — no temp file,
# so nothing root-owned is left in /tmp), then fully removes it.
read -r -d '' PRIV <<EOF || true
set -e
cat > '${PLIST}' <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>sleep 3</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
PL
chown root:wheel '${PLIST}'
chmod 644 '${PLIST}'
launchctl bootout system '${PLIST}' 2>/dev/null || true
launchctl bootstrap system '${PLIST}'
sleep 1
launchctl print system/${LABEL} 2>&1 || echo print-failed
launchctl bootout system '${PLIST}' 2>/dev/null || true
rm -f '${PLIST}'
EOF

echo ">> Invoking the GUI admin prompt from an UNSIGNED shell caller (osascript)…"
echo ">> (You'll see a native 'wants to make changes' dialog — enter your password once.)"
# Escape backslashes + double-quotes for AppleScript's string literal. `do shell script`
# returns the command's stdout, which osascript prints — we capture + inspect it.
ESCAPED=$(printf '%s' "$PRIV" | sed 's/\\/\\\\/g; s/"/\\"/g')
RESULT=$(osascript -e "do shell script \"${ESCAPED}\" with administrator privileges with prompt \"Tunnex spike wants to install a test helper.\"")

echo
echo "=== RESULT ==="
if printf '%s' "$RESULT" | grep -qE 'state = running|pid = [0-9]+|program = /bin/sh'; then
  echo "PASS: unsigned-invoked admin prompt installed + launchd LOADED the daemon."
  printf '%s\n' "$RESULT" | grep -E 'state|pid|program' | head -3 | sed 's/^/   /'
else
  echo "INCONCLUSIVE/FAIL: daemon did not show loaded. Captured output:"
  printf '%s\n' "$RESULT" | sed 's/^/   /'
fi
echo
echo "=== RESIDUE CHECK (must all be gone) ==="
test ! -f "$PLIST" && echo "   plist removed: OK" || echo "   plist STILL PRESENT: $PLIST  <-- FAIL"
launchctl print "system/${LABEL}" >/dev/null 2>&1 && echo "   daemon STILL LOADED  <-- FAIL" || echo "   daemon unloaded: OK"
echo ">> Spike done. No residue expected; nothing real was touched."
