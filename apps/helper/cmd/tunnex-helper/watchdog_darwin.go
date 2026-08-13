//go:build darwin

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/helper"
)

const (
	daemonLabel  = "io.tunnex.helper"
	daemonPlist  = "/Library/LaunchDaemons/io.tunnex.helper.plist"
	installDest  = "/usr/local/tunnex"
	runtimeDir   = "/var/run/tunnex"
	pfConfPath   = "/etc/pf.conf"
	pfConfBackup = "/etc/pf.conf.tunnex-bak"
	pfAnchorLine = `anchor "tunnex"`
	appBundle    = "Tunnex.app" // only OUR bundle arms the watchdog
	// watchdogInterval × watchdogMissThreshold ≈ how long the app must be gone before
	// self-uninstall. ~90s tolerates an app-update that briefly replaces the bundle.
	watchdogInterval      = 30 * time.Second
	watchdogMissThreshold = 3
)

// startUninstallWatchdog makes "drag the app to Trash" fully clean on unsigned S6.5a
// (SMAppService auto-removal needs signing → S6.5b). The helper is a root LaunchDaemon
// OUTSIDE the .app, so trashing the bundle alone leaves it behind. This watches the
// owning /Applications/Tunnex.app; once it's been gone past the debounce, the helper
// releases its kill-switch, removes the tunnex pf anchor, removes its own files, and
// unloads itself. Armed ONLY for the packaged single-dir install of OUR bundle.
func startUninstallWatchdog(installDir string, sup *helper.Supervisor) {
	if installDir == "" || containsPathListSep(installDir) {
		return // dev / multi-dir install — no watchdog
	}
	// installDir = …/Tunnex.app/Contents/MacOS → app bundle = up two levels.
	app := filepath.Dir(filepath.Dir(installDir))
	// Only watch OUR bundle by name — never self-uninstall because some unrelated .app
	// was moved/removed (review #4).
	if filepath.Base(app) != appBundle {
		return
	}
	go func() {
		missing := 0
		t := time.NewTicker(watchdogInterval)
		defer t.Stop()
		for range t.C {
			if _, err := os.Stat(app); os.IsNotExist(err) {
				missing++
				if missing >= watchdogMissThreshold {
					selfUninstall(app, sup)
					return
				}
			} else {
				missing = 0 // present (or a transient stat error) → reset
			}
		}
	}()
}

func containsPathListSep(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == os.PathListSeparator {
			return true
		}
	}
	return false
}

// selfUninstall tears the helper down after its owning app was removed. Ordering:
// release the kill-switch, surgically remove the pf anchor, remove installed files,
// THEN unload the daemon by LABEL (bootout-by-label needs no plist file, so removing
// the plist first is safe — review #3). bootout SIGTERMs us, so file removal happens
// before it; os.Exit is a fallback if bootout doesn't take.
func selfUninstall(app string, sup *helper.Supervisor) {
	log.Printf("tunnex-helper: owning app %q removed — self-uninstalling", app)

	// 1. Release any armed kill-switch (pf anchor rules) so networking is restored.
	if err := sup.SelfHeal(); err != nil {
		log.Printf("tunnex-helper: self-uninstall self-heal: %v", err)
	}
	// 2. Remove ONLY the tunnex anchor line from /etc/pf.conf (never clobber the user's
	//    file — review #2) + flush the anchor.
	removePfAnchor()
	// 3. Remove installed files (before bootout, which terminates this process).
	_ = os.Remove(daemonPlist)
	_ = os.RemoveAll(installDest)
	_ = os.RemoveAll(runtimeDir)
	// 4. Unload self by LABEL (no plist file needed) — this terminates the process.
	_ = exec.Command("launchctl", "bootout", "system/"+daemonLabel).Run()
	os.Exit(0)
}

// removePfAnchor deletes the single `anchor "tunnex"` line from /etc/pf.conf and
// reloads pf — a surgical edit that preserves any rules the user or another tool added
// after install (the whole-file restore this replaces destroyed them — review #2).
func removePfAnchor() {
	if data, err := os.ReadFile(pfConfPath); err == nil {
		lines := strings.Split(string(data), "\n")
		kept := make([]string, 0, len(lines))
		for _, l := range lines {
			if strings.TrimSpace(l) == pfAnchorLine {
				continue // drop only our anchor reference
			}
			kept = append(kept, l)
		}
		if err := os.WriteFile(pfConfPath, []byte(strings.Join(kept, "\n")), 0o644); err == nil {
			_ = exec.Command("pfctl", "-f", pfConfPath).Run()
		}
	}
	_ = os.Remove(pfConfBackup) // the install-time backup is no longer used for restore
	// Flush the anchor's rules regardless (harmless if already empty).
	_ = exec.Command("pfctl", "-a", "tunnex", "-F", "all").Run()
}
