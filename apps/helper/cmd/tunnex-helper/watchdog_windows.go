//go:build windows

package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/tunnexio/tunnex/apps/helper"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	winWatchdogInterval      = 30 * time.Second
	winWatchdogMissThreshold = 3 // ~90s — tolerates an in-place app update
)

// startUninstallWatchdog (Windows) makes uninstall robust even when the NSIS uninstaller
// is skipped or corrupt: it watches the install dir's Tunnex.exe and, once it's been gone
// past the debounce, releases the WFP kill-switch and DELETES the helper's own SCM
// service. A clean Add/Remove Programs uninstall already does sc delete first (so this
// never fires then). TUNNEX_INSTALL_DIR on Windows is the single install dir ($INSTDIR).
func startUninstallWatchdog(installDir string, sup *helper.Supervisor) {
	if installDir == "" || containsPathListSep(installDir) {
		return
	}
	appExe := filepath.Join(installDir, "Tunnex.exe")
	go func() {
		missing := 0
		t := time.NewTicker(winWatchdogInterval)
		defer t.Stop()
		for range t.C {
			if _, err := os.Stat(appExe); os.IsNotExist(err) {
				missing++
				if missing >= winWatchdogMissThreshold {
					// selfUninstall os.Exits on success; on failure it returns false and
					// we keep watching + retry after another window — NEVER os.Exit into
					// the SCM restart policy on a failed delete (= no self-uninstall loop,
					// review #7).
					if !selfUninstall(sup) {
						missing = 0
					}
				}
			} else {
				missing = 0
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

// selfUninstall releases the kill-switch and marks the service for deletion. Returns
// false (WITHOUT exiting) if the delete could not be issued, so the caller keeps the
// process alive and retries — an os.Exit on a failed delete would let the SCM restart
// policy respawn us into a self-uninstall loop. On a successful Delete it os.Exits;
// DELETE_PENDING completes once the process is gone.
func selfUninstall(sup *helper.Supervisor) bool {
	log.Printf("tunnex-helper: install dir removed — self-uninstalling the service")
	if err := sup.SelfHeal(); err != nil { // release any armed WFP kill-switch first
		log.Printf("tunnex-helper: self-uninstall self-heal: %v", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		log.Printf("tunnex-helper: self-uninstall scm connect: %v", err)
		return false
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Printf("tunnex-helper: self-uninstall open service: %v", err)
		return false
	}
	defer func() { _ = s.Close() }()
	if err := s.Delete(); err != nil {
		log.Printf("tunnex-helper: self-uninstall delete service: %v", err)
		return false // do NOT exit — avoids a restart/self-uninstall loop
	}
	os.Exit(0) // marked for deletion; the SCM removes it once this process exits
	return true
}
