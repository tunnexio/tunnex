//go:build !darwin && !windows

package main

import "github.com/tunnexio/tunnex/apps/helper"

// startUninstallWatchdog is a no-op on non-desktop platforms (Linux). macOS and Windows
// have their own self-uninstall watchdogs (watchdog_darwin.go / watchdog_windows.go).
func startUninstallWatchdog(_ string, _ *helper.Supervisor) {}
