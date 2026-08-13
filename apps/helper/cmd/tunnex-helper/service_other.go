//go:build !windows

package main

// Off Windows there is no SCM: the helper runs as a LaunchDaemon (macOS) or a plain
// console process, so isWindowsService is always false and runService is never called.
func isWindowsService() bool { return false }

func runService() {} // unreachable off Windows (guarded by isWindowsService)
