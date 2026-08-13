//go:build !windows

package main

import "errors"

// The WFP escape hatch is Windows-only (it operates on the WFP kill-switch).
func wfpClean() error { return errors.New("--wfp-clean is Windows-only") }
