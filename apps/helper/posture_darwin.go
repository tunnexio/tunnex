//go:build darwin

package helper

import (
	"context"
	"os/exec"
)

// collectPosture reads macOS posture facts (S7.5.3). FileVault state comes from
// `fdesetup status` (needs root — which this helper is; the unprivileged app
// cannot ask). Any failure or unrecognized output yields a nil fact: reported
// absent upstream, never guessed.
func collectPosture() PostureStatus {
	ctx, cancel := context.WithTimeout(context.Background(), postureCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/fdesetup", "status").CombinedOutput()
	if err != nil {
		return PostureStatus{}
	}
	return PostureStatus{DiskEncrypted: parseFileVaultStatus(string(out))}
}
