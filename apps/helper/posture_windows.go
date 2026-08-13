//go:build windows

package helper

import (
	"context"
	"os/exec"
)

// collectPosture reads Windows posture facts (S7.5.3). BitLocker state for the
// SYSTEM drive comes from the Win32_EncryptableVolume WMI class (needs admin —
// which this SCM service is). The NUMERIC ProtectionStatus is read deliberately:
// manage-bde prose is localized and unparseable across locales. Any failure or
// unrecognized output yields a nil fact: reported absent upstream, never guessed.
func collectPosture() PostureStatus {
	ctx, cancel := context.WithTimeout(context.Background(), postureCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx,
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter ("DriveLetter='" + $env:SystemDrive + "'")).ProtectionStatus`,
	).Output()
	if err != nil {
		return PostureStatus{}
	}
	return PostureStatus{DiskEncrypted: parseProtectionStatus(string(out))}
}
